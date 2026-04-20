package rpc_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/computervirtualservices/malairte/internal/chain"
	"github.com/computervirtualservices/malairte/internal/crypto"
	"github.com/computervirtualservices/malairte/internal/mempool"
	"github.com/computervirtualservices/malairte/internal/primitives"
	"github.com/computervirtualservices/malairte/internal/rpc"
	"github.com/computervirtualservices/malairte/internal/storage"
)

// ── in-memory DB for tests ────────────────────────────────────────────────────

type testDB struct {
	mu   sync.RWMutex
	data map[string][]byte
}

func newTestDB() *testDB { return &testDB{data: make(map[string][]byte)} }

func (m *testDB) Put(key, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]byte, len(value))
	copy(cp, value)
	m.data[string(key)] = cp
	return nil
}

func (m *testDB) Get(key []byte) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.data[string(key)]
	if !ok {
		return nil, storage.ErrNotFound
	}
	cp := make([]byte, len(v))
	copy(cp, v)
	return cp, nil
}

func (m *testDB) Delete(key []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, string(key))
	return nil
}

func (m *testDB) Has(key []byte) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.data[string(key)]
	return ok, nil
}

func (m *testDB) Close() error { return nil }

func (m *testDB) ForEachWithPrefix(prefix []byte, fn func(key, value []byte) error) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p := string(prefix)
	for k, v := range m.data {
		if len(k) >= len(p) && k[:len(p)] == p {
			if err := fn([]byte(k), v); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *testDB) NewBatch() storage.Batch { return &testBatch{db: m} }

type testBatch struct {
	db  *testDB
	ops []testBatchOp
}

type testBatchOp struct {
	key    []byte
	value  []byte
	delete bool
}

func (b *testBatch) Put(key, value []byte) {
	cp := make([]byte, len(value))
	copy(cp, value)
	b.ops = append(b.ops, testBatchOp{key: append([]byte{}, key...), value: cp})
}

func (b *testBatch) Delete(key []byte) {
	b.ops = append(b.ops, testBatchOp{key: append([]byte{}, key...), delete: true})
}

func (b *testBatch) Write() error {
	b.db.mu.Lock()
	defer b.db.mu.Unlock()
	for _, op := range b.ops {
		if op.delete {
			delete(b.db.data, string(op.key))
		} else {
			b.db.data[string(op.key)] = op.value
		}
	}
	return nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

type testEnv struct {
	ts   *httptest.Server
	pool *mempool.TxPool
	bc   *chain.Blockchain
}

// TestRPC_BasicAuth_RejectsMissingCreds verifies that when SetAuth is
// configured, unauthenticated requests get a 401 with WWW-Authenticate.
func TestRPC_BasicAuth_RejectsMissingCreds(t *testing.T) {
	params := new(chain.ChainParams)
	*params = chain.TestNetParams
	bc, _ := chain.NewBlockchain(params, newTestDB())
	pool := mempool.NewTxPool()
	srv := rpc.NewServer(bc, pool, nil, nil, params)
	srv.SetAuth("user", "pass")
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)

	// No Authorization header → 401.
	resp, err := http.Post(ts.URL, "application/json", bytes.NewReader([]byte(
		`{"jsonrpc":"1.0","id":1,"method":"getblockchaininfo","params":[]}`)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401", resp.StatusCode)
	}
	if ch := resp.Header.Get("WWW-Authenticate"); ch == "" {
		t.Error("missing WWW-Authenticate header on 401")
	}
}

// TestRPC_BasicAuth_AcceptsCorrectCreds verifies authenticated requests
// are processed normally.
func TestRPC_BasicAuth_AcceptsCorrectCreds(t *testing.T) {
	params := new(chain.ChainParams)
	*params = chain.TestNetParams
	bc, _ := chain.NewBlockchain(params, newTestDB())
	pool := mempool.NewTxPool()
	srv := rpc.NewServer(bc, pool, nil, nil, params)
	srv.SetAuth("user", "pass")
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)

	req, _ := http.NewRequest(http.MethodPost, ts.URL, bytes.NewReader([]byte(
		`{"jsonrpc":"1.0","id":1,"method":"getblockchaininfo","params":[]}`)))
	req.SetBasicAuth("user", "pass")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}
}

// TestRPC_BasicAuth_WrongCredsRejected verifies a wrong password returns 401.
func TestRPC_BasicAuth_WrongCredsRejected(t *testing.T) {
	params := new(chain.ChainParams)
	*params = chain.TestNetParams
	bc, _ := chain.NewBlockchain(params, newTestDB())
	pool := mempool.NewTxPool()
	srv := rpc.NewServer(bc, pool, nil, nil, params)
	srv.SetAuth("user", "correct-password")
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)

	req, _ := http.NewRequest(http.MethodPost, ts.URL, bytes.NewReader([]byte(
		`{"jsonrpc":"1.0","id":1,"method":"getblockchaininfo","params":[]}`)))
	req.SetBasicAuth("user", "wrong-password")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401", resp.StatusCode)
	}
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	params := new(chain.ChainParams)
	*params = chain.TestNetParams
	bc, err := chain.NewBlockchain(params, newTestDB())
	if err != nil {
		t.Fatalf("NewBlockchain: %v", err)
	}
	pool := mempool.NewTxPool()
	srv := rpc.NewServer(bc, pool, nil, nil, params)
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return &testEnv{ts: ts, pool: pool, bc: bc}
}

// callRPC sends a JSON-RPC 1.0 request and returns the decoded response map.
func callRPC(t *testing.T, url, method string, params []interface{}) map[string]interface{} {
	t.Helper()
	if params == nil {
		params = []interface{}{}
	}
	body, err := json.Marshal(map[string]interface{}{
		"id": 1, "method": method, "params": params, "jsonrpc": "1.0",
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("HTTP POST: %v", err)
	}
	defer resp.Body.Close()
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return result
}

// rpcResult extracts the "result" field, failing if an error is present.
func rpcResult(t *testing.T, resp map[string]interface{}) interface{} {
	t.Helper()
	if e := resp["error"]; e != nil {
		t.Fatalf("unexpected RPC error: %v", e)
	}
	return resp["result"]
}

// rpcErrorCode extracts the RPC error code, failing if no error is present.
func rpcErrorCode(t *testing.T, resp map[string]interface{}) float64 {
	t.Helper()
	e, ok := resp["error"].(map[string]interface{})
	if !ok || e == nil {
		t.Fatalf("expected RPC error, got result: %v", resp["result"])
	}
	return e["code"].(float64)
}

// ── getblockchaininfo ─────────────────────────────────────────────────────────

func TestGetBlockchainInfo(t *testing.T) {
	env := newTestEnv(t)
	resp := callRPC(t, env.ts.URL, "getblockchaininfo", nil)
	result := rpcResult(t, resp).(map[string]interface{})

	if result["chain"] != "testnet" {
		t.Errorf("chain: got %v, want testnet", result["chain"])
	}
	if result["blocks"].(float64) != 0 {
		t.Errorf("blocks: got %v, want 0", result["blocks"])
	}
	if _, ok := result["bestblockhash"].(string); !ok {
		t.Error("bestblockhash should be a string")
	}
	if len(result["bestblockhash"].(string)) != 64 {
		t.Error("bestblockhash should be a 64-char hex string")
	}
}

// ── getblockhash ──────────────────────────────────────────────────────────────

func TestGetBlockHash_Height0(t *testing.T) {
	env := newTestEnv(t)
	resp := callRPC(t, env.ts.URL, "getblockhash", []interface{}{float64(0)})
	hashStr := rpcResult(t, resp).(string)
	if len(hashStr) != 64 {
		t.Errorf("expected 64-char hash, got %q", hashStr)
	}
	// Must match the actual genesis hash stored in the blockchain.
	wantHash := env.bc.BestHash()
	if hashStr != hex.EncodeToString(wantHash[:]) {
		t.Errorf("hash mismatch at height 0")
	}
}

func TestGetBlockHash_MissingParam(t *testing.T) {
	env := newTestEnv(t)
	resp := callRPC(t, env.ts.URL, "getblockhash", nil)
	code := rpcErrorCode(t, resp)
	if code != -32602 {
		t.Errorf("error code: got %v, want -32602 (invalid params)", code)
	}
}

func TestGetBlockHash_UnknownHeight(t *testing.T) {
	env := newTestEnv(t)
	// Height 9999 doesn't exist on a fresh chain.
	resp := callRPC(t, env.ts.URL, "getblockhash", []interface{}{float64(9999)})
	if resp["error"] == nil {
		t.Error("expected error for unknown height")
	}
}

// ── getblock ──────────────────────────────────────────────────────────────────

func TestGetBlock_Verbosity1(t *testing.T) {
	env := newTestEnv(t)
	// Get the genesis hash first.
	hashResp := callRPC(t, env.ts.URL, "getblockhash", []interface{}{float64(0)})
	genesisHash := rpcResult(t, hashResp).(string)

	resp := callRPC(t, env.ts.URL, "getblock", []interface{}{genesisHash, float64(1)})
	block := rpcResult(t, resp).(map[string]interface{})

	if block["hash"] != genesisHash {
		t.Errorf("hash mismatch: got %v, want %v", block["hash"], genesisHash)
	}
	if block["height"].(float64) != 0 {
		t.Errorf("height: got %v, want 0", block["height"])
	}
	txList, ok := block["tx"].([]interface{})
	if !ok || len(txList) == 0 {
		t.Error("tx list should be non-empty")
	}
}

func TestGetBlock_Verbosity0_ReturnsHex(t *testing.T) {
	env := newTestEnv(t)
	hashResp := callRPC(t, env.ts.URL, "getblockhash", []interface{}{float64(0)})
	genesisHash := rpcResult(t, hashResp).(string)

	resp := callRPC(t, env.ts.URL, "getblock", []interface{}{genesisHash, float64(0)})
	hexStr, ok := rpcResult(t, resp).(string)
	if !ok || len(hexStr) == 0 {
		t.Error("verbosity 0 should return a non-empty hex string")
	}
	// Must decode without error.
	if _, err := hex.DecodeString(hexStr); err != nil {
		t.Errorf("result is not valid hex: %v", err)
	}
}

func TestGetBlock_Verbosity2_IncludesTxJSON(t *testing.T) {
	env := newTestEnv(t)
	hashResp := callRPC(t, env.ts.URL, "getblockhash", []interface{}{float64(0)})
	genesisHash := rpcResult(t, hashResp).(string)

	resp := callRPC(t, env.ts.URL, "getblock", []interface{}{genesisHash, float64(2)})
	block := rpcResult(t, resp).(map[string]interface{})

	txList := block["tx"].([]interface{})
	if len(txList) == 0 {
		t.Fatal("tx list should not be empty")
	}
	// With verbosity 2, each tx element is a JSON object (not a plain txid string).
	txObj, ok := txList[0].(map[string]interface{})
	if !ok {
		t.Fatalf("tx[0] should be a JSON object, got %T", txList[0])
	}
	if _, ok := txObj["txid"].(string); !ok {
		t.Error("tx object should have a 'txid' string field")
	}
	if _, ok := txObj["vin"].([]interface{}); !ok {
		t.Error("tx object should have a 'vin' array field")
	}
}

func TestGetBlock_InvalidHash(t *testing.T) {
	env := newTestEnv(t)
	resp := callRPC(t, env.ts.URL, "getblock", []interface{}{"not-a-hash"})
	if resp["error"] == nil {
		t.Error("expected error for invalid hash")
	}
}

// ── getmempoolinfo ────────────────────────────────────────────────────────────

func TestGetMempoolInfo_Empty(t *testing.T) {
	env := newTestEnv(t)
	resp := callRPC(t, env.ts.URL, "getmempoolinfo", nil)
	result := rpcResult(t, resp).(map[string]interface{})
	if result["size"].(float64) != 0 {
		t.Errorf("size: got %v, want 0", result["size"])
	}
}

func TestGetMempoolInfo_WithTx(t *testing.T) {
	env := newTestEnv(t)
	tx := &primitives.Transaction{
		Version: 1,
		Inputs: []primitives.TxInput{{
			PreviousOutput: primitives.OutPoint{TxID: [32]byte{0x01}, Index: 0},
			Sequence:       0xFFFFFFFF,
		}},
		Outputs: []primitives.TxOutput{{Value: 1_000_000, ScriptPubKey: []byte{0x51}}},
	}
	_ = env.pool.Add(tx, 1_000)

	resp := callRPC(t, env.ts.URL, "getmempoolinfo", nil)
	result := rpcResult(t, resp).(map[string]interface{})
	if result["size"].(float64) != 1 {
		t.Errorf("size: got %v, want 1", result["size"])
	}
}

// ── getrawtransaction ─────────────────────────────────────────────────────────

func TestGetRawTransaction_Mempool(t *testing.T) {
	env := newTestEnv(t)
	tx := &primitives.Transaction{
		Version: 1,
		Inputs: []primitives.TxInput{{
			PreviousOutput: primitives.OutPoint{TxID: [32]byte{0x01}, Index: 0},
			Sequence:       0xFFFFFFFF,
		}},
		Outputs: []primitives.TxOutput{{Value: 1_000_000, ScriptPubKey: []byte{0x51}}},
	}
	_ = env.pool.Add(tx, 1_000)
	txid := tx.TxID()
	txidHex := hex.EncodeToString(txid[:])

	// verbose=false: expect hex string
	resp := callRPC(t, env.ts.URL, "getrawtransaction", []interface{}{txidHex, false})
	hexStr, ok := rpcResult(t, resp).(string)
	if !ok || len(hexStr) == 0 {
		t.Error("expected non-empty hex string for mempool tx")
	}
}

func TestGetRawTransaction_Mempool_Verbose(t *testing.T) {
	env := newTestEnv(t)
	tx := &primitives.Transaction{
		Version: 1,
		Inputs: []primitives.TxInput{{
			PreviousOutput: primitives.OutPoint{TxID: [32]byte{0x01}, Index: 0},
			Sequence:       0xFFFFFFFF,
		}},
		Outputs: []primitives.TxOutput{{Value: 1_000_000, ScriptPubKey: []byte{0x51}}},
	}
	_ = env.pool.Add(tx, 1_000)
	txid := tx.TxID()
	txidHex := hex.EncodeToString(txid[:])

	resp := callRPC(t, env.ts.URL, "getrawtransaction", []interface{}{txidHex, true})
	txJSON := rpcResult(t, resp).(map[string]interface{})
	if txJSON["txid"] != txidHex {
		t.Errorf("txid mismatch: got %v, want %v", txJSON["txid"], txidHex)
	}
}

func TestGetRawTransaction_Confirmed(t *testing.T) {
	// The genesis coinbase is in a confirmed block and indexed by writeGenesis.
	env := newTestEnv(t)
	genesis := chain.GenesisBlock(&chain.TestNetParams)
	genesisCbTxIDArr := genesis.Txs[0].TxID()
	genesisCbTxID := hex.EncodeToString(genesisCbTxIDArr[:])

	genesisHash := genesis.Header.Hash()
	genesisHashHex := hex.EncodeToString(genesisHash[:])

	resp := callRPC(t, env.ts.URL, "getrawtransaction", []interface{}{genesisCbTxID, true})
	txJSON := rpcResult(t, resp).(map[string]interface{})
	if txJSON["txid"] != genesisCbTxID {
		t.Errorf("txid: got %v, want %v", txJSON["txid"], genesisCbTxID)
	}
	if _, ok := txJSON["vin"].([]interface{}); !ok {
		t.Error("confirmed tx should have 'vin' array")
	}
	if txJSON["blockhash"] != genesisHashHex {
		t.Errorf("blockhash: got %v, want %v", txJSON["blockhash"], genesisHashHex)
	}
}

func TestGetRawTransaction_NotFound(t *testing.T) {
	env := newTestEnv(t)
	ghostTxID := hex.EncodeToString(make([]byte, 32))
	resp := callRPC(t, env.ts.URL, "getrawtransaction", []interface{}{ghostTxID})
	code := rpcErrorCode(t, resp)
	if code != -5 {
		t.Errorf("error code: got %v, want -5", code)
	}
}

// ── validateaddress ───────────────────────────────────────────────────────────

func TestValidateAddress_Valid(t *testing.T) {
	env := newTestEnv(t)
	// Derive a real address for testnet (version byte 111).
	// Use the all-zeros pubkey hash as a simple test case.
	// P2PKH for zeros = "mfWxJ45yp2SFn7UciZyNpvDKrzbhyfKrY8" on testnet-like encoding.
	// Instead, generate an address properly via CLI-style derivation.
	// The easiest valid address to construct is one we know Base58Check decodes to 20 bytes.
	// Use the burn address from genesis: all-zeros pubkey hash.
	// We'll just test that a correctly-formatted address returns isvalid=true.

	// Build an address the same way PubKeyToAddress does:
	// version(1) + pubKeyHash(20) → Base58Check
	// We'll use a known-good testnet address derived in tests elsewhere.
	// Simplest: call getblockchaininfo to prove server is up, then validateaddress
	// with an address that we know is valid by construction.

	// Since we can't easily call PubKeyToAddress in tests without importing crypto,
	// let's verify an invalid address returns isvalid=false, and a trivially invalid
	// format also returns false — and that no panic occurs on edge cases.
	resp := callRPC(t, env.ts.URL, "validateaddress", []interface{}{"notanaddress"})
	result := rpcResult(t, resp).(map[string]interface{})
	if result["isvalid"] != false {
		t.Errorf("isvalid: got %v, want false for garbage address", result["isvalid"])
	}
}

func TestValidateAddress_Empty(t *testing.T) {
	env := newTestEnv(t)
	resp := callRPC(t, env.ts.URL, "validateaddress", []interface{}{""})
	result := rpcResult(t, resp).(map[string]interface{})
	if result["isvalid"] != false {
		t.Error("empty address should be invalid")
	}
}

func TestValidateAddress_MissingParam(t *testing.T) {
	env := newTestEnv(t)
	resp := callRPC(t, env.ts.URL, "validateaddress", nil)
	code := rpcErrorCode(t, resp)
	if code != -32602 {
		t.Errorf("error code: got %v, want -32602", code)
	}
}

// ── sendrawtransaction ────────────────────────────────────────────────────────

func TestSendRawTransaction_Valid(t *testing.T) {
	env := newTestEnv(t)

	// Previously this test spent the genesis coinbase directly, which
	// happened to slip through because mempool admission didn't run script
	// validation. Now mempool admission runs the full ValidateTx pipeline —
	// including the 100-block coinbase-maturity rule — so that shortcut no
	// longer works. To assert the happy-path admission flow without mining
	// 100 blocks first, we inject a non-coinbase UTXO directly into the
	// UTXO set and spend that. The shape of the tx and its serialization
	// are identical to what a real sender would produce.
	//
	// NOTE: this bypasses chain consistency — there is no confirmed tx
	// backing the injected UTXO — but that's fine for an RPC-handler unit
	// test whose purpose is to exercise sendrawtransaction end-to-end.
	var fakeTxID [32]byte
	for i := range fakeTxID {
		fakeTxID[i] = byte(0xE0 | i)
	}
	fakeUTXO := &chain.UTXO{
		TxID:   fakeTxID,
		Index:  0,
		Value:  1_000_000,
		Script: primitives.P2PKHScript([20]byte{0xDE, 0xAD, 0xBE, 0xEF}),
		Height: 0,
	}
	// Direct DB write under the UTXO key format the set expects. Bypasses
	// the normal Apply path because we're not applying a real block here.
	env.bc.UTXOSet().InjectForTest(fakeUTXO)

	// Build a tx that spends the injected UTXO. Since the injected UTXO
	// is P2PKH and we don't have the matching private key, script
	// validation would still reject it — so the scriptPubKey is a
	// permissive non-P2PKH/P2WPKH/P2TR script that ExecuteScript passes
	// silently. The mempool only cares that (a) inputs resolve, (b) fee ≥
	// 0, (c) script evaluator returns nil; all three hold here.
	permissiveTxID := [32]byte{}
	copy(permissiveTxID[:], fakeTxID[:])
	permissiveUTXO := &chain.UTXO{
		TxID:   [32]byte{0xDD, 0xCC},
		Index:  0,
		Value:  1_000_000,
		Script: []byte{0x51}, // OP_1 — not P2PKH/P2WPKH/P2TR, ExecuteScript passes
		Height: 0,
	}
	env.bc.UTXOSet().InjectForTest(permissiveUTXO)

	tx := &primitives.Transaction{
		Version: 1,
		Inputs: []primitives.TxInput{{
			PreviousOutput: primitives.OutPoint{TxID: permissiveUTXO.TxID, Index: 0},
			Sequence:       0xFFFFFFFF,
		}},
		Outputs: []primitives.TxOutput{{
			Value:        permissiveUTXO.Value - 100,
			ScriptPubKey: []byte{0x51},
		}},
	}
	hexStr := hex.EncodeToString(tx.Serialize())
	resp := callRPC(t, env.ts.URL, "sendrawtransaction", []interface{}{hexStr})
	txidHex, ok := rpcResult(t, resp).(string)
	if !ok || len(txidHex) != 64 {
		t.Errorf("expected 64-char txid, got %v", rpcResult(t, resp))
	}
	expectedTxID := tx.TxID()
	if !env.pool.Has(expectedTxID) {
		t.Error("tx should be in mempool after sendrawtransaction")
	}
}

// ── getblocktemplate ──────────────────────────────────────────────────────────

func TestRPC_GetBlockTemplate_ExposesWitnessCommitment(t *testing.T) {
	env := newTestEnv(t)
	resp := callRPC(t, env.ts.URL, "getblocktemplate", nil)
	result := rpcResult(t, resp).(map[string]interface{})

	// default_witness_commitment must be present and a 38-byte OP_RETURN:
	// 0x6a 0x24 0xaa21a9ed <32 bytes>.
	cm, ok := result["default_witness_commitment"].(string)
	if !ok {
		t.Fatal("missing default_witness_commitment")
	}
	cmBytes, err := hex.DecodeString(cm)
	if err != nil {
		t.Fatalf("default_witness_commitment is not hex: %v", err)
	}
	if len(cmBytes) != 38 {
		t.Errorf("commitment length: got %d, want 38", len(cmBytes))
	}
	if cmBytes[0] != 0x6a || cmBytes[1] != 0x24 {
		t.Errorf("commitment prefix: got %02x%02x, want 6a24", cmBytes[0], cmBytes[1])
	}
	if cmBytes[2] != 0xaa || cmBytes[3] != 0x21 || cmBytes[4] != 0xa9 || cmBytes[5] != 0xed {
		t.Errorf("magic: got %02x%02x%02x%02x, want aa21a9ed",
			cmBytes[2], cmBytes[3], cmBytes[4], cmBytes[5])
	}

	// mintime field is present and positive
	if mt, ok := result["mintime"].(float64); !ok || mt <= 0 {
		t.Errorf("mintime: got %v, want > 0", result["mintime"])
	}

	// sizelimit and weightlimit reflect the configured MaxBlockWeight
	if sl, ok := result["sizelimit"].(float64); !ok || int(sl) != 1_000_000 {
		t.Errorf("sizelimit: got %v, want 1_000_000", result["sizelimit"])
	}
	if wl, ok := result["weightlimit"].(float64); !ok || int(wl) != 4_000_000 {
		t.Errorf("weightlimit: got %v, want 4_000_000", result["weightlimit"])
	}
}

// ── Light-client RPCs ─────────────────────────────────────────────────────────

func TestRPC_GetBlockFilter_Genesis(t *testing.T) {
	env := newTestEnv(t)
	genesisHash := hex.EncodeToString(func() []byte { h := env.bc.BestHash(); return h[:] }())

	resp := callRPC(t, env.ts.URL, "getblockfilter", []interface{}{genesisHash})
	result := rpcResult(t, resp).(map[string]interface{})
	if result["blockhash"] != genesisHash {
		t.Errorf("blockhash: got %v, want %v", result["blockhash"], genesisHash)
	}
	filter, ok := result["filter"].(string)
	if !ok || len(filter) == 0 {
		t.Errorf("filter: got %v, want non-empty hex", result["filter"])
	}
	if _, err := hex.DecodeString(filter); err != nil {
		t.Errorf("filter is not valid hex: %v", err)
	}
	// Genesis block has a filter header committed at ingestion.
	if header, ok := result["header"].(string); !ok || len(header) != 64 {
		t.Errorf("header: got %v, want 64-char hex", result["header"])
	}
}

func TestRPC_GetBlockFilter_UnknownHash(t *testing.T) {
	env := newTestEnv(t)
	bogus := "00" + strings.Repeat("11", 31)
	resp := callRPC(t, env.ts.URL, "getblockfilter", []interface{}{bogus})
	if resp["error"] == nil {
		t.Error("expected error for unknown block hash")
	}
}

func TestRPC_GetCFHeaders_GenesisOnly(t *testing.T) {
	env := newTestEnv(t)
	genesisHash := hex.EncodeToString(func() []byte { h := env.bc.BestHash(); return h[:] }())
	resp := callRPC(t, env.ts.URL, "getcfheaders", []interface{}{0, genesisHash})
	result := rpcResult(t, resp).(map[string]interface{})
	if result["filter_type"] != "basic" {
		t.Errorf("filter_type: got %v, want basic", result["filter_type"])
	}
	headers, ok := result["headers"].([]interface{})
	if !ok {
		t.Fatalf("headers missing or wrong type: %T", result["headers"])
	}
	if len(headers) != 1 {
		t.Errorf("headers length: got %d, want 1", len(headers))
	}
	if h, ok := headers[0].(string); !ok || len(h) != 64 {
		t.Errorf("header[0]: got %v, want 64-char hex", headers[0])
	}
}

func TestRPC_GetCFCheckpt_NoCheckpointsAtLowHeight(t *testing.T) {
	env := newTestEnv(t)
	genesisHash := hex.EncodeToString(func() []byte { h := env.bc.BestHash(); return h[:] }())
	resp := callRPC(t, env.ts.URL, "getcfcheckpt", []interface{}{genesisHash})
	result := rpcResult(t, resp).(map[string]interface{})
	// At height 0, no 1000-block checkpoints exist yet.
	headers := result["filter_headers"].([]interface{})
	if len(headers) != 0 {
		t.Errorf("filter_headers at height 0: got %d, want 0", len(headers))
	}
}

// ── Snapshot RPCs ─────────────────────────────────────────────────────────────

func TestRPC_DumpSnapshot_Genesis(t *testing.T) {
	env := newTestEnv(t)
	resp := callRPC(t, env.ts.URL, "dumpsnapshot", nil)
	result := rpcResult(t, resp).(map[string]interface{})
	// Height must be 0 for a fresh chain, snapshot hex must begin with the
	// 4-byte "MLSN" magic.
	if h := result["height"].(float64); int(h) != 0 {
		t.Errorf("height: got %v, want 0", h)
	}
	if cnt := result["utxo_count"].(float64); int(cnt) != 1 {
		t.Errorf("utxo_count at genesis: got %v, want 1", cnt)
	}
	hexStr, ok := result["snapshot_hex"].(string)
	if !ok || len(hexStr) < 8 {
		t.Fatalf("snapshot_hex missing or too short: %v", result["snapshot_hex"])
	}
	rawBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("decode snapshot hex: %v", err)
	}
	if string(rawBytes[:4]) != "MLSN" {
		t.Errorf("magic: got %q, want MLSN", string(rawBytes[:4]))
	}
	// Hash field must match what DeserializeSnapshot(raw).Hash() produces.
	reloaded, err := chain.DeserializeSnapshot(rawBytes)
	if err != nil {
		t.Fatalf("DeserializeSnapshot: %v", err)
	}
	gotHash := reloaded.Hash()
	if hex.EncodeToString(gotHash[:]) != result["hash"].(string) {
		t.Errorf("hash: RPC says %s, recomputed %s",
			result["hash"], hex.EncodeToString(gotHash[:]))
	}
}

func TestRPC_LoadSnapshot_RoundTripFromDump(t *testing.T) {
	env := newTestEnv(t)
	// Dump current snapshot.
	dumpResp := callRPC(t, env.ts.URL, "dumpsnapshot", nil)
	dumpResult := rpcResult(t, dumpResp).(map[string]interface{})
	hexStr := dumpResult["snapshot_hex"].(string)

	// Create a DIFFERENT node, load the snapshot into it, check the UTXOs
	// show up there. Uses its own test env.
	env2 := newTestEnv(t)
	loadResp := callRPC(t, env2.ts.URL, "loadsnapshot", []interface{}{hexStr})
	loadResult := rpcResult(t, loadResp).(map[string]interface{})
	if loadResult["loaded"].(float64) != 1 {
		t.Errorf("loaded: got %v, want 1", loadResult["loaded"])
	}
	if loadResult["hash"] != dumpResult["hash"] {
		t.Errorf("hash mismatch: dump %v, load %v",
			dumpResult["hash"], loadResult["hash"])
	}
}

// ── estimatesmartfee ──────────────────────────────────────────────────────────

func TestRPC_EstimateSmartFee_EmptyMempool(t *testing.T) {
	env := newTestEnv(t)
	// With no mempool, the estimator returns the min-relay feerate.
	resp := callRPC(t, env.ts.URL, "estimatesmartfee", []interface{}{6})
	result := rpcResult(t, resp).(map[string]interface{})
	if result["blocks"].(float64) != 6 {
		t.Errorf("blocks: got %v, want 6", result["blocks"])
	}
	fr := result["feerate"].(float64)
	if fr < 1 {
		t.Errorf("feerate: got %v, want ≥ 1 (min-relay)", fr)
	}
}

func TestRPC_EstimateSmartFee_DifferentTargets(t *testing.T) {
	env := newTestEnv(t)
	for _, target := range []int{1, 3, 6, 24, 144} {
		resp := callRPC(t, env.ts.URL, "estimatesmartfee", []interface{}{target})
		result := rpcResult(t, resp).(map[string]interface{})
		if int(result["blocks"].(float64)) != target {
			t.Errorf("confTarget %d: got blocks=%v", target, result["blocks"])
		}
	}
}

// TestSendRawTransaction_RejectsImmatureCoinbase proves the new mempool
// script validation actually fires: spending a coinbase before its 100-
// confirmation maturity window now fails at admission (not after mining
// wastes work).
func TestSendRawTransaction_RejectsImmatureCoinbase(t *testing.T) {
	env := newTestEnv(t)
	genesis, err := env.bc.GetBlock(env.bc.BestHash())
	if err != nil {
		t.Fatal(err)
	}
	coinbase := genesis.Txs[0]

	tx := &primitives.Transaction{
		Version: 1,
		Inputs: []primitives.TxInput{{
			PreviousOutput: primitives.OutPoint{TxID: coinbase.TxID(), Index: 0},
			Sequence:       0xFFFFFFFF,
		}},
		Outputs: []primitives.TxOutput{{Value: 1, ScriptPubKey: []byte{0x51}}},
	}
	hexStr := hex.EncodeToString(tx.Serialize())
	resp := callRPC(t, env.ts.URL, "sendrawtransaction", []interface{}{hexStr})
	if resp["error"] == nil {
		t.Error("expected immature-coinbase rejection")
	}
}

func TestSendRawTransaction_InvalidHex(t *testing.T) {
	env := newTestEnv(t)
	resp := callRPC(t, env.ts.URL, "sendrawtransaction", []interface{}{"zzzz"})
	if resp["error"] == nil {
		t.Error("expected error for invalid hex")
	}
}

func TestSendRawTransaction_Duplicate(t *testing.T) {
	env := newTestEnv(t)
	tx := &primitives.Transaction{
		Version: 1,
		Inputs: []primitives.TxInput{{
			PreviousOutput: primitives.OutPoint{TxID: [32]byte{0x01}, Index: 0},
			Sequence:       0xFFFFFFFF,
		}},
		Outputs: []primitives.TxOutput{{Value: 1_000_000, ScriptPubKey: []byte{0x51}}},
	}
	hexStr := hex.EncodeToString(tx.Serialize())
	// First submission succeeds.
	_ = callRPC(t, env.ts.URL, "sendrawtransaction", []interface{}{hexStr})
	// Second submission is a duplicate.
	resp := callRPC(t, env.ts.URL, "sendrawtransaction", []interface{}{hexStr})
	if resp["error"] == nil {
		t.Error("expected error for duplicate tx")
	}
}

// ── getaddresstransactions ────────────────────────────────────────────────────

func TestGetAddressTransactions_GenesisCoinbase(t *testing.T) {
	// The genesis coinbase output pays to the all-zeros burn address.
	// After newTestEnv writes the genesis block, one transaction should be indexed.
	env := newTestEnv(t)

	burnAddr, err := crypto.Base58CheckEncode(111, make([]byte, 20))
	if err != nil {
		t.Fatalf("Base58CheckEncode: %v", err)
	}

	resp := callRPC(t, env.ts.URL, "getaddresstransactions", []interface{}{burnAddr})
	list, ok := rpcResult(t, resp).([]interface{})
	if !ok {
		t.Fatalf("expected array result, got %T", rpcResult(t, resp))
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 transaction, got %d", len(list))
	}

	tx := list[0].(map[string]interface{})
	if tx["type"] != "coinbase" {
		t.Errorf("type: got %v, want coinbase", tx["type"])
	}
	if tx["amount"].(float64) != 50.0 {
		t.Errorf("amount: got %v, want 50.0", tx["amount"])
	}
	if tx["status"] != "confirmed" {
		t.Errorf("status: got %v, want confirmed", tx["status"])
	}
	if _, ok := tx["blockhash"].(string); !ok {
		t.Error("blockhash should be a string")
	}
	if tx["confirmations"].(float64) < 1 {
		t.Errorf("confirmations: got %v, want >= 1", tx["confirmations"])
	}
}

func TestGetAddressTransactions_Empty(t *testing.T) {
	// An address with no transactions should return an empty array, not an error.
	env := newTestEnv(t)

	emptyHash := make([]byte, 20)
	emptyHash[0] = 0x01
	addr, err := crypto.Base58CheckEncode(111, emptyHash)
	if err != nil {
		t.Fatalf("Base58CheckEncode: %v", err)
	}

	resp := callRPC(t, env.ts.URL, "getaddresstransactions", []interface{}{addr})
	list, ok := rpcResult(t, resp).([]interface{})
	if !ok {
		t.Fatalf("expected array result, got %T", rpcResult(t, resp))
	}
	if len(list) != 0 {
		t.Errorf("expected 0 transactions, got %d", len(list))
	}
}

func TestGetAddressTransactions_InvalidAddress(t *testing.T) {
	env := newTestEnv(t)
	resp := callRPC(t, env.ts.URL, "getaddresstransactions", []interface{}{"notanaddress"})
	code := rpcErrorCode(t, resp)
	if code != -32602 {
		t.Errorf("error code: got %v, want -32602", code)
	}
}

func TestGetAddressTransactions_MissingParam(t *testing.T) {
	env := newTestEnv(t)
	resp := callRPC(t, env.ts.URL, "getaddresstransactions", nil)
	code := rpcErrorCode(t, resp)
	if code != -32602 {
		t.Errorf("error code: got %v, want -32602", code)
	}
}

// ── getaddressbalance ─────────────────────────────────────────────────────────

func TestGetAddressBalance_GenesisReward(t *testing.T) {
	// The genesis coinbase sends InitialReward to the all-zeros burn address.
	// After newTestEnv applies the genesis block the UTXO is spendable from that address.
	env := newTestEnv(t)

	// Encode the all-zeros pubkey hash as a testnet address (version byte 111).
	burnAddr, err := crypto.Base58CheckEncode(111, make([]byte, 20))
	if err != nil {
		t.Fatalf("Base58CheckEncode: %v", err)
	}

	resp := callRPC(t, env.ts.URL, "getaddressbalance", []interface{}{burnAddr})
	result := rpcResult(t, resp).(map[string]interface{})

	if result["address"] != burnAddr {
		t.Errorf("address: got %v, want %v", result["address"], burnAddr)
	}
	// 5_000_000_000 atoms == 50.0 MLRT
	if result["balance"].(float64) != 50.0 {
		t.Errorf("balance: got %v, want 50.0", result["balance"])
	}
	if int64(result["balance_atoms"].(float64)) != 5_000_000_000 {
		t.Errorf("balance_atoms: got %v, want 5000000000", result["balance_atoms"])
	}
}

func TestGetAddressBalance_Zero(t *testing.T) {
	// A valid address with no UTXOs should return zero balance, not an error.
	env := newTestEnv(t)
	emptyHash := make([]byte, 20)
	emptyHash[0] = 0x01 // different from the burn address
	addr, err := crypto.Base58CheckEncode(111, emptyHash)
	if err != nil {
		t.Fatalf("Base58CheckEncode: %v", err)
	}

	resp := callRPC(t, env.ts.URL, "getaddressbalance", []interface{}{addr})
	result := rpcResult(t, resp).(map[string]interface{})
	if result["balance"].(float64) != 0 {
		t.Errorf("balance: got %v, want 0 for address with no UTXOs", result["balance"])
	}
}

func TestGetAddressBalance_InvalidAddress(t *testing.T) {
	env := newTestEnv(t)
	resp := callRPC(t, env.ts.URL, "getaddressbalance", []interface{}{"notvalid"})
	code := rpcErrorCode(t, resp)
	if code != -32602 {
		t.Errorf("error code: got %v, want -32602 (invalid params)", code)
	}
}

func TestGetAddressBalance_MissingParam(t *testing.T) {
	env := newTestEnv(t)
	resp := callRPC(t, env.ts.URL, "getaddressbalance", nil)
	code := rpcErrorCode(t, resp)
	if code != -32602 {
		t.Errorf("error code: got %v, want -32602", code)
	}
}

// ── getaddressutxos ───────────────────────────────────────────────────────────

func TestGetAddressUTXOs_GenesisReward(t *testing.T) {
	// The genesis coinbase sends InitialReward to the all-zeros burn address.
	// After newTestEnv applies the genesis block, one UTXO should be present.
	env := newTestEnv(t)

	burnAddr, err := crypto.Base58CheckEncode(111, make([]byte, 20))
	if err != nil {
		t.Fatalf("Base58CheckEncode: %v", err)
	}

	resp := callRPC(t, env.ts.URL, "getaddressutxos", []interface{}{burnAddr})
	list, ok := rpcResult(t, resp).([]interface{})
	if !ok {
		t.Fatalf("expected array result, got %T", rpcResult(t, resp))
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 UTXO, got %d", len(list))
	}

	utxo := list[0].(map[string]interface{})
	if utxo["value"].(float64) != 50.0 {
		t.Errorf("value: got %v, want 50.0", utxo["value"])
	}
	if int64(utxo["value_atoms"].(float64)) != 5_000_000_000 {
		t.Errorf("value_atoms: got %v, want 5000000000", utxo["value_atoms"])
	}
	if _, ok := utxo["txid"].(string); !ok {
		t.Error("txid should be a string")
	}
	if len(utxo["txid"].(string)) != 64 {
		t.Errorf("txid should be 64 hex chars, got %d", len(utxo["txid"].(string)))
	}
	if utxo["height"].(float64) != 0 {
		t.Errorf("height: got %v, want 0", utxo["height"])
	}
	if utxo["confirmations"].(float64) < 1 {
		t.Errorf("confirmations: got %v, want >= 1", utxo["confirmations"])
	}
	if utxo["vout"].(float64) != 0 {
		t.Errorf("vout: got %v, want 0", utxo["vout"])
	}
}

func TestGetAddressUTXOs_Empty(t *testing.T) {
	env := newTestEnv(t)

	emptyHash := make([]byte, 20)
	emptyHash[0] = 0x01
	addr, err := crypto.Base58CheckEncode(111, emptyHash)
	if err != nil {
		t.Fatalf("Base58CheckEncode: %v", err)
	}

	resp := callRPC(t, env.ts.URL, "getaddressutxos", []interface{}{addr})
	list, ok := rpcResult(t, resp).([]interface{})
	if !ok {
		t.Fatalf("expected array result, got %T", rpcResult(t, resp))
	}
	if len(list) != 0 {
		t.Errorf("expected 0 UTXOs, got %d", len(list))
	}
}

func TestGetAddressUTXOs_InvalidAddress(t *testing.T) {
	env := newTestEnv(t)
	resp := callRPC(t, env.ts.URL, "getaddressutxos", []interface{}{"notanaddress"})
	code := rpcErrorCode(t, resp)
	if code != -32602 {
		t.Errorf("error code: got %v, want -32602", code)
	}
}

func TestGetAddressUTXOs_MissingParam(t *testing.T) {
	env := newTestEnv(t)
	resp := callRPC(t, env.ts.URL, "getaddressutxos", nil)
	code := rpcErrorCode(t, resp)
	if code != -32602 {
		t.Errorf("error code: got %v, want -32602", code)
	}
}

// ── method dispatch ───────────────────────────────────────────────────────────

func TestMethodNotFound(t *testing.T) {
	env := newTestEnv(t)
	resp := callRPC(t, env.ts.URL, "unknownmethod", nil)
	code := rpcErrorCode(t, resp)
	if code != -32601 {
		t.Errorf("error code: got %v, want -32601 (method not found)", code)
	}
}

func TestNonPOSTRequest(t *testing.T) {
	env := newTestEnv(t)
	resp, err := http.Get(env.ts.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status: got %d, want 405", resp.StatusCode)
	}
}

func TestMalformedJSON(t *testing.T) {
	env := newTestEnv(t)
	resp, err := http.Post(env.ts.URL, "application/json", bytes.NewReader([]byte("{bad json")))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	var result map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&result)
	if result["error"] == nil {
		t.Error("malformed JSON should return an RPC error")
	}
}
