package rpc

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/malairt/malairt/internal/chain"
	"github.com/malairt/malairt/internal/consensus"
	"github.com/malairt/malairt/internal/crypto"
	"github.com/malairt/malairt/internal/primitives"
)

// getBlockchainInfo returns summary information about the chain state.
// Response: {chain, blocks, bestblockhash, difficulty, mediantime, chainwork}
func (s *Server) getBlockchainInfo(_ []interface{}) (interface{}, *rpcError) {
	height := s.bc.BestHeight()
	bestHash := s.bc.BestHash()
	header := s.bc.BestHeader()

	difficulty := bitsToFloat64(header.Bits)

	return map[string]interface{}{
		"chain":         s.params.Name,
		"blocks":        height,
		"bestblockhash": hex.EncodeToString(bestHash[:]),
		"difficulty":    difficulty,
		"mediantime":    header.Timestamp,
		"chainwork":     fmt.Sprintf("%064x", big.NewInt(int64(height))),
		"softforks":     []interface{}{},
	}, nil
}

// getBlockHash returns the block hash at the given height.
func (s *Server) getBlockHash(params []interface{}) (interface{}, *rpcError) {
	if len(params) < 1 {
		return nil, newRPCError(errCodeInvalidParams, "height required")
	}
	height, err := toUint64(params[0])
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid height: "+err.Error())
	}
	hash, err := s.bc.GetBlockHashAtHeight(height)
	if err != nil {
		return nil, newRPCError(errCodeInternal, "block not found: "+err.Error())
	}
	return hex.EncodeToString(hash[:]), nil
}

// getBlockHeader returns a block header by hash, as hex or verbose JSON.
func (s *Server) getBlockHeader(params []interface{}) (interface{}, *rpcError) {
	if len(params) < 1 {
		return nil, newRPCError(errCodeInvalidParams, "hash required")
	}
	hash, err := parseHash(params[0])
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, err.Error())
	}

	verbose := true
	if len(params) >= 2 {
		verbose, _ = toBool(params[1])
	}

	header, err := s.bc.GetBlockHeader(hash)
	if err != nil {
		return nil, newRPCError(errCodeInternal, "header not found: "+err.Error())
	}

	if !verbose {
		return hex.EncodeToString(header.Serialize()), nil
	}

	hashStr := hex.EncodeToString(hash[:])
	prevHash := hex.EncodeToString(header.PreviousHash[:])
	merkle := hex.EncodeToString(header.MerkleRoot[:])

	result := map[string]interface{}{
		"hash":              hashStr,
		"height":            header.Height,
		"version":           header.Version,
		"previousblockhash": prevHash,
		"merkleroot":        merkle,
		"time":              header.Timestamp,
		"bits":              fmt.Sprintf("%08x", header.Bits),
		"nonce":             header.Nonce,
		"difficulty":        bitsToFloat64(header.Bits),
	}

	// Add next block hash if available
	nextHash, err := s.bc.GetBlockHashAtHeight(header.Height + 1)
	if err == nil {
		result["nextblockhash"] = hex.EncodeToString(nextHash[:])
	}

	return result, nil
}

// getBlock returns a block by hash with configurable verbosity.
// verbosity 0: hex-encoded raw block
// verbosity 1: block summary JSON
// verbosity 2: block with full transaction JSON
func (s *Server) getBlock(params []interface{}) (interface{}, *rpcError) {
	if len(params) < 1 {
		return nil, newRPCError(errCodeInvalidParams, "hash required")
	}
	hash, err := parseHash(params[0])
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, err.Error())
	}

	verbosity := 1
	if len(params) >= 2 {
		v, err := toInt(params[1])
		if err == nil {
			verbosity = v
		}
	}

	block, err := s.bc.GetBlock(hash)
	if err != nil {
		return nil, newRPCError(errCodeInternal, "block not found: "+err.Error())
	}

	if verbosity == 0 {
		return hex.EncodeToString(block.Serialize()), nil
	}

	hashStr := hex.EncodeToString(hash[:])
	prevHash := hex.EncodeToString(block.Header.PreviousHash[:])
	merkle := hex.EncodeToString(block.Header.MerkleRoot[:])

	var txids []interface{}
	for _, tx := range block.Txs {
		txid := tx.TxID()
		if verbosity == 2 {
			txids = append(txids, txToJSON(tx))
		} else {
			txids = append(txids, hex.EncodeToString(txid[:]))
		}
	}

	result := map[string]interface{}{
		"hash":              hashStr,
		"height":            block.Header.Height,
		"version":           block.Header.Version,
		"previousblockhash": prevHash,
		"merkleroot":        merkle,
		"time":              block.Header.Timestamp,
		"bits":              fmt.Sprintf("%08x", block.Header.Bits),
		"nonce":             block.Header.Nonce,
		"difficulty":        bitsToFloat64(block.Header.Bits),
		"ntx":               len(block.Txs),
		"tx":                txids,
		"size":              len(block.Serialize()),
	}

	nextHash, err := s.bc.GetBlockHashAtHeight(block.Header.Height + 1)
	if err == nil {
		result["nextblockhash"] = hex.EncodeToString(nextHash[:])
	}

	return result, nil
}

// getRawTransaction retrieves a transaction by txid.
// Returns hex string if verbose=false, JSON object if verbose=true.
func (s *Server) getRawTransaction(params []interface{}) (interface{}, *rpcError) {
	if len(params) < 1 {
		return nil, newRPCError(errCodeInvalidParams, "txid required")
	}
	txid, err := parseHash(params[0])
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, err.Error())
	}

	verbose := false
	if len(params) >= 2 {
		verbose, _ = toBool(params[1])
	}

	// Check mempool first, then fall back to the confirmed txindex.
	tx, inMempool := s.pool.Get(txid)
	var confirmedBlockHash [32]byte
	if !inMempool {
		confirmed, blockHash, err := s.bc.GetTransactionWithBlockHash(txid)
		if err != nil {
			return nil, newRPCError(-5, "transaction not found")
		}
		tx = confirmed
		confirmedBlockHash = blockHash
	}

	if !verbose {
		return hex.EncodeToString(tx.Serialize()), nil
	}

	result := txToJSON(tx)
	if !inMempool {
		result["blockhash"] = hex.EncodeToString(confirmedBlockHash[:])
	}
	return result, nil
}

// sendRawTransaction decodes and submits a raw transaction to the mempool.
func (s *Server) sendRawTransaction(params []interface{}) (interface{}, *rpcError) {
	if len(params) < 1 {
		return nil, newRPCError(errCodeInvalidParams, "hex string required")
	}
	hexStr, ok := params[0].(string)
	if !ok {
		return nil, newRPCError(errCodeInvalidParams, "parameter must be a hex string")
	}

	data, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid hex: "+err.Error())
	}

	tx, _, err := primitives.DeserializeTx(data)
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, "failed to decode transaction: "+err.Error())
	}

	if err := s.pool.Add(tx); err != nil {
		return nil, newRPCError(-26, "transaction rejected: "+err.Error())
	}

	// Broadcast to peers if P2P is running
	if s.peerSrv != nil {
		s.peerSrv.BroadcastTx(tx)
	}

	txid := tx.TxID()
	return hex.EncodeToString(txid[:]), nil
}

// getMempoolInfo returns statistics about the memory pool.
func (s *Server) getMempoolInfo(_ []interface{}) (interface{}, *rpcError) {
	return map[string]interface{}{
		"size":  s.pool.Count(),
		"bytes": s.pool.Size(),
		"usage": s.pool.Size(),
	}, nil
}

// getRawMempool returns all txids in the mempool.
func (s *Server) getRawMempool(params []interface{}) (interface{}, *rpcError) {
	verbose := false
	if len(params) >= 1 {
		verbose, _ = toBool(params[0])
	}

	if !verbose {
		txs := s.pool.GetAll()
		ids := make([]string, 0, len(txs))
		for _, tx := range txs {
			txid := tx.TxID()
			ids = append(ids, hex.EncodeToString(txid[:]))
		}
		return ids, nil
	}

	txs := s.pool.GetAll()
	result := make(map[string]interface{}, len(txs))
	for _, tx := range txs {
		txid := tx.TxID()
		txidStr := hex.EncodeToString(txid[:])
		result[txidStr] = map[string]interface{}{
			"size": len(tx.Serialize()),
			"time": time.Now().Unix(),
		}
	}
	return result, nil
}

// getBlockTemplate returns a block template for external miners (simplified GBT).
func (s *Server) getBlockTemplate(params []interface{}) (interface{}, *rpcError) {
	height := s.bc.BestHeight() + 1
	bestHash := s.bc.BestHash()
	bits, err := s.bc.CalcNextBits()
	if err != nil {
		return nil, newRPCError(errCodeInternal, "calc bits: "+err.Error())
	}

	subsidy := chain.CalcBlockSubsidy(height, s.params)
	txs := s.pool.GetSorted(2000)

	txResults := make([]interface{}, 0, len(txs))
	for _, tx := range txs {
		txid := tx.TxID()
		txResults = append(txResults, map[string]interface{}{
			"data":    hex.EncodeToString(tx.Serialize()),
			"txid":    hex.EncodeToString(txid[:]),
			"fee":     0,
			"sigops":  0,
			"depends": []interface{}{},
		})
	}

	target := consensus.CompactToBig(bits)
	targetHex := fmt.Sprintf("%064x", target)

	return map[string]interface{}{
		"version":           1,
		"previousblockhash": hex.EncodeToString(bestHash[:]),
		"transactions":      txResults,
		"coinbasevalue":     subsidy,
		"target":            targetHex,
		"bits":              fmt.Sprintf("%08x", bits),
		"height":            height,
		"curtime":           time.Now().Unix(),
		"mutable":           []string{"time", "transactions", "prevblock"},
		"noncerange":        "00000000ffffffffffffffff",
	}, nil
}

// submitBlock decodes and submits a raw block to the chain.
func (s *Server) submitBlock(params []interface{}) (interface{}, *rpcError) {
	if len(params) < 1 {
		return nil, newRPCError(errCodeInvalidParams, "hex string required")
	}
	hexStr, ok := params[0].(string)
	if !ok {
		return nil, newRPCError(errCodeInvalidParams, "parameter must be a hex string")
	}

	data, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid hex: "+err.Error())
	}

	block, err := primitives.DeserializeBlock(data)
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, "failed to decode block: "+err.Error())
	}

	if err := s.bc.ProcessBlock(block); err != nil {
		return nil, newRPCError(-25, "rejected: "+err.Error())
	}

	s.pool.RemoveBlock(block)
	if s.peerSrv != nil {
		s.peerSrv.BroadcastBlock(block)
	}

	return nil, nil // Bitcoin RPC returns null on success
}

// getPeerInfo returns information about connected peers.
func (s *Server) getPeerInfo(_ []interface{}) (interface{}, *rpcError) {
	if s.peerSrv == nil {
		return []interface{}{}, nil
	}
	return s.peerSrv.GetPeerInfo(), nil
}

// getNetworkInfo returns information about the P2P network.
func (s *Server) getNetworkInfo(_ []interface{}) (interface{}, *rpcError) {
	connections := 0
	if s.peerSrv != nil {
		connections = s.peerSrv.PeerCount()
	}

	return map[string]interface{}{
		"version":          70001,
		"subversion":       "/Malairted:0.1.0/",
		"protocolversion":  70001,
		"connections":      connections,
		"networks":         []interface{}{},
		"relayfee":         0.00001000,
		"incrementalfee":   0.00001000,
		"localaddresses":   []interface{}{},
		"warnings":         "",
	}, nil
}

// getMiningInfo returns mining-related statistics.
func (s *Server) getMiningInfo(_ []interface{}) (interface{}, *rpcError) {
	height := s.bc.BestHeight()
	header := s.bc.BestHeader()
	difficulty := bitsToFloat64(header.Bits)

	var hashRate int64
	var minerRunning bool
	if s.miner != nil {
		hashRate = s.miner.HashRate.Load()
		minerRunning = s.miner.IsRunning()
	}

	return map[string]interface{}{
		"blocks":           height,
		"currentblocksize": 0,
		"currentblocktx":   s.pool.Count(),
		"difficulty":       difficulty,
		"errors":           "",
		"hashespersec":     hashRate,
		"pooledtx":         s.pool.Count(),
		"chain":            s.params.Name,
		"generate":         minerRunning,
	}, nil
}

// validateAddress validates an address and returns information about it.
func (s *Server) validateAddress(params []interface{}) (interface{}, *rpcError) {
	if len(params) < 1 {
		return nil, newRPCError(errCodeInvalidParams, "address required")
	}
	addrStr, ok := params[0].(string)
	if !ok {
		return nil, newRPCError(errCodeInvalidParams, "address must be a string")
	}

	_, payload, err := crypto.Base58CheckDecode(addrStr)
	if err != nil {
		return map[string]interface{}{
			"isvalid": false,
			"address": addrStr,
		}, nil
	}

	if len(payload) != 20 {
		return map[string]interface{}{
			"isvalid": false,
			"address": addrStr,
		}, nil
	}

	var pubKeyHash [20]byte
	copy(pubKeyHash[:], payload)
	script := primitives.P2PKHScript(pubKeyHash)

	return map[string]interface{}{
		"isvalid":      true,
		"address":      addrStr,
		"scriptPubKey": hex.EncodeToString(script),
		"ismine":       false,
		"iswatchonly":  false,
		"isscript":     false,
	}, nil
}

// getAddressTransactions returns the most recent confirmed transactions that paid
// to a P2PKH address. The result is ordered most-recent-first.
// Params: [address, limit (optional, default 50)]
// Response: [{txid, type, amount (MLRT), fee, address, blockhash, height, confirmations, status, timestamp}]
func (s *Server) getAddressTransactions(params []interface{}) (interface{}, *rpcError) {
	if len(params) < 1 {
		return nil, newRPCError(errCodeInvalidParams, "address required")
	}
	addrStr, ok := params[0].(string)
	if !ok {
		return nil, newRPCError(errCodeInvalidParams, "address must be a string")
	}

	_, payload, err := crypto.Base58CheckDecode(addrStr)
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid address: "+err.Error())
	}
	if len(payload) != 20 {
		return nil, newRPCError(errCodeInvalidParams, "invalid address: expected 20-byte pubkey hash")
	}

	limit := 50
	if len(params) >= 2 {
		if l, err := toInt(params[1]); err == nil && l > 0 {
			limit = l
		}
	}

	var pubKeyHash [20]byte
	copy(pubKeyHash[:], payload)

	records, err := s.bc.GetTransactionsByAddress(pubKeyHash, limit)
	if err != nil {
		return nil, newRPCError(errCodeInternal, "address lookup failed: "+err.Error())
	}

	bestHeight := s.bc.BestHeight()

	result := make([]interface{}, 0, len(records))
	for _, rec := range records {
		txid := rec.Tx.TxID()

		// Sum P2PKH outputs that pay to the queried address.
		var received int64
		for _, out := range rec.Tx.Outputs {
			h, ok := primitives.ExtractP2PKHHash(out.ScriptPubKey)
			if !ok {
				continue
			}
			if h == pubKeyHash {
				received += out.Value
			}
		}

		txType := "received"
		if rec.Tx.IsCoinbase() {
			txType = "coinbase"
		}

		confirmations := int64(0)
		if bestHeight >= rec.Height {
			confirmations = int64(bestHeight-rec.Height) + 1
		}

		result = append(result, map[string]interface{}{
			"txid":          hex.EncodeToString(txid[:]),
			"type":          txType,
			"amount":        float64(received) / 1e8,
			"fee":           0.0,
			"address":       addrStr,
			"blockhash":     hex.EncodeToString(rec.BlockHash[:]),
			"height":        rec.Height,
			"confirmations": confirmations,
			"status":        "confirmed",
			"timestamp":     rec.Timestamp,
		})
	}

	return result, nil
}

// getAddressUTXOs returns the individual unspent outputs for a P2PKH address.
// Params: [address]
// Response: [{txid, vout, value (MLRT), value_atoms, height, confirmations}]
func (s *Server) getAddressUTXOs(params []interface{}) (interface{}, *rpcError) {
	if len(params) < 1 {
		return nil, newRPCError(errCodeInvalidParams, "address required")
	}
	addrStr, ok := params[0].(string)
	if !ok {
		return nil, newRPCError(errCodeInvalidParams, "address must be a string")
	}

	_, payload, err := crypto.Base58CheckDecode(addrStr)
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid address: "+err.Error())
	}
	if len(payload) != 20 {
		return nil, newRPCError(errCodeInvalidParams, "invalid address: expected 20-byte pubkey hash")
	}

	var pubKeyHash [20]byte
	copy(pubKeyHash[:], payload)

	utxos, err := s.bc.UTXOSet().GetUTXOsByAddress(pubKeyHash)
	if err != nil {
		return nil, newRPCError(errCodeInternal, "UTXO lookup failed: "+err.Error())
	}

	bestHeight := s.bc.BestHeight()

	result := make([]interface{}, 0, len(utxos))
	for _, utxo := range utxos {
		confirmations := uint64(0)
		if bestHeight >= utxo.Height {
			confirmations = bestHeight - utxo.Height + 1
		}
		result = append(result, map[string]interface{}{
			"txid":        hex.EncodeToString(utxo.TxID[:]),
			"vout":        utxo.Index,
			"value":       float64(utxo.Value) / 1e8,
			"value_atoms": utxo.Value,
			"height":      utxo.Height,
			"confirmations": confirmations,
		})
	}

	return result, nil
}

// getAddressBalance returns the confirmed spendable balance for a P2PKH address.
// Response: {address, balance (MLRT as float64), balance_atoms (int64)}
func (s *Server) getAddressBalance(params []interface{}) (interface{}, *rpcError) {
	if len(params) < 1 {
		return nil, newRPCError(errCodeInvalidParams, "address required")
	}
	addrStr, ok := params[0].(string)
	if !ok {
		return nil, newRPCError(errCodeInvalidParams, "address must be a string")
	}

	_, payload, err := crypto.Base58CheckDecode(addrStr)
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid address: "+err.Error())
	}
	if len(payload) != 20 {
		return nil, newRPCError(errCodeInvalidParams, "invalid address: expected 20-byte pubkey hash")
	}

	var pubKeyHash [20]byte
	copy(pubKeyHash[:], payload)

	atoms := s.bc.UTXOSet().Balance(pubKeyHash)

	return map[string]interface{}{
		"address":       addrStr,
		"balance":       float64(atoms) / 1e8,
		"balance_atoms": atoms,
	}, nil
}

// stop initiates a graceful shutdown of the node.
func (s *Server) stop(_ []interface{}) (interface{}, *rpcError) {
	go func() {
		// Signal shutdown via the stopCh channel
		select {
		case s.stopCh <- struct{}{}:
		default:
		}
	}()
	return "Malairt node stopping.", nil
}

// StopCh returns the channel that receives a signal when stop is called via RPC.
func (s *Server) StopCh() <-chan struct{} {
	return s.stopCh
}

// --- Helper functions ---

// bitsToFloat64 converts compact bits to a difficulty float64.
// difficulty = genesis_target / current_target
func bitsToFloat64(bits uint32) float64 {
	genesisBits := uint32(0x207fffff)
	genesisTarget := consensus.CompactToBig(genesisBits)
	currentTarget := consensus.CompactToBig(bits)
	if currentTarget.Sign() == 0 {
		return 0
	}
	// Compute as float64
	gFloat, _ := new(big.Float).SetInt(genesisTarget).Float64()
	cFloat, _ := new(big.Float).SetInt(currentTarget).Float64()
	if cFloat == 0 {
		return 0
	}
	return gFloat / cFloat
}

// txToJSON converts a Transaction to a JSON-serializable map.
func txToJSON(tx *primitives.Transaction) map[string]interface{} {
	txid := tx.TxID()

	inputs := make([]interface{}, len(tx.Inputs))
	for i, in := range tx.Inputs {
		inp := map[string]interface{}{
			"txid":     hex.EncodeToString(in.PreviousOutput.TxID[:]),
			"vout":     in.PreviousOutput.Index,
			"scriptsig": hex.EncodeToString(in.ScriptSig),
			"sequence": in.Sequence,
		}
		if tx.IsCoinbase() && i == 0 {
			inp["coinbase"] = hex.EncodeToString(in.ScriptSig)
			delete(inp, "scriptsig")
		}
		inputs[i] = inp
	}

	outputs := make([]interface{}, len(tx.Outputs))
	for i, out := range tx.Outputs {
		outputs[i] = map[string]interface{}{
			"value":        float64(out.Value) / 1e8,
			"n":            i,
			"scriptpubkey": hex.EncodeToString(out.ScriptPubKey),
		}
	}

	return map[string]interface{}{
		"txid":     hex.EncodeToString(txid[:]),
		"version":  tx.Version,
		"vin":      inputs,
		"vout":     outputs,
		"locktime": tx.LockTime,
		"size":     len(tx.Serialize()),
	}
}

// parseHash decodes a 32-byte hash from a hex string parameter.
func parseHash(param interface{}) ([32]byte, error) {
	s, ok := param.(string)
	if !ok {
		return [32]byte{}, fmt.Errorf("expected string, got %T", param)
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return [32]byte{}, fmt.Errorf("invalid hex: %w", err)
	}
	if len(b) != 32 {
		return [32]byte{}, fmt.Errorf("expected 32-byte hash, got %d bytes", len(b))
	}
	var h [32]byte
	copy(h[:], b)
	return h, nil
}

// toUint64 converts an interface{} to uint64.
func toUint64(v interface{}) (uint64, error) {
	switch n := v.(type) {
	case float64:
		return uint64(n), nil
	case int:
		return uint64(n), nil
	case int64:
		return uint64(n), nil
	case uint64:
		return n, nil
	case string:
		var u uint64
		if _, err := fmt.Sscanf(n, "%d", &u); err != nil {
			return 0, err
		}
		return u, nil
	default:
		return 0, fmt.Errorf("cannot convert %T to uint64", v)
	}
}

// toInt converts an interface{} to int.
func toInt(v interface{}) (int, error) {
	n, err := toUint64(v)
	return int(n), err
}

// toBool converts an interface{} to bool.
func toBool(v interface{}) (bool, error) {
	switch b := v.(type) {
	case bool:
		return b, nil
	case float64:
		return b != 0, nil
	case int:
		return b != 0, nil
	default:
		return false, fmt.Errorf("cannot convert %T to bool", v)
	}
}
