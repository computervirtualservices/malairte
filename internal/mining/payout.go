package mining

import (
	"errors"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/computervirtualservices/malairte/internal/chain"
	"github.com/computervirtualservices/malairte/internal/crypto"
	"github.com/computervirtualservices/malairte/internal/mempool"
	"github.com/computervirtualservices/malairte/internal/network"
	"github.com/computervirtualservices/malairte/internal/primitives"
)

// PayoutSweeper periodically sweeps mined coins from a miner address into a
// configured destination (cold storage / exchange).
//
// Architecture:
//   - The miner's private key already lives in this process (passed in as
//     `coinbaseKey` to the CpuMiner). The sweeper reuses it — no key transmission.
//   - Every checkInterval, the sweeper sums the unspent value of the miner's
//     P2PKH outputs. When that sum reaches threshold, it builds + signs +
//     broadcasts a single sweep transaction consuming all UTXOs in one tx.
//   - The fee is fixed (feeAtoms) and subtracted from the swept amount.
//   - Re-checks every cycle, so multiple sweeps happen naturally as more rewards
//     accumulate above the threshold.
type PayoutSweeper struct {
	bc          *chain.Blockchain
	pool        *mempool.TxPool
	peerSrv     *network.PeerServer
	minerKey    []byte // 32-byte secp256k1 private key (same as the CPU miner uses)
	destAddr    string // base58check destination address
	threshold   int64  // sweep when balance ≥ threshold (atoms)
	feeAtoms    int64  // flat fee subtracted from each sweep
	interval    time.Duration

	running  atomic.Bool
	stopCh   chan struct{}
	stopOnce sync.Once
}

// NewPayoutSweeper constructs a sweeper. minerKey is the same private key the
// CPU/GPU miner uses to receive block rewards. destAddr must be a valid
// base58check P2PKH address. threshold and fee are in atoms (1 MLRT = 1e8 atoms).
func NewPayoutSweeper(
	bc *chain.Blockchain,
	pool *mempool.TxPool,
	peerSrv *network.PeerServer,
	minerKey []byte,
	destAddr string,
	threshold int64,
	feeAtoms int64,
	interval time.Duration,
) (*PayoutSweeper, error) {
	if len(minerKey) != 32 {
		return nil, errors.New("payout: minerKey must be 32 bytes")
	}
	if destAddr == "" {
		return nil, errors.New("payout: destAddr must be set")
	}
	if threshold <= 0 {
		return nil, errors.New("payout: threshold must be positive")
	}
	// Validate destination address up front so we fail fast on bad config.
	if _, err := decodeP2PKHAddress(destAddr); err != nil {
		return nil, fmt.Errorf("payout: invalid destAddr: %w", err)
	}
	if interval <= 0 {
		interval = 30 * time.Second
	}
	if feeAtoms < 0 {
		feeAtoms = 0
	}
	return &PayoutSweeper{
		bc:        bc,
		pool:      pool,
		peerSrv:   peerSrv,
		minerKey:  minerKey,
		destAddr:  destAddr,
		threshold: threshold,
		feeAtoms:  feeAtoms,
		interval:  interval,
		stopCh:    make(chan struct{}),
	}, nil
}

// Start launches the periodic sweep loop. No-op if already running.
func (s *PayoutSweeper) Start() {
	if s.running.Swap(true) {
		return
	}
	s.stopCh = make(chan struct{})
	s.stopOnce = sync.Once{}
	log.Printf("[payout] sweeper started: dest=%s threshold=%d atoms (%.2f MLRT) interval=%s",
		s.destAddr, s.threshold, float64(s.threshold)/1e8, s.interval)
	go s.loop()
}

// Stop halts the sweep loop. Safe to call multiple times.
func (s *PayoutSweeper) Stop() {
	if !s.running.Swap(false) {
		return
	}
	s.stopOnce.Do(func() { close(s.stopCh) })
}

func (s *PayoutSweeper) loop() {
	defer log.Printf("[payout] sweeper stopped")
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			if err := s.checkAndSweep(); err != nil {
				log.Printf("[payout] error: %v", err)
			}
		}
	}
}

// checkAndSweep does one threshold check + sweep cycle.
func (s *PayoutSweeper) checkAndSweep() error {
	pubKey, err := crypto.PubKeyFromPrivKey(s.minerKey)
	if err != nil {
		return fmt.Errorf("derive pubkey: %w", err)
	}
	pkh20 := crypto.Hash160(pubKey)

	utxos, err := s.bc.UTXOSet().GetUTXOsByAddress(pkh20)
	if err != nil {
		return fmt.Errorf("get utxos: %w", err)
	}

	var total int64
	for _, u := range utxos {
		total += u.Value
	}
	if total < s.threshold {
		return nil // not enough to sweep
	}

	if total <= s.feeAtoms {
		return fmt.Errorf("balance %d <= fee %d, cannot sweep", total, s.feeAtoms)
	}

	tx, err := s.buildSweepTx(utxos, pubKey)
	if err != nil {
		return fmt.Errorf("build tx: %w", err)
	}

	// The sweep builder subtracts s.feeAtoms from the destination payout, so
	// that flat fee IS the transaction fee (no other surplus inputs-vs-outputs).
	if err := s.pool.Add(tx, s.feeAtoms); err != nil {
		return fmt.Errorf("mempool reject: %w", err)
	}
	if s.peerSrv != nil {
		s.peerSrv.BroadcastTx(tx)
	}

	txid := tx.TxID()
	log.Printf("[payout] swept %.8f MLRT (fee %.8f) → %s  tx=%x",
		float64(total-s.feeAtoms)/1e8, float64(s.feeAtoms)/1e8, s.destAddr, txid)
	return nil
}

// buildSweepTx consumes every utxo and pays (sum - fee - adminFee) to destAddr,
// with a separate adminFee output to the protocol-fee address (consensus rule).
func (s *PayoutSweeper) buildSweepTx(utxos []*chain.UTXO, pubKey []byte) (*primitives.Transaction, error) {
	destPkh, err := decodeP2PKHAddress(s.destAddr)
	if err != nil {
		return nil, err
	}

	var total int64
	inputs := make([]primitives.TxInput, 0, len(utxos))
	for _, u := range utxos {
		inputs = append(inputs, primitives.TxInput{
			PreviousOutput: primitives.OutPoint{TxID: u.TxID, Index: u.Index},
			ScriptSig:      nil, // filled in below
			Sequence:       0xFFFFFFFF,
		})
		total += u.Value
	}

	// Subtract the admin protocol fee if the chain enforces one. Validators
	// reject txs without the admin output, so this isn't optional.
	params := s.bc.Params()
	adminScript := params.AdminScript()
	adminFee := int64(0)
	if adminScript != nil {
		adminFee = params.AdminFeeAtoms
	}

	destValue := total - s.feeAtoms - adminFee
	if destValue <= 0 {
		return nil, fmt.Errorf("balance %d insufficient to cover network fee %d + admin fee %d",
			total, s.feeAtoms, adminFee)
	}

	outputs := []primitives.TxOutput{{
		Value:        destValue,
		ScriptPubKey: primitives.P2PKHScript(destPkh),
	}}
	if adminScript != nil {
		outputs = append(outputs, primitives.TxOutput{
			Value:        adminFee,
			ScriptPubKey: adminScript,
		})
	}

	tx := &primitives.Transaction{
		Version: 1,
		Inputs:  inputs,
		Outputs: outputs,
		LockTime: 0,
	}

	// Sign each input with SIGHASH_ALL using the source scriptPubKey as the subscript.
	srcScript := primitives.P2PKHScript(crypto.Hash160(pubKey))

	chainID := s.bc.Params().Net
	for i := range tx.Inputs {
		sigHash := chain.CalcSigHash(tx, i, srcScript, chainID)
		sig, err := crypto.Sign(s.minerKey, sigHash[:])
		if err != nil {
			return nil, fmt.Errorf("sign input %d: %w", i, err)
		}
		tx.Inputs[i].ScriptSig = chain.BuildP2PKHScriptSig(sig, pubKey)
	}
	return tx, nil
}

// decodeP2PKHAddress returns the 20-byte pubkey hash for a base58check P2PKH address.
func decodeP2PKHAddress(addr string) ([20]byte, error) {
	var out [20]byte
	_, payload, err := crypto.Base58CheckDecode(addr)
	if err != nil {
		return out, fmt.Errorf("base58 decode: %w", err)
	}
	if len(payload) != 20 {
		return out, fmt.Errorf("expected 20-byte hash160, got %d bytes", len(payload))
	}
	copy(out[:], payload)
	return out, nil
}
