package rpc

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"sort"
	"time"

	"github.com/computervirtualservices/malairte/internal/chain"
	"github.com/computervirtualservices/malairte/internal/consensus"
	"github.com/computervirtualservices/malairte/internal/crypto"
	"github.com/computervirtualservices/malairte/internal/mempool"
	"github.com/computervirtualservices/malairte/internal/primitives"
)

// getBlockchainInfo returns summary information about the chain state.
// Response: {chain, blocks, bestblockhash, difficulty, mediantime, chainwork}
func (s *Server) getBlockchainInfo(_ []interface{}) (interface{}, *rpcError) {
	height := s.bc.BestHeight()
	bestHash := s.bc.BestHash()
	header := s.bc.BestHeader()

	difficulty := bitsToFloat64(header.Bits)
	// Cumulative chainwork at the tip — padded to 64 hex chars to match
	// Bitcoin Core's getblockchaininfo convention.
	work := s.bc.ChainWork(bestHash)
	chainworkHex := fmt.Sprintf("%064x", work)

	return map[string]interface{}{
		"chain":         s.params.Name,
		"blocks":        height,
		"bestblockhash": hex.EncodeToString(bestHash[:]),
		"difficulty":    difficulty,
		"mediantime":    header.Timestamp,
		"chainwork":     chainworkHex,
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

	// Resolve each input against the confirmed UTXO set; fall through to the
	// mempool if the UTXO lookup misses (CPFP — child of an unconfirmed
	// parent). Only reject when neither source knows the output.
	utxo := s.bc.UTXOSet()
	var totalIn int64
	for _, in := range tx.Inputs {
		if entry, found := utxo.Get(in.PreviousOutput); found {
			totalIn += entry.Value
			continue
		}
		if out, found := s.pool.GetOutput(in.PreviousOutput); found {
			totalIn += out.Value
			continue
		}
		return nil, newRPCError(-25, fmt.Sprintf(
			"transaction references unknown UTXO %x:%d", in.PreviousOutput.TxID, in.PreviousOutput.Index))
	}
	var totalOut int64
	for _, out := range tx.Outputs {
		totalOut += out.Value
	}
	if totalIn < totalOut {
		return nil, newRPCError(-26, "transaction spends more than it references")
	}
	feeAtoms := totalIn - totalOut

	// Full script validation BEFORE admission so a tx with bogus signatures
	// can't sit in the mempool until a miner wastes work on it. ValidateTx
	// runs the same interpreter (P2PKH + P2WPKH + P2TR key-path + tapscript)
	// the block-level validator uses, against the current chain height +
	// tip-1 for BIP-68 relative-locktime evaluation.
	nextHeight := s.bc.BestHeight() + 1
	if err := chain.ValidateTx(tx, s.bc.UTXOSet(), nextHeight, s.bc.Params()); err != nil {
		return nil, newRPCError(-26, "transaction rejected: "+err.Error())
	}

	if err := s.pool.Add(tx, feeAtoms); err != nil {
		return nil, newRPCError(-26, "transaction rejected: "+err.Error())
	}

	// Broadcast to peers if P2P is running
	if s.peerSrv != nil {
		s.peerSrv.BroadcastTx(tx)
	}

	txid := tx.TxID()
	return hex.EncodeToString(txid[:]), nil
}

// getMempoolInfo returns statistics about the memory pool, including the
// feerate distribution a smart-fee estimator can use, plus flags advertising
// policy features the node enforces (full-RBF, package relay).
func (s *Server) getMempoolInfo(_ []interface{}) (interface{}, *rpcError) {
	// Collect feerates via FeeOf per-entry. Cheap: mempool is normally
	// small enough that one pass is fine.
	all := s.pool.GetAll()
	feerates := make([]int64, 0, len(all))
	var totalFee int64
	var minFR, maxFR int64 = 0, 0
	for _, tx := range all {
		fee, fr, ok := s.pool.FeeOf(tx.TxID())
		if !ok {
			continue
		}
		feerates = append(feerates, fr)
		totalFee += fee
		if len(feerates) == 1 || fr < minFR {
			minFR = fr
		}
		if fr > maxFR {
			maxFR = fr
		}
	}
	var meanFR int64
	if len(feerates) > 0 {
		meanFR = totalFee / int64(len(feerates))
	}

	return map[string]interface{}{
		"size":              s.pool.Count(),
		"bytes":             s.pool.Size(),
		"usage":             s.pool.Size(),
		"totalfee":          totalFee,
		"minfeerate":        minFR,
		"maxfeerate":        maxFR,
		"meanfeerate":       meanFR,
		"minrelaytxfee":     mempool.MinRelayFeeAtomsPerVByte,
		"fullrbf":           true,
		"packagerelay":      true,
	}, nil
}

// getCFHeaders returns a batch of BIP-157 filter headers ending at stopHash.
// Light clients replay the filter-header chain locally to verify a large
// range of filters against a single trusted tip; they pull the header chain
// in ~2000-block batches via this RPC.
//
// Params: [startHeight uint, stopHash hex, filterType string = "basic"]
// Response: {filter_type, stop_hash, previous_header, headers: [hex…]}
func (s *Server) getCFHeaders(params []interface{}) (interface{}, *rpcError) {
	if len(params) < 2 {
		return nil, newRPCError(errCodeInvalidParams, "getcfheaders: need startHeight, stopHash")
	}
	startHeight, err := toUint64(params[0])
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, "startHeight: "+err.Error())
	}
	stopHashStr, ok := params[1].(string)
	if !ok {
		return nil, newRPCError(errCodeInvalidParams, "stopHash must be string")
	}
	stopHashBytes, err := hex.DecodeString(stopHashStr)
	if err != nil || len(stopHashBytes) != 32 {
		return nil, newRPCError(errCodeInvalidParams, "bad stopHash")
	}
	var stopHash [32]byte
	copy(stopHash[:], stopHashBytes)

	// Resolve stopHash → height, then walk the canonical chain from
	// startHeight up to that height.
	stopHeader, err := s.bc.GetBlockHeader(stopHash)
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, "unknown stopHash: "+err.Error())
	}
	if startHeight > stopHeader.Height {
		return nil, newRPCError(errCodeInvalidParams, "startHeight > stop height")
	}
	// Cap at 2000 headers per call to match BIP-157.
	const maxBatch = 2000
	if stopHeader.Height-startHeight+1 > maxBatch {
		return nil, newRPCError(errCodeInvalidParams, fmt.Sprintf("batch limit %d exceeded", maxBatch))
	}

	// previous_header is the filter header of the block at (startHeight-1).
	var prevHeader [32]byte
	if startHeight > 0 {
		phHash, err := s.bc.GetBlockHashAtHeight(startHeight - 1)
		if err != nil {
			return nil, newRPCError(errCodeInternal, "walk prev: "+err.Error())
		}
		if ph, err := s.bc.GetFilterHeader(phHash); err == nil {
			prevHeader = ph
		}
	}

	headers := make([]string, 0, stopHeader.Height-startHeight+1)
	for h := startHeight; h <= stopHeader.Height; h++ {
		blockHash, err := s.bc.GetBlockHashAtHeight(h)
		if err != nil {
			return nil, newRPCError(errCodeInternal, fmt.Sprintf("hash at %d: %v", h, err))
		}
		fh, err := s.bc.GetFilterHeader(blockHash)
		if err != nil {
			// Older block ingested before filter persistence — no header.
			headers = append(headers, "")
			continue
		}
		headers = append(headers, hex.EncodeToString(fh[:]))
	}
	return map[string]interface{}{
		"filter_type":     "basic",
		"stop_hash":       stopHashStr,
		"previous_header": hex.EncodeToString(prevHeader[:]),
		"headers":         headers,
	}, nil
}

// getCFCheckpt returns every 1000th filter header up to stopHash, so light
// clients can anchor their filter-header chain at regular checkpoints and
// verify long runs by filling gaps between checkpoints via getcfheaders.
//
// Params: [stopHash hex, filterType string = "basic"]
// Response: {filter_type, stop_hash, filter_headers: [hex…]}  // height 1000, 2000, …
func (s *Server) getCFCheckpt(params []interface{}) (interface{}, *rpcError) {
	if len(params) < 1 {
		return nil, newRPCError(errCodeInvalidParams, "getcfcheckpt: need stopHash")
	}
	stopHashStr, ok := params[0].(string)
	if !ok {
		return nil, newRPCError(errCodeInvalidParams, "stopHash must be string")
	}
	stopHashBytes, err := hex.DecodeString(stopHashStr)
	if err != nil || len(stopHashBytes) != 32 {
		return nil, newRPCError(errCodeInvalidParams, "bad stopHash")
	}
	var stopHash [32]byte
	copy(stopHash[:], stopHashBytes)
	stopHeader, err := s.bc.GetBlockHeader(stopHash)
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, "unknown stopHash: "+err.Error())
	}

	const interval uint64 = 1000
	last := stopHeader.Height
	checkpts := make([]string, 0, last/interval+1)
	for h := interval; h <= last; h += interval {
		blockHash, err := s.bc.GetBlockHashAtHeight(h)
		if err != nil {
			continue
		}
		fh, err := s.bc.GetFilterHeader(blockHash)
		if err != nil {
			checkpts = append(checkpts, "")
			continue
		}
		checkpts = append(checkpts, hex.EncodeToString(fh[:]))
	}
	return map[string]interface{}{
		"filter_type":    "basic",
		"stop_hash":      stopHashStr,
		"filter_headers": checkpts,
	}, nil
}

// dumpSnapshot returns a hex-encoded UTXO-set snapshot at the current tip,
// plus its SHA256 hash. Operators capture this at a well-known height and
// commit the hash into ChainParams.AssumeUTXOHash; new nodes then load the
// snapshot instead of replaying every block.
//
// Response: { height, blockhash, hash, snapshot_hex, utxo_count }
func (s *Server) dumpSnapshot(_ []interface{}) (interface{}, *rpcError) {
	snap, err := chain.BuildSnapshot(s.bc)
	if err != nil {
		return nil, newRPCError(errCodeInternal, "build snapshot: "+err.Error())
	}
	body := snap.Serialize()
	h := snap.Hash()
	return map[string]interface{}{
		"height":       snap.Height,
		"blockhash":    hex.EncodeToString(snap.BlockHash[:]),
		"hash":         hex.EncodeToString(h[:]),
		"snapshot_hex": hex.EncodeToString(body),
		"utxo_count":   len(snap.UTXOs),
	}, nil
}

// loadSnapshot parses a hex-encoded snapshot and writes its UTXOs into the
// chain's database. Intended to be called ONCE on a fresh node before any
// blocks are processed. A future version will verify the snapshot hash
// against ChainParams.AssumeUTXOHash; today this is a trust-the-operator
// operation, suitable for testing and for genesis snapshot creation.
//
// Params: [snapshot_hex string]
// Response: { loaded: <n utxos>, height: <u64>, hash: "<hex>" }
func (s *Server) loadSnapshot(params []interface{}) (interface{}, *rpcError) {
	if len(params) < 1 {
		return nil, newRPCError(errCodeInvalidParams, "missing snapshot hex")
	}
	hexStr, ok := params[0].(string)
	if !ok {
		return nil, newRPCError(errCodeInvalidParams, "snapshot must be a hex string")
	}
	data, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, "bad hex: "+err.Error())
	}
	snap, err := chain.DeserializeSnapshot(data)
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, "parse snapshot: "+err.Error())
	}
	n, err := chain.LoadSnapshot(s.bc.DB(), snap)
	if err != nil {
		return nil, newRPCError(errCodeInternal, "write snapshot: "+err.Error())
	}
	h := snap.Hash()
	return map[string]interface{}{
		"loaded": n,
		"height": snap.Height,
		"hash":   hex.EncodeToString(h[:]),
	}, nil
}

// getBlockFilter returns the BIP-158 compact block filter (output-only
// variant) for the given block. Light clients use this to scan a long
// history of blocks for outputs paying their addresses without downloading
// every full block — they fetch one filter per block (tiny) and only fetch
// the full block when the filter says their address might be in it.
//
// Params: [blockHashHex string, filterType string = "basic"]
// Response: { filter: "<hex>", header: "<hex>", blockhash: "<hex>" }
func (s *Server) getBlockFilter(params []interface{}) (interface{}, *rpcError) {
	if len(params) < 1 {
		return nil, newRPCError(errCodeInvalidParams, "missing block hash")
	}
	hashStr, ok := params[0].(string)
	if !ok {
		return nil, newRPCError(errCodeInvalidParams, "block hash must be a string")
	}
	hashBytes, err := hex.DecodeString(hashStr)
	if err != nil || len(hashBytes) != 32 {
		return nil, newRPCError(errCodeInvalidParams, "invalid block hash")
	}
	var hash [32]byte
	copy(hash[:], hashBytes)

	// Only the basic filter type is supported for now.
	if len(params) >= 2 {
		if t, _ := params[1].(string); t != "" && t != "basic" {
			return nil, newRPCError(errCodeInvalidParams, "only 'basic' filter type supported")
		}
	}

	// Fast path: the filter was built + persisted at ingestion. Returns
	// the true BIP-158 basic variant including spent-input scripts, plus
	// the BIP-157 filter header so the client can verify it.
	if stored, err := s.bc.GetBlockFilter(hash); err == nil && len(stored) > 0 {
		resp := map[string]interface{}{
			"filter":    hex.EncodeToString(stored),
			"blockhash": hashStr,
		}
		if header, err := s.bc.GetFilterHeader(hash); err == nil {
			resp["header"] = hex.EncodeToString(header[:])
		}
		return resp, nil
	}

	// Fallback: rebuild on demand. Only output scripts — spent-input
	// scripts can't be resolved after Apply, so this is a weaker filter.
	// Callers of old blocks (pre-filter-persistence) get this subset.
	block, err := s.bc.GetBlock(hash)
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, "block not found: "+err.Error())
	}
	filter := chain.BuildBlockFilter(block, nil)
	return map[string]interface{}{
		"filter":    hex.EncodeToString(filter),
		"blockhash": hashStr,
	}, nil
}

// estimateSmartFee returns a feerate (atoms/vbyte) a sender should attach to
// get confirmed within confTarget blocks. Uses a percentile-of-current-mempool
// heuristic: the confTarget-th percentile of feerates currently in the pool
// is the floor that likely mines before then. Returns MinRelayFeeAtomsPerVByte
// when the mempool is empty.
//
// Params: [confTarget int] (blocks, default 6; accepted range 1..1008)
func (s *Server) estimateSmartFee(params []interface{}) (interface{}, *rpcError) {
	confTarget := 6
	if len(params) >= 1 {
		if n, err := toUint64(params[0]); err == nil && n >= 1 && n <= 1008 {
			confTarget = int(n)
		}
	}

	all := s.pool.GetAll()
	if len(all) == 0 {
		return map[string]interface{}{
			"feerate": mempool.MinRelayFeeAtomsPerVByte,
			"blocks":  confTarget,
		}, nil
	}

	feerates := make([]int64, 0, len(all))
	for _, tx := range all {
		if _, fr, ok := s.pool.FeeOf(tx.TxID()); ok {
			feerates = append(feerates, fr)
		}
	}
	// Sort ascending so the top percentile is at the end.
	sort.Slice(feerates, func(i, j int) bool { return feerates[i] < feerates[j] })

	// Map confTarget → pool percentile. A confTarget of 1 block needs the
	// top-feerate slice; 6 blocks tolerates much lower. Formula is a rough
	// piecewise fit: target=1 → 95th pct, target=6 → 50th, target=144 → 10th.
	var pct float64
	switch {
	case confTarget <= 1:
		pct = 0.95
	case confTarget <= 3:
		pct = 0.80
	case confTarget <= 6:
		pct = 0.50
	case confTarget <= 24:
		pct = 0.25
	default:
		pct = 0.10
	}
	idx := int(float64(len(feerates)-1) * pct)
	estimated := feerates[idx]
	if estimated < mempool.MinRelayFeeAtomsPerVByte {
		estimated = mempool.MinRelayFeeAtomsPerVByte
	}
	return map[string]interface{}{
		"feerate": estimated,
		"blocks":  confTarget,
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

// getBlockTemplate returns a block template for external miners.
//
// In addition to Bitcoin Core's standard fields, we expose two that the
// Malairt consensus rules require:
//
//   default_witness_commitment — the hex-encoded 38-byte OP_RETURN script
//     the miner must append as the LAST output of the coinbase. Our
//     ValidateBlock rejects blocks without it. Computed as
//     OP_RETURN 0x24 0xaa21a9ed || Hash256(witnessMerkleRoot || 0^32).
//     The value passed to Hash256 uses the witness-merkle-root over THIS
//     template's transactions, treating the coinbase's WTxID as zeros.
//
//   mintime — the minimum timestamp a new block may carry, computed as
//     MedianTimePast(last 11 parents) + 1. Miners that pick a lower
//     timestamp will have blocks rejected.
//
// Per-tx fee is now the actual mempool-tracked fee (previously hardcoded 0,
// which meant miners couldn't compute their reward correctly).
func (s *Server) getBlockTemplate(params []interface{}) (interface{}, *rpcError) {
	height := s.bc.BestHeight() + 1
	bestHash := s.bc.BestHash()
	bits, err := s.bc.CalcNextBits()
	if err != nil {
		return nil, newRPCError(errCodeInternal, "calc bits: "+err.Error())
	}

	subsidy := chain.CalcBlockSubsidy(height, s.params)
	txs := s.pool.GetSorted(2000)

	// Build tx results with actual fees from the mempool's fee tracker.
	// Sum fees so we can include subsidy+fees in coinbasevalue.
	var totalFees int64
	txResults := make([]interface{}, 0, len(txs))
	for _, tx := range txs {
		txid := tx.TxID()
		fee, _, _ := s.pool.FeeOf(txid)
		totalFees += fee
		txResults = append(txResults, map[string]interface{}{
			"data":    hex.EncodeToString(tx.Serialize()),
			"txid":    hex.EncodeToString(txid[:]),
			"fee":     fee,
			"sigops":  0,
			"depends": []interface{}{},
		})
	}

	// Compute the witness-merkle-root over the template's txs. The miner
	// will prepend a coinbase of its own choosing, so we reconstruct the
	// full tx list with a placeholder coinbase (WTxID = zeros by BIP-141)
	// before computing the commitment.
	// The witness commitment's Hash256 input is: witnessRoot || reserved(32).
	// We don't know the coinbase txid yet — but per BIP-141 the coinbase's
	// WTxID is defined as 0x0…0, so it contributes zeros no matter what
	// coinbase the miner picks.
	placeholderCoinbase := &primitives.Transaction{
		Version: 1,
		Inputs: []primitives.TxInput{{
			PreviousOutput: primitives.OutPoint{TxID: [32]byte{}, Index: 0xFFFFFFFF},
			ScriptSig:      []byte{},
			Sequence:       0xFFFFFFFF,
		}},
		Outputs: []primitives.TxOutput{{Value: subsidy + totalFees, ScriptPubKey: []byte{0x51}}},
	}
	allTxs := append([]*primitives.Transaction{placeholderCoinbase}, txs...)
	commitment := primitives.ComputeWitnessCommitment(allTxs)
	commitmentScript := primitives.BuildWitnessCommitmentScript(commitment)

	// mintime = MTP + 1. BestHeader is the tip; MTP is median of tip +
	// previous 10. For the first few blocks we just pass a timestamp
	// slightly above the tip as a safe default.
	tipHeader := s.bc.BestHeader()
	mintime := tipHeader.Timestamp + 1

	target := consensus.CompactToBig(bits)
	targetHex := fmt.Sprintf("%064x", target)

	return map[string]interface{}{
		"version":                     1,
		"previousblockhash":           hex.EncodeToString(bestHash[:]),
		"transactions":                txResults,
		"coinbasevalue":               subsidy + totalFees,
		"target":                      targetHex,
		"bits":                        fmt.Sprintf("%08x", bits),
		"height":                      height,
		"curtime":                     time.Now().Unix(),
		"mintime":                     mintime,
		"mutable":                     []string{"time", "transactions", "prevblock"},
		"noncerange":                  "00000000ffffffffffffffff",
		"default_witness_commitment":  hex.EncodeToString(commitmentScript),
		"sizelimit":                   s.params.MaxBlockWeight / 4,
		"weightlimit":                 s.params.MaxBlockWeight,
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
		"networkhashps":    s.computeNetworkHashps(120),
		"pooledtx":         s.pool.Count(),
		"chain":            s.params.Name,
		"generate":         minerRunning,
	}, nil
}

// getNetworkHashps returns the estimated network hashrate in hashes per second,
// computed from the last `blocks` headers (default 120). Bitcoin-compatible.
// Params: [blocks int = 120, height int = -1 (tip)]
func (s *Server) getNetworkHashps(params []interface{}) (interface{}, *rpcError) {
	blocks := 120
	if len(params) >= 1 {
		if n, err := toUint64(params[0]); err == nil && n > 0 {
			blocks = int(n)
		}
	}
	return s.computeNetworkHashps(blocks), nil
}

// computeNetworkHashps estimates the network hashrate from the last `blocks`
// headers on the current chain. Sums work (2^256 / (target+1)) per block and
// divides by the observed time span between the first and last headers in the
// window. Returns 0 if the chain is too short or timestamps are degenerate.
func (s *Server) computeNetworkHashps(blocks int) float64 {
	tip := s.bc.BestHeight()
	if tip == 0 {
		return 0
	}
	if blocks <= 0 {
		blocks = 120
	}
	if uint64(blocks) > tip {
		blocks = int(tip)
	}

	startHeight := tip - uint64(blocks)
	startHash, err := s.bc.GetBlockHashAtHeight(startHeight)
	if err != nil {
		return 0
	}
	startHeader, err := s.bc.GetBlockHeader(startHash)
	if err != nil {
		return 0
	}
	tipHash, err := s.bc.GetBlockHashAtHeight(tip)
	if err != nil {
		return 0
	}
	tipHeader, err := s.bc.GetBlockHeader(tipHash)
	if err != nil {
		return 0
	}

	timeSpan := tipHeader.Timestamp - startHeader.Timestamp
	if timeSpan <= 0 {
		return 0
	}

	max256 := new(big.Int).Lsh(big.NewInt(1), 256)
	totalWork := new(big.Int)
	one := big.NewInt(1)
	for h := startHeight + 1; h <= tip; h++ {
		hash, err := s.bc.GetBlockHashAtHeight(h)
		if err != nil {
			continue
		}
		hdr, err := s.bc.GetBlockHeader(hash)
		if err != nil {
			continue
		}
		target := consensus.CompactToBig(hdr.Bits)
		if target.Sign() <= 0 {
			continue
		}
		work := new(big.Int).Div(max256, new(big.Int).Add(target, one))
		totalWork.Add(totalWork, work)
	}

	workFloat, _ := new(big.Float).SetInt(totalWork).Float64()
	return workFloat / float64(timeSpan)
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
