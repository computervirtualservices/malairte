package mining

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/computervirtualservices/malairte/internal/chain"
	"github.com/computervirtualservices/malairte/internal/consensus"
	"github.com/computervirtualservices/malairte/internal/crypto"
	"github.com/computervirtualservices/malairte/internal/mempool"
	"github.com/computervirtualservices/malairte/internal/network"
	"github.com/computervirtualservices/malairte/internal/primitives"
)

// CpuMiner continuously mines new blocks using the CPU and submits them to the blockchain.
// It supports multiple parallel mining threads, each searching a different nonce space.
// When gpu is true and an OpenCL device is available, a GPU worker runs alongside the
// CPU threads; otherwise the flag is a no-op and mining stays CPU-only.
type CpuMiner struct {
	bc          *chain.Blockchain
	pool        *mempool.TxPool
	coinbaseKey []byte // 32-byte secp256k1 private key for mining rewards
	peerSrv     *network.PeerServer
	threads     int
	gpu         bool
	running     atomic.Bool
	stopCh      chan struct{}
	stopOnce    sync.Once
	// totalHashes counts all hashes attempted across all threads since Start().
	totalHashes atomic.Int64
	// HashRate is the current total hash rate in hashes per second across all threads.
	HashRate atomic.Int64
}

// SetGPU enables or disables the GPU mining worker. Must be called before Start().
func (m *CpuMiner) SetGPU(enabled bool) {
	m.gpu = enabled
}

// NewCpuMiner creates a new CPU miner.
// coinbaseKey is the 32-byte private key whose address receives mining rewards.
// threads is the number of parallel mining goroutines (1 = single-threaded).
// peerSrv may be nil if P2P is not running.
func NewCpuMiner(bc *chain.Blockchain, pool *mempool.TxPool, coinbaseKey []byte, threads int, peerSrv *network.PeerServer) *CpuMiner {
	if threads < 1 {
		threads = 1
	}
	return &CpuMiner{
		bc:          bc,
		pool:        pool,
		coinbaseKey: coinbaseKey,
		peerSrv:     peerSrv,
		threads:     threads,
		stopCh:      make(chan struct{}),
	}
}

// Start launches the mining goroutines. No-op if the miner is already running.
func (m *CpuMiner) Start() {
	if m.running.Swap(true) {
		return // already running
	}
	m.stopCh = make(chan struct{})
	m.stopOnce = sync.Once{}
	m.totalHashes.Store(0)
	m.HashRate.Store(0)
	log.Printf("[miner] starting %d mining thread(s)", m.threads)
	for i := range m.threads {
		go m.mineLoop(i)
	}
	if m.gpu {
		go m.gpuLoop()
	}
	go m.hashrateLoop()
}

// hashrateLoop samples totalHashes every second to compute a rolling hashrate.
func (m *CpuMiner) hashrateLoop() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var prev int64
	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			cur := m.totalHashes.Load()
			m.HashRate.Store(cur - prev)
			prev = cur
		}
	}
}

// Stop gracefully stops the mining goroutine. Safe to call multiple times.
func (m *CpuMiner) Stop() {
	if !m.running.Swap(false) {
		return // already stopped
	}
	m.stopOnce.Do(func() {
		close(m.stopCh)
	})
}

// IsRunning returns true if the miner is currently active.
func (m *CpuMiner) IsRunning() bool {
	return m.running.Load()
}

// mineLoop is the mining goroutine for a single thread.
// threadID offsets the extraNonce so threads search non-overlapping coinbase spaces.
func (m *CpuMiner) mineLoop(threadID int) {
	log.Printf("[miner] thread %d started", threadID)
	defer log.Printf("[miner] thread %d stopped", threadID)

	// Derive coinbase address from the mining key
	pubKey, err := crypto.PubKeyFromPrivKey(m.coinbaseKey)
	if err != nil {
		log.Printf("[miner] thread %d: failed to derive public key: %v", threadID, err)
		m.running.Store(false)
		return
	}
	pubKeyHash := crypto.Hash160(pubKey)
	coinbaseScript := primitives.P2PKHScript(pubKeyHash)

	// Each thread starts at a unique extraNonce offset so they search different merkle roots.
	extraNonce := uint64(threadID)
	for {
		select {
		case <-m.stopCh:
			return
		default:
		}

		// Build block template
		tmpl, err := NewBlockTemplate(m.bc, m.pool, coinbaseScript, extraNonce)
		if err != nil {
			log.Printf("[miner] thread %d: failed to build block template: %v", threadID, err)
			select {
			case <-m.stopCh:
				return
			case <-time.After(time.Second):
			}
			continue
		}

		// Create a cancellable context for this mining attempt
		ctx, cancel := context.WithCancel(context.Background())

		// Cancel context when stop is requested
		go func() {
			select {
			case <-m.stopCh:
				cancel()
			case <-ctx.Done():
			}
		}()

		found := consensus.MineBlock(ctx, &tmpl.Header, nil)
		m.totalHashes.Add(int64(tmpl.Header.Nonce) + 1)

		cancel()

		if !found {
			// Step by thread count so threads stay in different nonce spaces
			extraNonce += uint64(m.threads)
			continue
		}

		// We found a valid nonce — assemble the block
		block := &primitives.Block{
			Header: tmpl.Header,
			Txs:    tmpl.Txs,
		}

		blockHash := block.Header.Hash()
		log.Printf("[miner] thread %d found block height=%d hash=%x nonce=%d",
			threadID, block.Header.Height, blockHash, block.Header.Nonce)

		// Submit the block to the chain
		if err := m.bc.ProcessBlock(block); err != nil {
			log.Printf("[miner] thread %d: ProcessBlock failed: %v", threadID, err)
			select {
			case <-m.stopCh:
				return
			case <-time.After(time.Second):
			}
		} else {
			m.pool.RemoveBlock(block)
			if m.peerSrv != nil {
				m.peerSrv.BroadcastBlock(block)
			}
			log.Printf("[miner] block %x accepted at height %d", blockHash, block.Header.Height)
		}

		extraNonce += uint64(m.threads)
	}
}

// CoinbaseAddress returns the miner's reward address as a hex-encoded public key hash.
// Used for display purposes.
func (m *CpuMiner) CoinbaseAddress() (string, error) {
	pubKey, err := crypto.PubKeyFromPrivKey(m.coinbaseKey)
	if err != nil {
		return "", fmt.Errorf("derive public key: %w", err)
	}
	return hex.EncodeToString(pubKey), nil
}
