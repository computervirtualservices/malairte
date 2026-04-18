//go:build cuda

// gpu_cuda.go implements the real CUDA-backed mining path. It is only
// compiled when the binary is built with `-tags cuda` AND libmlrtgpu.a has
// been built via `cd internal/mining/cuda && make`.
//
// Build and run:
//
//	cd internal/mining/cuda && make
//	cd ../../..
//	CGO_ENABLED=1 go build -tags cuda -o malairte-node ./cmd/malairte-node
//	./malairte-node --mine --gpu --miner-key=<key>
package mining

/*
#cgo CFLAGS: -I${SRCDIR}/cuda
#cgo linux   LDFLAGS: ${SRCDIR}/cuda/libmlrtgpu.a -lcudart_static -lculibos -ldl -lpthread -lrt -lstdc++ -lm
// Windows: link against the MinGW import lib for mlrt_gpu.dll. The DLL itself
// statically embeds the CUDA runtime + MSVC intrinsics so this exe has zero
// external CUDA dependencies — just ship mlrt_gpu.dll alongside malairte-node.exe.
#cgo windows LDFLAGS: ${SRCDIR}/cuda/libmlrtgpu.a

#include <stdint.h>
#include "mlrt_gpu.h"
*/
import "C"

import (
	"context"
	"log"
	"math/big"
	"time"
	"unsafe"

	"github.com/computervirtualservices/malairte/internal/consensus"
	"github.com/computervirtualservices/malairte/internal/crypto"
	"github.com/computervirtualservices/malairte/internal/primitives"
)

// gpuBatchSize is the number of nonces tried per kernel launch.
// 16M nonces at ~2ns/hash on an RTX 5090 = ~33ms per batch, which keeps
// latency low enough to check stopCh often without hurting throughput.
const gpuBatchSize = 16 * 1024 * 1024

func (m *CpuMiner) gpuLoop() {
	log.Printf("[miner/gpu] initializing CUDA device...")
	if rc := C.mlrt_gpu_init(); rc != 0 {
		log.Printf("[miner/gpu] init failed (rc=%d) — falling back to CPU-only", int(rc))
		return
	}
	defer C.mlrt_gpu_shutdown()
	log.Printf("[miner/gpu] worker running")
	defer log.Printf("[miner/gpu] worker stopped")

	pubKey, err := crypto.PubKeyFromPrivKey(m.coinbaseKey)
	if err != nil {
		log.Printf("[miner/gpu] derive public key: %v", err)
		return
	}
	coinbaseScript := primitives.P2PKHScript(crypto.Hash160(pubKey))

	// Start GPU extraNonce high up so it doesn't collide with CPU thread space.
	const gpuExtraNonceBase uint64 = 1 << 32
	extraNonce := gpuExtraNonceBase

	for {
		select {
		case <-m.stopCh:
			return
		default:
		}

		tmpl, err := NewBlockTemplate(m.bc, m.pool, coinbaseScript, extraNonce)
		if err != nil {
			log.Printf("[miner/gpu] build template: %v", err)
			select {
			case <-m.stopCh:
				return
			case <-time.After(time.Second):
			}
			continue
		}

		if m.gpuMineTemplate(tmpl) {
			// block accepted & broadcast; move to next extraNonce
		}
		extraNonce++
	}
}

// gpuMineTemplate searches the given template's nonce space on the GPU.
// Returns true if a block was mined and submitted, false if the nonce space
// was exhausted (caller should try a new template) or the context was cancelled.
func (m *CpuMiner) gpuMineTemplate(tmpl *BlockTemplate) bool {
	headerBytes := tmpl.Header.Serialize()
	if len(headerBytes) != 96 {
		log.Printf("[miner/gpu] unexpected header size %d", len(headerBytes))
		return false
	}

	// Target as 32-byte big-endian.
	target := consensus.CompactToBig(tmpl.Header.Bits)
	targetBytes := make([]byte, 32)
	tb := target.Bytes()
	copy(targetBytes[32-len(tb):], tb)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-m.stopCh:
			cancel()
		case <-ctx.Done():
		}
	}()

	var startNonce uint64 = 0
	for {
		select {
		case <-ctx.Done():
			return false
		default:
		}

		var gotNonce C.uint64_t
		var gotFound C.int
		rc := C.mlrt_gpu_mine(
			(*C.uint8_t)(unsafe.Pointer(&headerBytes[0])),
			(*C.uint8_t)(unsafe.Pointer(&targetBytes[0])),
			C.uint64_t(startNonce),
			C.uint64_t(gpuBatchSize),
			&gotNonce,
			&gotFound,
		)
		if rc != 0 {
			log.Printf("[miner/gpu] kernel error rc=%d", int(rc))
			return false
		}
		m.totalHashes.Add(int64(gpuBatchSize))

		if gotFound != 0 {
			tmpl.Header.Nonce = uint64(gotNonce)
			// Re-verify on CPU before we submit — catches GPU bugs early.
			if !consensus.HashMeetsDifficulty(tmpl.Header.Hash(), tmpl.Header.Bits) {
				log.Printf("[miner/gpu] BUG: kernel reported hit at nonce=%d but CPU says no — dumping state",
					uint64(gotNonce))
				m.dumpBadHit(tmpl.Header, targetBytes)
				return false
			}

			block := &primitives.Block{Header: tmpl.Header, Txs: tmpl.Txs}
			blockHash := block.Header.Hash()
			log.Printf("[miner/gpu] found block height=%d hash=%x nonce=%d",
				block.Header.Height, blockHash, block.Header.Nonce)

			if err := m.bc.ProcessBlock(block); err != nil {
				log.Printf("[miner/gpu] ProcessBlock failed: %v", err)
				return false
			}
			m.pool.RemoveBlock(block)
			if m.peerSrv != nil {
				m.peerSrv.BroadcastBlock(block)
			}
			log.Printf("[miner/gpu] block %x accepted at height %d",
				blockHash, block.Header.Height)
			return true
		}

		// Advance nonce range; wrap means the template is exhausted.
		next := startNonce + gpuBatchSize
		if next < startNonce {
			return false
		}
		startNonce = next
	}
}

// dumpBadHit logs the failing inputs. Helps debug a GPU/CPU hash mismatch.
func (m *CpuMiner) dumpBadHit(h primitives.BlockHeader, target []byte) {
	got := h.Hash()
	log.Printf("[miner/gpu] header:  %x", h.Serialize())
	log.Printf("[miner/gpu] target:  %x", target)
	log.Printf("[miner/gpu] cpu hash:%x", got)
	// Compare as big ints for clarity.
	hi := new(big.Int).SetBytes(got[:])
	ti := new(big.Int).SetBytes(target)
	log.Printf("[miner/gpu] hash>=target: %v", hi.Cmp(ti) > 0)
}
