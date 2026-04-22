// Command malairte-node is the Malairt blockchain node daemon.
// It manages the P2P network, blockchain state, UTXO set, mempool, CPU miner,
// and JSON-RPC server.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/computervirtualservices/malairte/config"
	"github.com/computervirtualservices/malairte/internal/chain"
	"github.com/computervirtualservices/malairte/internal/crypto"
	"github.com/computervirtualservices/malairte/internal/mempool"
	"github.com/computervirtualservices/malairte/internal/mining"
	"github.com/computervirtualservices/malairte/internal/network"
	"github.com/computervirtualservices/malairte/internal/rpc"
	"github.com/computervirtualservices/malairte/internal/storage"
)

const version = "0.2.0"

func main() {
	// 1. Load configuration from flags
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Select chain parameters
	var params *chain.ChainParams
	switch cfg.Network {
	case "mainnet":
		p := chain.MainNetParams
		params = &p
	case "testnet":
		p := chain.TestNetParams
		params = &p
	default:
		log.Fatalf("Unknown network: %s", cfg.Network)
	}

	// Print startup banner
	fmt.Printf("\n")
	fmt.Printf("  Malairted v%s\n", version)
	fmt.Printf("  Network:      %s\n", params.Name)
	fmt.Printf("  Data dir:     %s\n", cfg.DataDir)
	fmt.Printf("  P2P:          %s\n", cfg.P2PAddr)
	fmt.Printf("  RPC:          %s\n", cfg.RPCAddr)
	if cfg.Mine {
		fmt.Printf("  Mine threads: %d\n", cfg.MineThreads)
		if cfg.GPU {
			fmt.Printf("  GPU mining:   enabled\n")
		}
	}
	fmt.Printf("\n")

	// 2. Open BadgerDB
	dbPath := filepath.Join(cfg.DataDir, "chaindata")
	if err := os.MkdirAll(dbPath, 0755); err != nil {
		log.Fatalf("Create data dir %s: %v", dbPath, err)
	}
	db, err := storage.OpenBadger(dbPath)
	if err != nil {
		log.Fatalf("Open database at %s: %v", dbPath, err)
	}
	defer func() {
		log.Println("Closing database...")
		if err := db.Close(); err != nil {
			log.Printf("Error closing database: %v", err)
		}
	}()
	log.Printf("Database opened at %s", dbPath)

	// 4. NewBlockchain — initializes genesis if the database is empty
	bc, err := chain.NewBlockchain(params, db)
	if err != nil {
		log.Fatalf("Initialize blockchain: %v", err)
	}
	log.Printf("Blockchain initialized: height=%d tip=%x", bc.BestHeight(), bc.BestHash())

	// 5. NewTxPool
	pool := mempool.NewTxPool()

	// 6. NewPeerServer
	peerSrv := network.NewPeerServer(bc, pool, params)
	peerSrv.SetMaxPeers(cfg.MaxPeers)

	// 7. Start P2P server
	if err := peerSrv.Start(cfg.P2PAddr); err != nil {
		log.Fatalf("Start P2P server on %s: %v", cfg.P2PAddr, err)
	}
	defer peerSrv.Stop()

	// 8. Connect to seed peers: merge network defaults with any --seeds flag entries
	allSeeds := append(params.SeedPeers, cfg.SeedPeers...)
	if len(allSeeds) > 0 {
		log.Printf("Connecting to %d seed peer(s)...", len(allSeeds))
		peerSrv.ConnectSeeds(allSeeds)
	}

	// 9. Create RPC server (miner is set later if mining is enabled)
	rpcSrv := rpc.NewServer(bc, pool, nil, peerSrv, params)
	if cfg.RPCUser != "" && cfg.RPCPass != "" {
		rpcSrv.SetAuth(cfg.RPCUser, cfg.RPCPass)
		log.Printf("[rpc] HTTP Basic Auth enabled")
	} else if cfg.RPCAddr != "" {
		host, _, _ := net.SplitHostPort(cfg.RPCAddr)
		if host != "127.0.0.1" && host != "::1" && host != "localhost" {
			log.Printf("[rpc] WARNING: non-localhost RPC with no auth — set --rpc-user and --rpc-pass")
		}
	}

	// 10. Start RPC server
	if err := rpcSrv.Start(cfg.RPCAddr); err != nil {
		log.Fatalf("Start RPC server on %s: %v", cfg.RPCAddr, err)
	}
	defer rpcSrv.Stop()

	// 11. Optionally start CPU miner
	var miner *mining.CpuMiner
	if cfg.Mine {
		// Resolve the miner key up-front so we can derive the reward
		// address before anything else — the heartbeat needs both so the
		// explorer can render a per-address sync-progress badge before
		// mining has even started.
		minerKey, err := resolveMinerKey(cfg.MinerKey)
		if err != nil {
			log.Fatalf("Resolve miner key: %v", err)
		}
		pubKey, err := crypto.PubKeyFromPrivKey(minerKey)
		if err != nil {
			log.Fatalf("Derive miner public key: %v", err)
		}
		addr, err := crypto.PubKeyToAddress(pubKey, params.AddressVersion)
		if err != nil {
			log.Fatalf("Derive miner address: %v", err)
		}
		log.Printf("Mining reward address: %s", addr)

		// Late-bound miner + lifecycle flag consumed by the heartbeat
		// goroutine. isMining flips from false → true the moment the CPU
		// miner actually starts; up until then the heartbeat reports
		// "syncing" with the current tip so the explorer can draw a
		// progress bar.
		var minerPtr atomic.Pointer[mining.CpuMiner]
		var isMining atomic.Bool

		var hb *mining.HeartbeatSender
		if cfg.HeartbeatURL != "" {
			hb = mining.NewHeartbeatSender(
				cfg.HeartbeatURL, hex.EncodeToString(pubKey), addr, cfg.HeartbeatWorker,
				func() int64 {
					if m := minerPtr.Load(); m != nil {
						return m.HashRate.Load()
					}
					return 0
				},
			).WithChainStatus(
				func() string {
					if isMining.Load() {
						return "mining"
					}
					return "syncing"
				},
				func() uint64 { return bc.BestHeight() },
				func() int32 { h, _ := peerSrv.BestPeerHeight(); return h },
			)
			// 15s keeps the sync progress bar responsive without flooding
			// the explorer. Small constant across both phases keeps the
			// lifecycle code simple.
			hb.SetInterval(15 * time.Second)
			hb.Start()
			defer hb.Stop()
		}

		// Before touching the miner, make sure we are building on top of the
		// canonical chain rather than mining an orphan fork from genesis.
		// Without this gate, a freshly-installed node (or any node that fell
		// behind while offline) would extend its own chain until it happened
		// to catch up — and every block mined in between would be orphaned
		// once peers advertised their longer chain.
		if cfg.SyncBeforeMine && cfg.SyncWaitTimeout > 0 {
			log.Printf("Waiting up to %s for initial chain sync before mining (tip=%d)...",
				cfg.SyncWaitTimeout, bc.BestHeight())
			ctx, cancel := context.WithTimeout(context.Background(), cfg.SyncWaitTimeout)
			err := peerSrv.WaitForInitialSync(ctx)
			cancel()
			switch {
			case err == nil:
				// Synced — proceed to mining.
			case errors.Is(err, context.DeadlineExceeded):
				log.Printf("WARNING: initial sync did not complete within %s; "+
					"starting miner anyway at tip=%d — blocks may be orphaned if "+
					"the network advances past us",
					cfg.SyncWaitTimeout, bc.BestHeight())
			default:
				log.Fatalf("Wait for initial sync: %v", err)
			}
		}

		miner = mining.NewCpuMiner(bc, pool, minerKey, cfg.MineThreads, peerSrv)
		miner.SetGPU(cfg.GPU)
		rpcSrv.SetMiner(miner)
		miner.Start()
		minerPtr.Store(miner)
		isMining.Store(true)
		defer miner.Stop()
		if cfg.GPU {
			log.Printf("Miner started: %d CPU thread(s) + GPU (if OpenCL device available)", cfg.MineThreads)
		} else {
			log.Printf("CPU miner started with %d thread(s)", cfg.MineThreads)
		}

		// Optional auto-payout sweep: when --payout-addr is set, periodically
		// sweep the miner's UTXOs to the destination once they reach threshold.
		// Default fee 1000 atoms = 0.00001 MLRT per sweep — keeps the fee market
		// healthy for when block rewards halve and miners rely on fees.
		if cfg.PayoutAddr != "" {
			sweeper, err := mining.NewPayoutSweeper(
				bc, pool, peerSrv, minerKey,
				cfg.PayoutAddr, cfg.PayoutThresholdAtoms,
				/*fee*/ 1_000, /*interval*/ 30*time.Second,
			)
			if err != nil {
				log.Printf("Payout sweeper disabled: %v", err)
			} else {
				sweeper.Start()
				defer sweeper.Stop()
			}
		}
	}

	// 12. Wait for SIGINT/SIGTERM or RPC stop command
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		log.Printf("Received signal %v, shutting down...", sig)
	case <-rpcSrv.StopCh():
		log.Println("Shutdown requested via RPC")
	}

	// 13. Graceful shutdown in reverse order
	if miner != nil {
		log.Println("Stopping miner...")
		miner.Stop()
	}
	log.Println("Stopping RPC server...")
	rpcSrv.Stop()
	log.Println("Stopping P2P server...")
	peerSrv.Stop()
	log.Println("Shutdown complete.")
}

// resolveMinerKey returns the 32-byte mining private key.
// If hexKey is non-empty, it decodes and returns it.
// Otherwise, it generates a new key, prints it, and returns it.
func resolveMinerKey(hexKey string) ([]byte, error) {
	if hexKey != "" {
		key, err := hex.DecodeString(hexKey)
		if err != nil {
			return nil, fmt.Errorf("decode miner key hex: %w", err)
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("miner key must be 32 bytes, got %d", len(key))
		}
		return key, nil
	}

	// Generate a new key
	privKey, pubKey, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate miner key: %w", err)
	}
	fmt.Printf("Generated miner private key: %x\n", privKey)
	fmt.Printf("Miner public key:            %x\n", pubKey)
	fmt.Printf("IMPORTANT: Save the private key above — it receives all mining rewards!\n\n")
	return privKey, nil
}
