// Command malairte-node is the Malairt blockchain node daemon.
// It manages the P2P network, blockchain state, UTXO set, mempool, CPU miner,
// and JSON-RPC server.
package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
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

const version = "0.1.0-dev"

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

	// 10. Start RPC server
	if err := rpcSrv.Start(cfg.RPCAddr); err != nil {
		log.Fatalf("Start RPC server on %s: %v", cfg.RPCAddr, err)
	}
	defer rpcSrv.Stop()

	// 11. Optionally start CPU miner
	var miner *mining.CpuMiner
	if cfg.Mine {
		minerKey, err := resolveMinerKey(cfg.MinerKey)
		if err != nil {
			log.Fatalf("Resolve miner key: %v", err)
		}

		// Derive and display the miner's reward address
		pubKey, err := crypto.PubKeyFromPrivKey(minerKey)
		if err != nil {
			log.Fatalf("Derive miner public key: %v", err)
		}
		addr, err := crypto.PubKeyToAddress(pubKey, params.AddressVersion)
		if err != nil {
			log.Fatalf("Derive miner address: %v", err)
		}
		log.Printf("Mining reward address: %s", addr)

		miner = mining.NewCpuMiner(bc, pool, minerKey, cfg.MineThreads, peerSrv)
		miner.SetGPU(cfg.GPU)
		rpcSrv.SetMiner(miner)
		miner.Start()
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
