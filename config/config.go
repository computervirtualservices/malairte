// Package config provides runtime configuration loading for the Malairt node.
package config

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Config holds the full runtime configuration for the node daemon.
type Config struct {
	// DataDir is the path where blockchain data and the database are stored.
	DataDir string
	// Network is either "mainnet" or "testnet".
	Network string
	// RPCAddr is the host:port for the JSON-RPC server (localhost only).
	RPCAddr string
	// P2PAddr is the host:port for the P2P listen socket.
	P2PAddr string
	// Mine enables the CPU miner when true.
	Mine bool
	// MinerKey is a hex-encoded 32-byte secp256k1 private key for mining rewards.
	// If empty, a fresh key is generated at startup and printed to stdout.
	MinerKey string
	// SeedPeers is a list of "host:port" addresses to connect to on startup.
	SeedPeers []string
	// LogLevel controls verbosity: "debug", "info", "warn", "error".
	LogLevel string
	// MaxPeers is the maximum number of simultaneous P2P connections.
	MaxPeers int
	// MaxMempool is the maximum mempool size in megabytes.
	MaxMempool int
	// MineThreads is the number of parallel CPU mining goroutines (default: NumCPU).
	MineThreads int
	// GPU enables the OpenCL GPU miner alongside the CPU miner when true.
	// Falls back silently to CPU-only if no OpenCL device is available.
	GPU bool
	// PayoutAddr is the destination address for the auto-payout sweep.
	// When empty, no sweeping happens. When set, the node periodically checks
	// the miner address's UTXO set and broadcasts a sweep tx whenever the
	// unspent balance reaches PayoutThresholdAtoms.
	PayoutAddr string
	// PayoutThresholdAtoms is the minimum unspent balance (in atoms) that
	// triggers a sweep. Default 100_000_000_000 = 1000 MLRT.
	PayoutThresholdAtoms int64
}

// DefaultConfig returns a Config with sensible production defaults.
func DefaultConfig() *Config {
	return &Config{
		DataDir:    defaultDataDir(),
		Network:    "mainnet",
		RPCAddr:    "127.0.0.1:9332",
		P2PAddr:    "0.0.0.0:9333",
		Mine:       false,
		MinerKey:   "",
		SeedPeers:  []string{},
		LogLevel:   "info",
		MaxPeers:    125,
		MaxMempool:  300, // MB
		MineThreads:          runtime.NumCPU(),
		GPU:                  false,
		PayoutAddr:           "",
		PayoutThresholdAtoms: 100_000_000_000, // 1000 MLRT
	}
}

// LoadConfig parses command-line flags and returns a populated Config.
// Flag values take precedence over defaults.
func LoadConfig() (*Config, error) {
	cfg := DefaultConfig()

	flag.StringVar(&cfg.DataDir, "data-dir", cfg.DataDir,
		"Directory for blockchain data and database")
	flag.StringVar(&cfg.Network, "network", cfg.Network,
		"Network to use: mainnet or testnet")
	flag.StringVar(&cfg.RPCAddr, "rpc-addr", cfg.RPCAddr,
		"JSON-RPC server listen address (must be localhost)")
	flag.StringVar(&cfg.P2PAddr, "p2p-addr", cfg.P2PAddr,
		"P2P listen address")
	flag.BoolVar(&cfg.Mine, "mine", cfg.Mine,
		"Enable CPU miner")
	flag.StringVar(&cfg.MinerKey, "miner-key", cfg.MinerKey,
		"Hex-encoded private key for mining rewards (generated if empty)")
	seeds := flag.String("seeds", "",
		"Comma-separated list of seed peer addresses (host:port)")
	flag.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel,
		"Log verbosity: debug, info, warn, error")
	flag.IntVar(&cfg.MaxPeers, "max-peers", cfg.MaxPeers,
		"Maximum number of simultaneous peer connections")
	flag.IntVar(&cfg.MaxMempool, "max-mempool", cfg.MaxMempool,
		"Maximum mempool size in megabytes")
	flag.IntVar(&cfg.MineThreads, "mine-threads", cfg.MineThreads,
		"Number of parallel CPU mining threads (default: number of logical CPUs)")
	flag.BoolVar(&cfg.GPU, "gpu", cfg.GPU,
		"Enable GPU mining (OpenCL; falls back to CPU-only if no device available)")
	flag.StringVar(&cfg.PayoutAddr, "payout-addr", cfg.PayoutAddr,
		"Optional destination address for auto-payout sweeps. When set, the node "+
			"sweeps mined coins to this address whenever balance >= --payout-threshold")
	flag.Int64Var(&cfg.PayoutThresholdAtoms, "payout-threshold", cfg.PayoutThresholdAtoms,
		"Sweep threshold in atoms (default 100_000_000_000 = 1000 MLRT). "+
			"Ignored when --payout-addr is empty")

	flag.Parse()

	// Parse seed peers
	if *seeds != "" {
		cfg.SeedPeers = strings.Split(*seeds, ",")
		for i, s := range cfg.SeedPeers {
			cfg.SeedPeers[i] = strings.TrimSpace(s)
		}
	}

	// Override RPC and P2P ports for testnet
	if cfg.Network == "testnet" {
		if cfg.RPCAddr == "127.0.0.1:9332" {
			cfg.RPCAddr = "127.0.0.1:19332"
		}
		if cfg.P2PAddr == "0.0.0.0:9333" {
			cfg.P2PAddr = "0.0.0.0:19333"
		}
	}

	// Validate network
	if cfg.Network != "mainnet" && cfg.Network != "testnet" {
		return nil, fmt.Errorf("unknown network %q (use mainnet or testnet)", cfg.Network)
	}

	// Expand the data directory
	cfg.DataDir = expandPath(cfg.DataDir)

	// Append network subdirectory
	cfg.DataDir = filepath.Join(cfg.DataDir, cfg.Network)

	return cfg, nil
}

// defaultDataDir returns the platform-appropriate default data directory.
func defaultDataDir() string {
	switch runtime.GOOS {
	case "windows":
		appdata := os.Getenv("APPDATA")
		if appdata != "" {
			return filepath.Join(appdata, "Malairted")
		}
		return filepath.Join(os.Getenv("USERPROFILE"), ".malairted")
	case "darwin":
		home, _ := os.UserHomeDir()
		return filepath.Join(home, "Library", "Application Support", "Malairted")
	default: // Linux and other Unix-like
		home, _ := os.UserHomeDir()
		return filepath.Join(home, ".malairted")
	}
}

// expandPath expands ~ and environment variables in a path.
func expandPath(path string) string {
	if path == "~" {
		home, err := os.UserHomeDir()
		if err == nil {
			return home
		}
	} else if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			// Use filepath.Join so the result uses the OS-native path separator.
			path = filepath.Join(home, path[2:])
		}
	}
	return os.ExpandEnv(path)
}
