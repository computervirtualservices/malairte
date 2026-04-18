// Package chain implements the Malairt blockchain state management.
package chain

import (
	"github.com/malairt/malairt/internal/crypto"
	"github.com/malairt/malairt/internal/primitives"
)

// ChainParams holds all consensus-critical parameters for a network.
// Different networks (mainnet, testnet) have different parameters.
type ChainParams struct {
	// Name is the human-readable network name.
	Name string
	// Net is the 4-byte magic identifier for P2P messages, stored as uint32.
	Net uint32
	// DefaultPort is the default P2P listening port.
	DefaultPort string
	// RPCPort is the default RPC listening port.
	RPCPort string
	// GenesisHash is the hash of the genesis block (computed at startup).
	GenesisHash [32]byte
	// GenesisBits is the compact difficulty target for the genesis block.
	GenesisBits uint32
	// GenesisTimestamp is the Unix timestamp embedded in the genesis block.
	GenesisTimestamp int64
	// InitialReward is the block subsidy in atoms for block 0 to HalvingInterval-1.
	InitialReward int64
	// HalvingInterval is the number of blocks between each halving of the block reward.
	HalvingInterval uint64
	// RetargetInterval is the number of blocks between difficulty adjustments.
	RetargetInterval uint64
	// BlockTime is the target time between blocks in seconds.
	BlockTime int64
	// AdminAddress is the protocol-fee recipient. Every block (except genesis)
	// pays AdminFeeAtoms here as part of the coinbase, and every non-coinbase
	// transaction must include an output of at least AdminFeeAtoms to this
	// address. This is a consensus rule — every node enforces it identically.
	AdminAddress string
	// AdminFeeAtoms is the per-block and per-transaction protocol fee in atoms.
	AdminFeeAtoms int64
	// AddressVersion is the Base58Check version byte (50=mainnet "M", 111=testnet "m").
	AddressVersion byte
	// Checkpoints maps block heights to expected block hashes.
	Checkpoints map[uint64][32]byte
	// SeedPeers is the list of default bootstrap peer addresses ("host:port").
	// These are used on first start before the node has discovered other peers.
	SeedPeers []string
}

// MainNetParams are the chain parameters for the Malairt main network.
var MainNetParams = ChainParams{
	Name:             "mainnet",
	Net:              0x4d4c5254, // "MLRT"
	DefaultPort:      "9333",
	RPCPort:          "9332",
	InitialReward:    5_000_000_000, // 50 MLRT in atoms
	HalvingInterval:  210_000,
	RetargetInterval: 2016,
	BlockTime:        120, // 2 minutes
	AdminAddress:     "MRxSEiJJ4FgHrUMMEMfTMeT6EmMDARE1AD", // protocol fee recipient
	AdminFeeAtoms:    10,                                  // 0.0000001 MLRT per coinbase + per tx
	AddressVersion:   50,                                  // Base58Check prefix "M"
	GenesisBits:      0x207fffff,
	GenesisTimestamp: 1_776_472_889, // 2026-04-18 00:41:29 UTC — mainnet bootstrap
	Checkpoints:      map[uint64][32]byte{},
	// SeedPeers will be populated once public bootstrap nodes are deployed.
	SeedPeers: []string{},
}

// TestNetParams are the chain parameters for the Malairt test network.
var TestNetParams = ChainParams{
	Name:             "testnet",
	Net:              0x4d4c7274, // "MLrt"
	DefaultPort:      "19333",
	RPCPort:          "19332",
	InitialReward:    5_000_000_000, // 50 MLRT in atoms
	HalvingInterval:  210_000,
	RetargetInterval: 2016,
	BlockTime:        120, // 2 minutes
	AdminAddress:     "", // not enforced on testnet by default
	AdminFeeAtoms:    0,
	AddressVersion:   111, // Base58Check prefix "m"
	GenesisBits:      0x207fffff,
	GenesisTimestamp: 1_745_452_800, // 2026-04-24 00:00:00 UTC
	Checkpoints:      map[uint64][32]byte{},
	// SeedPeers will be populated once public bootstrap nodes are deployed.
	SeedPeers: []string{},
}

// MagicBytes returns the network magic bytes as a [4]byte array.
func (p *ChainParams) MagicBytes() [4]byte {
	return [4]byte{
		byte(p.Net >> 24),
		byte(p.Net >> 16),
		byte(p.Net >> 8),
		byte(p.Net),
	}
}

// AdminScript returns the P2PKH locking script paying to AdminAddress, or nil
// when AdminAddress is empty (admin-fee enforcement disabled).
func (p *ChainParams) AdminScript() []byte {
	if p.AdminAddress == "" || p.AdminFeeAtoms <= 0 {
		return nil
	}
	_, payload, err := crypto.Base58CheckDecode(p.AdminAddress)
	if err != nil || len(payload) != 20 {
		return nil
	}
	var pkh [20]byte
	copy(pkh[:], payload)
	return primitives.P2PKHScript(pkh)
}
