// Package chain implements the Malairt blockchain state management.
package chain

import (
	"github.com/computervirtualservices/malairte/internal/crypto"
	"github.com/computervirtualservices/malairte/internal/primitives"
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
	// RetargetInterval is the legacy Bitcoin-style retarget window. Retained for
	// backwards compatibility with persisted chains; LWMA retargets every block
	// and ignores this value once the chain is past LWMAWindow headers.
	RetargetInterval uint64
	// BlockTime is the target time between blocks in seconds.
	BlockTime int64
	// PowLimitBits is the easiest permitted compact target. All post-LWMA
	// retargets clamp at this value; a block whose Bits exceed PowLimitBits
	// (i.e. whose numeric target is larger) is rejected.
	PowLimitBits uint32
	// AllowMinDifficultyBlocks, when true, relaxes the difficulty target to
	// PowLimitBits for any block whose timestamp is more than
	// 2 * BlockTime seconds after its parent. This is the Bitcoin-testnet
	// "never-stuck" rule: if a solo miner goes offline, anyone can resume
	// mining at trivial difficulty rather than being locked into the prior
	// high-hashrate LWMA target. Must stay false on mainnet.
	AllowMinDifficultyBlocks bool
	// MaxBlockWeight is the maximum permitted weight of a block in weight units
	// (WU). Pre-SegWit this caps the serialized block at MaxBlockWeight/4 bytes;
	// post-SegWit the witness discount lets a block carry up to MaxBlockWeight
	// bytes of witness data. Bitcoin mainnet uses 4_000_000 WU.
	MaxBlockWeight int
	// AdminAddress is the protocol-fee recipient. Every block (except genesis)
	// pays AdminFeeAtoms here as part of the coinbase, and every non-coinbase
	// transaction must include an output of at least AdminFeeAtoms to this
	// address. This is a consensus rule — every node enforces it identically.
	AdminAddress string
	// AdminFeeAtoms is the per-block and per-transaction protocol fee in atoms.
	AdminFeeAtoms int64
	// GenesisAddress is the recipient of the genesis block's coinbase reward.
	// Empty string falls back to the all-zeros burn hash (Satoshi-style
	// unspendable). Changing this value changes the genesis hash, so it must
	// remain fixed once a chain has been bootstrapped.
	GenesisAddress string
	// AddressVersion is the Base58Check version byte (50=mainnet "M", 111=testnet "m").
	AddressVersion byte
	// Bech32HRP is the human-readable prefix for native SegWit addresses:
	// "mlrt" on mainnet ("mlrt1q…" v0, "mlrt1p…" v1 taproot), "tmlrt" on
	// testnet. The same HRP covers every witness version; the version byte
	// selects between bech32 (v0) and bech32m (v1+).
	Bech32HRP string
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
	GenesisAddress:   "MRxSEiJJ4FgHrUMMEMfTMeT6EmMDARE1AD", // genesis reward pays treasury (was burn hash pre-rebootstrap)
	AddressVersion:   50,                                  // Base58Check prefix "M"
	Bech32HRP:        "mlrt",
	GenesisBits:      0x1d00ffff,                          // difficulty-1 at launch; LWMA adapts from here
	PowLimitBits:     0x1e0ffff0,                          // easiest permitted target (LWMA clamp)
	// Bootstrap-phase escape valve: a CPU-scale GPU session pushed LWMA to
	// ~diff 2e10, stranding the chain when the GPU went off. Until sustained
	// multi-miner hashrate arrives, any block >240s after parent is allowed
	// to use PowLimitBits. Flip back to false once the network is live.
	AllowMinDifficultyBlocks: true,
	MaxBlockWeight:           4_000_000, // 4 MWU — matches Bitcoin mainnet
	GenesisTimestamp:         1_776_732_000, // 2026-04-21 00:00:00 UTC — mainnet 0.2.0 re-bootstrap; old chaindata invalid
	Checkpoints:      map[uint64][32]byte{},
	// Default bootstrap peer. Fresh installs dial this first so they discover
	// the network and sync the canonical chain before their local miner can
	// build an orphan fork from genesis.
	SeedPeers: []string{
		"104.192.5.197:9333",
	},
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
	AddressVersion:   111,     // Base58Check prefix "m"
	Bech32HRP:        "tmlrt", // testnet native-SegWit HRP
	GenesisBits:              0x207fffff, // trivial target on testnet for dev-speed mining
	PowLimitBits:             0x207fffff,
	AllowMinDifficultyBlocks: true,      // testnet "never-stuck" escape valve
	MaxBlockWeight:           4_000_000, // same cap as mainnet
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

// GenesisScript returns the P2PKH locking script that receives the genesis
// coinbase reward. When GenesisAddress is empty (or undecodable), the reward
// goes to the all-zeros burn hash — Satoshi-style unspendable.
func (p *ChainParams) GenesisScript() []byte {
	if p.GenesisAddress == "" {
		return primitives.P2PKHScript([20]byte{})
	}
	_, payload, err := crypto.Base58CheckDecode(p.GenesisAddress)
	if err != nil || len(payload) != 20 {
		return primitives.P2PKHScript([20]byte{})
	}
	var pkh [20]byte
	copy(pkh[:], payload)
	return primitives.P2PKHScript(pkh)
}
