package chain

import (
	"github.com/malairt/malairt/internal/primitives"
)

// genesisMessage is the coinbase message embedded in the genesis block.
// Inspired by Bitcoin's Satoshi message, this marks the birth of the Malairt chain.
const genesisMessage = "MLRT Genesis - The Malairt coin begins."

// GenesisBlock constructs the genesis block for the given chain parameters.
// The genesis block:
//   - Has height 0 and a zero PreviousHash
//   - Contains a single coinbase transaction with the initial block reward
//   - Sends the reward to a burn address (all-zeros pubkey hash)
//   - Uses nonce=0 with easy difficulty (0x207fffff) so it validates immediately
func GenesisBlock(params *ChainParams) *primitives.Block {
	// Burn address: P2PKH script locking to all-zeros pubkey hash
	// This coins are permanently unspendable — genesis reward goes to nobody
	burnHash := [20]byte{} // all zeros
	burnScript := primitives.P2PKHScript(burnHash)

	// Create coinbase transaction with the genesis message
	coinbaseTx := createGenesisCoinbase(params.InitialReward, burnScript)

	// Compute merkle root from the single coinbase transaction
	merkleRoot := primitives.CalcMerkleRoot([]*primitives.Transaction{coinbaseTx})

	header := primitives.BlockHeader{
		Version:      1,
		PreviousHash: [32]byte{}, // all zeros for genesis
		MerkleRoot:   merkleRoot,
		Timestamp:    params.GenesisTimestamp,
		Bits:         params.GenesisBits,
		Nonce:        0, // easy difficulty means nonce=0 meets the target
		Height:       0,
	}

	return &primitives.Block{
		Header: header,
		Txs:    []*primitives.Transaction{coinbaseTx},
	}
}

// createGenesisCoinbase creates the genesis block coinbase transaction.
// The coinbase scriptSig contains only the genesis message (no BIP34 height prefix
// since the genesis block is special).
func createGenesisCoinbase(reward int64, scriptPubKey []byte) *primitives.Transaction {
	scriptSig := []byte(genesisMessage)

	return &primitives.Transaction{
		Version: 1,
		Inputs: []primitives.TxInput{
			{
				PreviousOutput: primitives.OutPoint{
					TxID:  [32]byte{}, // all zeros for coinbase
					Index: 0xFFFFFFFF,
				},
				ScriptSig: scriptSig,
				Sequence:  0xFFFFFFFF,
			},
		},
		Outputs: []primitives.TxOutput{
			{
				Value:        reward,
				ScriptPubKey: scriptPubKey,
			},
		},
		LockTime: 0,
	}
}

// GenesisHash computes the hash of the genesis block header for the given params.
func GenesisHash(params *ChainParams) [32]byte {
	block := GenesisBlock(params)
	return block.Header.Hash()
}

// CalcBlockSubsidy returns the block reward in atoms for a given block height.
// The reward starts at InitialReward and halves every HalvingInterval blocks.
// Eventually returns 0 when all halvings result in a zero reward.
func CalcBlockSubsidy(height uint64, params *ChainParams) int64 {
	halvings := height / params.HalvingInterval
	// After 64 halvings, the reward would be 0 due to integer shift overflow
	if halvings >= 64 {
		return 0
	}
	reward := params.InitialReward >> halvings
	return reward
}
