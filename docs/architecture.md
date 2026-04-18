# Malairt Blockchain Architecture

## Overview

Malairt (ticker: MLRT) is a Bitcoin-inspired proof-of-work cryptocurrency implemented in Go. It uses a UTXO model, SHA3-based double hashing for PoW, secp256k1 ECDSA for transaction signing, and BadgerDB for persistent storage.

---

## Chain Design Decisions

### Proof of Work: MLRTHash v1

MLRTHash is defined as `DoubleSHA3256(serialized_block_header)`, where:

```
MLRTHash(header) = SHA3-256(SHA3-256(header.Serialize()))
```

This is a placeholder for a future RandomX integration. The nonce-search mechanic is identical to Bitcoin: miners increment the 64-bit `Nonce` field in the block header until `HashAsInt(header) <= target`. Using `uint64` instead of Bitcoin's `uint32` gives 2^64 nonce space per timestamp/extraNonce combination.

### UTXO Model

Malairt uses an Unspent Transaction Output model identical in structure to Bitcoin:
- Every transaction consumes outputs from previous transactions (inputs) and creates new outputs
- The UTXO set is the complete set of all outputs not yet spent
- Coin ownership is determined by script locking conditions (P2PKH by default)

### Block Time and Reward

- **Target block time:** 120 seconds (2 minutes)
- **Initial block reward:** 5,000,000,000 atoms = 50.00000000 MLRT
- **1 MLRT = 100,000,000 atoms** (8 decimal places, same as Bitcoin's satoshis)
- **Halving interval:** 210,000 blocks (~1 year at 2 min/block)

### Difficulty Adjustment

Every 2,016 blocks, the difficulty is recalculated using the same algorithm as Bitcoin:

```
new_target = old_target × (actual_time / expected_time)
```

Where `expected_time = 2016 × 120 = 241,920 seconds`. The adjustment is clamped to a factor of 4 in either direction per window to prevent extreme swings.

---

## Module Overview

```
internal/
├── crypto/      Hash functions (SHA3-256, double-SHA3-256, Hash160, Hash256)
│                Key generation, signing, and verification (secp256k1)
│                Base58Check encoding/decoding
├── primitives/  Block headers and blocks
│                Transactions, inputs, outputs, outpoints
│                P2PKH script helpers
│                VarInt and serialization utilities
├── consensus/   MLRTHash PoW computation
│                Difficulty target (CompactToBig, BigToCompact)
│                Block mining loop (nonce search)
│                Difficulty adjustment algorithm
├── chain/       Chain parameters (mainnet, testnet)
│                Genesis block construction and hash
│                Blockchain struct (tip management, block storage)
│                UTXO set (backed by BadgerDB)
│                Block and transaction validation
│                Block subsidy calculation
├── mempool/     In-memory pool of unconfirmed transactions
│                Add, remove, sort by fee, count, size
├── mining/      Block template assembly (coinbase + mempool txs)
│                CPU miner goroutine (nonce search loop)
├── network/     P2P message framing (magic, command, checksum)
│                All message types (version, verack, ping, inv, block, tx, ...)
│                Peer connection management (send/receive loops)
│                PeerServer (listen, dial, broadcast, message dispatch)
├── rpc/         JSON-RPC 1.0 HTTP server
│                Bitcoin-compatible method handlers
└── storage/     DB interface (Put, Get, Delete, Has, ForEachWithPrefix, Batch)
                 BadgerDB implementation
```

---

## Genesis Block Specification

| Field         | Value                                                    |
|---------------|----------------------------------------------------------|
| Height        | 0                                                        |
| Version       | 1                                                        |
| PreviousHash  | 0x0000...0000 (32 zero bytes)                            |
| Timestamp     | 1,704,067,200 (2024-01-01 00:00:00 UTC)                  |
| Bits          | 0x207fffff (minimum difficulty — any hash passes)        |
| Nonce         | 0                                                        |
| Coinbase msg  | "MLRT Genesis - The Malairt coin begins."                |
| Coinbase dest | All-zeros burn address (permanently unspendable)         |
| Reward        | 5,000,000,000 atoms (50 MLRT)                            |

The genesis block hash is deterministic and computed at startup. With `Bits=0x207fffff`, the target is approximately `0x7fffff × 2^(8×(0x20-3)) = 7fffff × 2^216`, which is close to the maximum possible value. Virtually any hash satisfies this target, so `Nonce=0` always works.

---

## Emission Schedule

| Epoch | Block Range         | Reward (MLRT) | Reward (atoms)    | Total MLRT Issued |
|-------|---------------------|---------------|-------------------|-------------------|
| 0     | 0 – 209,999         | 50.00000000   | 5,000,000,000     | 10,500,000.00     |
| 1     | 210,000 – 419,999   | 25.00000000   | 2,500,000,000     | 15,750,000.00     |
| 2     | 420,000 – 629,999   | 12.50000000   | 1,250,000,000     | 18,375,000.00     |
| 3     | 630,000 – 839,999   | 6.25000000    | 625,000,000       | 19,687,500.00     |
| 4     | 840,000 – 1,049,999 | 3.12500000    | 312,500,000       | 20,343,750.00     |
| 5     | 1,050,000–1,259,999 | 1.56250000    | 156,250,000       | 20,671,875.00     |
| 6     | 1,260,000–1,469,999 | 0.78125000    | 78,125,000        | 20,835,937.50     |
| 7     | 1,470,000–1,679,999 | 0.39062500    | 39,062,500        | 20,917,968.75     |
| 8     | 1,680,000–1,889,999 | 0.19531250    | 19,531,250        | 20,958,984.375    |
| 9     | 1,890,000–2,099,999 | 0.09765625    | 9,765,625         | 20,979,492.188    |

**Asymptotic maximum supply: 21,000,000 MLRT** (approached but never reached; after 64 halvings the reward rounds down to 0 atoms).

---

## P2P Protocol Overview

The P2P layer uses a custom TCP framing protocol inspired by Bitcoin. All connections are bidirectional full-duplex streams.

### Wire Frame

```
[4]  magic bytes      Network identifier
[12] command          ASCII, null-padded to 12 bytes
[4]  payload length   Little-endian uint32
[4]  checksum         First 4 bytes of SHA3-256(payload)
[N]  payload          Variable-length message body
```

### Connection Lifecycle

1. TCP connection established
2. Both peers send `version` message immediately
3. Each peer responds with `verack` upon receiving a valid `version`
4. After both `verack` messages are exchanged, the connection is fully established
5. Periodic `ping`/`pong` messages keep the connection alive

### Block Propagation

1. Miner finds a block → sends `inv(type=block, hash=H)` to all peers
2. Peer receives `inv` → checks if it has the block → if not, sends `getdata(type=block, hash=H)`
3. Sender responds with `block` message containing the full block
4. Receiver validates and adds the block to its chain, then relays the `inv` to its own peers

---

## RPC Method Catalog

| Method                | Description                                         |
|-----------------------|-----------------------------------------------------|
| `getblockchaininfo`   | Chain height, best hash, difficulty, network        |
| `getblockhash`        | Block hash at a given height                        |
| `getblockheader`      | Block header as hex or JSON                         |
| `getblock`            | Full block as hex or JSON (verbosity 0/1/2)         |
| `getrawtransaction`   | Transaction hex or JSON (mempool only for now)      |
| `sendrawtransaction`  | Submit a raw transaction hex to the mempool         |
| `getmempoolinfo`      | Mempool size, bytes, usage                          |
| `getrawmempool`       | List of txids (or verbose map) in the mempool       |
| `getblocktemplate`    | Block template for external miners (simplified GBT) |
| `submitblock`         | Submit a solved block                               |
| `getpeerinfo`         | Connected peer addresses, versions, heights         |
| `getnetworkinfo`      | Protocol version, connections, subversion           |
| `getmininginfo`       | Hash rate, difficulty, pooled txs, chain            |
| `validateaddress`     | Validate a Base58Check address                      |
| `stop`                | Graceful node shutdown                              |

---

## Storage Key Conventions

| Prefix       | Key Format                              | Value                  |
|--------------|-----------------------------------------|------------------------|
| `b/`         | `b/` + 32-byte block hash               | Serialized BlockHeader |
| `bx/`        | `bx/` + 32-byte block hash              | Serialized transactions|
| `h/`         | `h/` + 8-byte big-endian height         | 32-byte block hash     |
| `tip`        | literal `tip`                           | 32-byte best hash      |
| `u/`         | `u/` + 32-byte txid + `/` + 4-byte idx | Serialized UTXO        |

---

## Address Format

Malairt uses Bitcoin-style Base58Check encoding with custom version bytes:

| Network  | Version Byte | Typical Prefix |
|----------|-------------|----------------|
| Mainnet  | 50          | M              |
| Testnet  | 111         | m              |

Address derivation:
1. Generate secp256k1 private key (32 random bytes)
2. Derive compressed public key (33 bytes)
3. `pubKeyHash = RIPEMD160(SHA256(compressedPubKey))`
4. `payload = [versionByte] + pubKeyHash`
5. `checksum = SHA256(SHA256(payload))[:4]`
6. `address = Base58Encode(payload + checksum)`

---

## Future Upgrade Notes

### RandomX PoW Integration
The `MLRTHash` function in `internal/consensus/pow.go` is the sole integration point for the PoW algorithm. Replacing it with RandomX requires:
1. Linking the RandomX C library (or a Go binding)
2. Updating `MLRTHash` to call `randomx_calculate_hash`
3. Implementing a RandomX dataset/cache lifecycle (typically one cache per epoch)
4. The rest of the codebase (difficulty, mining loop, validation) requires no changes

### Script Execution Engine
`internal/chain/validation.go:ValidateTx` currently stubs out script verification. A full implementation requires:
1. A stack-based script interpreter for OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG
2. Signature hash computation (SIGHASH_ALL for now)
3. SegWit or other script upgrade paths can be added later

### Transaction Index (txindex)
`getrawtransaction` currently only searches the mempool. A full txindex would store `txid → (block_hash, tx_index_in_block)` in BadgerDB under a `tx/` prefix, enabling retrieval of any confirmed transaction.
