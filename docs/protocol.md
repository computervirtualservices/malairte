# Malairt P2P Wire Protocol Specification

## Overview

The Malairt P2P protocol is a binary TCP protocol inspired by Bitcoin's peer-to-peer network protocol. All communication is full-duplex and message-based. Messages can be sent in either direction at any time after the handshake is complete.

---

## Message Framing

Every P2P message is wrapped in a fixed 24-byte header followed by a variable-length payload.

```
Offset  Length  Field            Type      Description
------  ------  -----            ----      -----------
0       4       magic            [4]byte   Network identifier
4       12      command          [12]byte  ASCII command string, null-padded
16      4       length           uint32 LE Payload length in bytes
20      4       checksum         [4]byte   SHA3-256(payload)[0:4]
24      N       payload          []byte    Message-specific body
```

### Magic Bytes

| Network  | Magic Bytes                        | ASCII |
|----------|------------------------------------|-------|
| Mainnet  | `0x4d 0x4c 0x52 0x54`             | MLRT  |
| Testnet  | `0x4d 0x4c 0x72 0x74`             | MLrt  |

### Command Field

The 12-byte command field contains the ASCII message type left-aligned, with trailing null bytes (`0x00`) padding to exactly 12 bytes. Example: `"version\x00\x00\x00\x00\x00"`.

### Checksum

The checksum is the first 4 bytes of `SHA3-256(payload)`. For messages with no payload (e.g., `verack`), the checksum of an empty byte slice is used: `SHA3-256([]byte{})[0:4]`.

---

## Message Types

### `version`

Sent immediately upon connecting to a new peer. The first message on any new connection.

```
Field        Type       Size    Description
-----------  ---------  ------  -----------
version      uint32 LE  4       Protocol version (currently 70001)
services     uint64 LE  8       Bitmask of supported services (0 = none)
timestamp    int64 LE   8       Current Unix time in seconds
addr_recv    varstring  var     Host:port of the receiving peer
addr_from    varstring  var     Host:port of the sending peer (may be empty)
nonce        uint64 LE  8       Random nonce to detect self-connections
user_agent   varstring  var     Software version string (e.g. "/Malairted:0.1.0/")
start_height int32 LE   4       The sender's current chain height
```

Strings are encoded as varint-prefixed UTF-8 bytes (Bitcoin varstring format).

### `verack`

Sent in response to a `version` message to complete the handshake. Has no payload (payload length = 0).

### `ping`

```
Field   Type       Size  Description
------  ---------  ----  -----------
nonce   uint64 LE  8     Random nonce; must be echoed back in pong
```

### `pong`

```
Field   Type       Size  Description
------  ---------  ----  -----------
nonce   uint64 LE  8     Echo of the nonce from the ping message
```

### `inv` (inventory)

Announces one or more inventory items (blocks or transactions) without sending their content.

```
Field   Type       Size  Description
------  ---------  ----  -----------
count   varint     var   Number of inventory items
items   []invvect  var   Each item is type(4) + hash(32)
```

**InvVect structure:**
```
type    uint32 LE  4   Object type: 1=TX, 2=Block
hash    [32]byte  32   SHA3-256 hash identifying the object
```

### `getdata`

Requests the data for specific inventory items. Identical structure to `inv`.

### `block`

Carries a complete serialized block.

```
Field    Type    Size  Description
-------  ------  ----  -----------
header   bytes   96    Serialized BlockHeader
txcount  varint  var   Number of transactions
txs      []tx    var   Each serialized transaction
```

**BlockHeader serialization (96 bytes, little-endian):**
```
version      uint32  4
previoushash [32]byte 32
merkleroot   [32]byte 32
timestamp    int64   8
bits         uint32  4
nonce        uint64  8
height       uint64  8
Total:                96
```

### `tx`

Carries a single serialized transaction.

**Transaction serialization:**
```
version      uint32 LE  4
in_count     varint     var
inputs       []txin     var
out_count    varint     var
outputs      []txout    var
locktime     uint32 LE  4
```

**TxInput:**
```
prev_txid    [32]byte   32
prev_idx     uint32 LE  4
scriptsig_len varint    var
scriptsig    []byte     var
sequence     uint32 LE  4
```

**TxOutput:**
```
value        int64 LE   8  (atoms; 1 MLRT = 100,000,000 atoms)
script_len   varint     var
scriptpubkey []byte     var
```

### `getblocks`

Requests a list of block inventory items from a peer. Used during initial sync.

```
Field         Type        Size  Description
-----------   ----------  ----  -----------
locator_count varint      var   Number of locator hashes
locator       [][32]byte  var   Block hashes from tip back toward genesis
stop_hash     [32]byte    32    Stop at this hash (all-zeros = no limit)
```

The peer responds with an `inv` message containing up to 500 block hashes starting after the highest locator hash it recognizes.

### `headers`

Carries a list of block headers (without transactions). Used for lightweight header sync.

```
Field     Type           Size  Description
-------   ------         ----  -----------
count     varint         var   Number of headers
headers   []blockheader  var   Each header (96 bytes) followed by varint(0)
```

The trailing `varint(0)` after each header is Bitcoin-compatible padding for the transaction count.

---

## Handshake Sequence

```
Initiator (outbound)              Responder (inbound)
         |                                |
         |-------- version message ------>|
         |                                |
         |<------- version message -------|
         |                                |
         |<------- verack message --------|
         |                                |
         |-------- verack message ------->|
         |                                |
         |     === Connection Ready ===   |
         |                                |
```

After both sides send and receive `verack`, the connection is fully established and any message type may be exchanged.

---

## Block Announcement Flow

When a miner discovers a new block:

```
Miner                         Connected Peers
  |                                  |
  |-- inv(type=block, hash=H) ------>|  (broadcast to all peers)
  |                                  |
  |<-- getdata(type=block, hash=H) --|  (peers that don't have block H)
  |                                  |
  |-- block(full block data) ------->|  (sends full block to requesting peers)
  |                                  |
  |     (peers validate and add      |
  |      to their chain, then        |
  |      relay inv to their peers)   |
```

---

## Transaction Relay Flow

When a user submits a transaction (via `sendrawtransaction` RPC or another peer):

```
Node                          Connected Peers
  |                                  |
  |-- inv(type=tx, txid=T) --------->|  (broadcast announcement)
  |                                  |
  |<-- getdata(type=tx, txid=T) -----|  (peers that want the tx)
  |                                  |
  |-- tx(full tx data) ------------->|  (send full transaction)
  |                                  |
```

---

## Chain Sync Flow

When a newly connected peer needs to catch up to the current chain tip:

```
New Peer                      Sync Peer
  |                                  |
  |-- getblocks(locator, stop=0) --->|  (locator = list of known hashes)
  |                                  |
  |<-- inv([hash1, hash2, ...500]) --|  (up to 500 block hashes)
  |                                  |
  |-- getdata([hash1]) ------------->|
  |<-- block(full block 1) ----------|
  |                                  |
  |-- getdata([hash2]) ------------->|
  |<-- block(full block 2) ----------|
  |         ...                      |
  |                                  |
  |-- getblocks(new locator, ...) -->|  (request next batch)
  |                                  |
```

The locator is built exponentially: the most recent 10 hashes appear in the locator, then every 2nd, every 4th, etc., back to the genesis block. This allows a node with any level of sync to quickly find a common ancestor with the sync peer.

---

## VarInt Encoding

Bitcoin-style variable-length integer encoding:

| Value Range           | Encoding                       | Bytes |
|-----------------------|--------------------------------|-------|
| 0x00 – 0xFC           | `[value]`                      | 1     |
| 0x00FD – 0xFFFF       | `[0xFD, low, high]`            | 3     |
| 0x00010000–0xFFFFFFFF | `[0xFE, b0, b1, b2, b3]`       | 5     |
| 0x100000000 and up    | `[0xFF, b0, b1, b2, b3, b4, b5, b6, b7]` | 9 |

All multi-byte values are in little-endian byte order.

---

## Error Handling

- A node that receives a malformed message (bad magic, bad checksum, truncated payload) SHOULD disconnect the offending peer.
- A node that receives an unknown command type SHOULD ignore the message and continue.
- There is no explicit error message type; rejections are communicated by disconnection or by the absence of a response.

---

## Connection Limits

- Default maximum connections: 125 (configurable via `--max-peers`)
- Inbound and outbound connections share the same limit
- New inbound connections beyond the limit are rejected by closing the TCP socket immediately
