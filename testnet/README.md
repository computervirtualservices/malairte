# Malairt Testnet

The Malairt testnet is a public test network with the same consensus rules as mainnet
but with separate chain state and different magic bytes.

## Parameters

| Parameter          | Value                                  |
|--------------------|----------------------------------------|
| Network name       | testnet                                |
| Magic bytes        | `0x4d 0x4c 0x72 0x74` (MLrt)          |
| P2P port           | 19333                                  |
| RPC port           | 19332                                  |
| Address prefix     | m (version byte 111)                   |
| Genesis timestamp  | 1,704,067,200 (2024-01-01 00:00:00 UTC)|
| Initial difficulty | 0x207fffff (minimum)                   |

## Running a Testnet Node

```bash
malairte-node --network=testnet --data-dir=~/.malairte/testnet
```

## Running a Testnet Miner

```bash
malairte-node --network=testnet --mine --data-dir=~/.malairte/testnet
```

## Connecting to Testnet Peers

```bash
malairte-node --network=testnet --seeds=<peer1>:19333,<peer2>:19333
```

## Testnet CLI Examples

```bash
# Use testnet RPC port
export MLRT_RPC=http://127.0.0.1:19332

malairte-cli --rpc $MLRT_RPC getinfo
malairte-cli --rpc $MLRT_RPC genkey
malairte-cli --rpc $MLRT_RPC getmininginfo
```

## Notes

- Testnet coins have no monetary value
- The difficulty resets to the minimum (0x207fffff) easily on testnet
- Testnet addresses start with lowercase `m`
