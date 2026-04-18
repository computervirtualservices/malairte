# Malairt Mainnet

The Malairt mainnet is the production network where MLRT tokens have real monetary value.

## Parameters

| Parameter          | Value                                  |
|--------------------|----------------------------------------|
| Network name       | mainnet                                |
| Magic bytes        | `0x4d 0x4c 0x52 0x54` (MLRT)          |
| P2P port           | 9333                                   |
| RPC port           | 9332                                   |
| Address prefix     | M (version byte 50)                    |
| Genesis timestamp  | 1,704,067,200 (2024-01-01 00:00:00 UTC)|
| Initial block reward | 50 MLRT (5,000,000,000 atoms)        |
| Halving interval   | 210,000 blocks                         |
| Block time target  | 120 seconds                            |
| Max supply         | ~21,000,000 MLRT                       |

## Running a Mainnet Node

```bash
# Default (mainnet)
malairted

# Explicit mainnet with custom data dir
malairted --network=mainnet --data-dir=/var/lib/malairted
```

## Running a Mainnet Miner

```bash
# Generate a new key first, then mine with it
malairtcli genkey
# Save the private key output, then:
malairted --mine --miner-key=<your-private-key-hex>
```

## RPC Examples

```bash
# Get blockchain info
malairtcli getinfo

# Get balance of an address
malairtcli validateaddress <address>

# Send a raw transaction
malairtcli sendrawtx <hex>

# Get block by hash
malairtcli getblock <hash>
```

## Security Notes

- The RPC server only listens on localhost (127.0.0.1) by default
- Keep your private keys secure — anyone with access can spend your funds
- Back up your data directory regularly
- The node does not implement authentication on the RPC interface — do not expose it to the network
