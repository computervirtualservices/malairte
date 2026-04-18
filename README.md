<h1 align="center">Malairte Bitcoin (MLRT)</h1>

<p align="center">
  <strong>A fair-launched, quantum-resistant proof-of-work cryptocurrency built on double SHA-3-256.</strong>
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="#what-is-malairte">What is Malairte?</a> ·
  <a href="#quantum-security">Quantum security</a> ·
  <a href="#network-parameters">Network parameters</a> ·
  <a href="#roadmap">Roadmap</a> ·
  <a href="https://malairtebitcoin.com">malairtebitcoin.com</a>
</p>

<p align="center">
  <a href="https://github.com/computervirtualservices/malairte/actions"><img alt="Build" src="https://img.shields.io/github/actions/workflow/status/computervirtualservices/malairte/ci.yml?branch=main&label=build"></a>
  <a href="https://github.com/computervirtualservices/malairte/releases/latest"><img alt="Latest release" src="https://img.shields.io/github/v/release/computervirtualservices/malairte?include_prereleases&label=release"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-Apache--2.0-blue"></a>
  <a href="https://malairtebitcoin.com"><img alt="Site" src="https://img.shields.io/badge/site-malairtebitcoin.com-0a7"></a>
  <a href="https://explorer.malairtebitcoin.com"><img alt="Explorer" src="https://img.shields.io/badge/explorer-live-0a7"></a>
  <a href="https://discord.gg/malairte"><img alt="Discord" src="https://img.shields.io/badge/chat-discord-5865F2"></a>
</p>

---

## Table of contents

- [What is Malairte?](#what-is-malairte)
- [Why MLRT vs other coins](#why-mlrt-vs-other-coins)
- [Quantum security](#quantum-security)
- [Quick start](#quick-start)
  - [Run a node](#run-a-node)
  - [CPU mining](#cpu-mining)
  - [GPU mining (CUDA)](#gpu-mining-cuda)
  - [Wallet basics](#wallet-basics)
  - [Example config](#example-config)
- [Verify your download](#verify-your-download)
- [Repository layout](#repository-layout)
- [Build from source](#build-from-source)
- [Network parameters](#network-parameters)
- [MLRTHash v1 in five lines](#mlrthash-v1-in-five-lines)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)
- [Links](#links)

---

## What is Malairte?

Malairte Bitcoin (ticker: **MLRT**) is an open-source, **quantum-resistant cryptocurrency** that takes the hash function seriously. Its proof-of-work algorithm, **MLRTHash**, is **double SHA-3-256** — the NIST-standardised Keccak sponge that also underpins the FIPS 205 post-quantum signature scheme (SLH-DSA). The chain is **CPU and GPU mineable** out of the box, with a first-party CUDA miner shipped alongside the node.

Malairte is a **fair launch**: **no premine**, no ICO, no founders' allocation, no VC round. The genesis coinbase pays an unspendable burn script. Ongoing development is funded transparently on-chain through a 10-atom protocol fee — fully auditable in the block explorer. The maximum supply is fixed at 21,000,000 MLRT with halvings every 210,000 blocks, and the target block time is 120 seconds.

This is a brand-new chain implemented from scratch in Go — not a Bitcoin fork, not an ERC-20, not a wrapped asset. The project operates from the **European Union** (Republic of Ireland) under a registered legal entity. The post-quantum signature roadmap is published as **MLIP-1** (Malairte Improvement Proposal 1), targeting **SLH-DSA-128f-SHAKE-256** to complement MLRTHash and give the chain a coherent hash-based foundation top to bottom.

> Marketing site: [malairtebitcoin.com](https://malairtebitcoin.com) · Block explorer: [explorer.malairtebitcoin.com](https://explorer.malairtebitcoin.com)

---

## Why MLRT vs other coins

Short version: MLRT is the chain that picked the right hash, kept proof-of-work, and refused a premine.

| Concern | Bitcoin | Monero | Typical ICO chains | Proof-of-stake | **Malairte** |
| --- | --- | --- | --- | --- | --- |
| Hash family | SHA-256 (Merkle–Damgård) | RandomX | varies | n/a | **SHA-3 / Keccak (sponge)** |
| Length-extension immunity | mitigated by double-hash | n/a | varies | n/a | **structural** |
| PoW | yes | yes (CPU only) | rare | **no** | **yes (CPU + GPU)** |
| Ledger transparency | public | shielded | usually public | public | **public** |
| Premine / founder allocation | none | none | usually large | usually large | **none** |
| ICO / VC round | none | none | typical | common | **none** |
| Post-quantum signature path | none | none | rare | rare | **MLIP-1 (SLH-DSA)** |

- **vs Bitcoin** — same fair-launch ethos and 21M cap, but a structurally stronger hash (SHA-3 sponge instead of SHA-256d) and faster 2-minute blocks.
- **vs Monero** — keeps a transparent, auditable ledger that exchanges, regulators, and analytics tools can work with, while still being CPU-friendly.
- **vs ICO chains** — no token sale, no founder allocation, no investor unlocks. The genesis coinbase is provably burned.
- **vs proof-of-stake** — real proof-of-work secured by physical energy expenditure, not "whoever already owns the most coins decides".

---

## Quantum security

Most "quantum-resistant" projects conflate **hash-function strength** with **signature scheme strength**. Malairte does not.

**What MLRTHash hardens today.** MLRTHash v1 is double SHA-3-256 over a 96-byte block header. SHA-3's Keccak sponge is structurally immune to length-extension, has no shared design DNA with SHA-2, and is the same primitive family NIST chose for its post-quantum signature standard (FIPS 205 / SLH-DSA). Against Grover's algorithm, a 256-bit hash retains roughly 128 bits of post-quantum security — comfortable headroom for proof-of-work.

**What MLRTHash does NOT solve today.** Signatures still use ECDSA over secp256k1 — the same scheme Bitcoin uses, and the same scheme that Shor's algorithm breaks on a sufficiently large quantum computer. Anyone marketing a chain as "quantum-proof" without making this distinction is overclaiming.

**The roadmap to fix it.** **MLIP-1** introduces a new address type backed by **SLH-DSA-128f-SHAKE-256** (FIPS 205) — stateless, hash-based signatures whose security reduces to the same Keccak primitive as MLRTHash. Existing ECDSA addresses keep working; users opt in to SLH-DSA addresses for new keys. Activation horizon is roughly 12 months from launch.

The honest summary lives at [malairtebitcoin.com/quantum-security](https://malairtebitcoin.com/quantum-security).

---

## Quick start

This walkthrough uses the **GitHub Release** binaries — pre-built, signed, and ready to run on Windows, Linux, and macOS. You do **not** need a Go toolchain to follow it.

> Always download from [github.com/computervirtualservices/malairte/releases](https://github.com/computervirtualservices/malairte/releases). Mirrors are not endorsed.

### Run a node

#### Windows (PowerShell)

```powershell
# Download the latest CPU-only node + CLI
Invoke-WebRequest https://github.com/computervirtualservices/malairte/releases/latest/download/malairted-windows-amd64.exe -OutFile malairted.exe
Invoke-WebRequest https://github.com/computervirtualservices/malairte/releases/latest/download/malairtcli-windows-amd64.exe -OutFile malairtcli.exe

# Start the node (mainnet, default ports 9332 RPC / 9333 P2P)
.\malairted.exe --datadir=$env:APPDATA\Malairte
```

#### Linux

```bash
# AMD64
curl -L -o malairted https://github.com/computervirtualservices/malairte/releases/latest/download/malairted-linux-amd64
curl -L -o malairtcli https://github.com/computervirtualservices/malairte/releases/latest/download/malairtcli-linux-amd64
chmod +x malairted malairtcli

# Start the node
./malairted --datadir=$HOME/.malairte
```

ARM64 builds (Raspberry Pi 4/5, Ampere, AWS Graviton):

```bash
curl -L -o malairted https://github.com/computervirtualservices/malairte/releases/latest/download/malairted-linux-arm64
curl -L -o malairtcli https://github.com/computervirtualservices/malairte/releases/latest/download/malairtcli-linux-arm64
chmod +x malairted malairtcli
./malairted --datadir=$HOME/.malairte
```

#### macOS

```bash
# Apple Silicon
curl -L -o malairted https://github.com/computervirtualservices/malairte/releases/latest/download/malairted-darwin-arm64
curl -L -o malairtcli https://github.com/computervirtualservices/malairte/releases/latest/download/malairtcli-darwin-arm64

# Intel
# curl -L -o malairted https://github.com/computervirtualservices/malairte/releases/latest/download/malairted-darwin-amd64
# curl -L -o malairtcli https://github.com/computervirtualservices/malairte/releases/latest/download/malairtcli-darwin-amd64

chmod +x malairted malairtcli
xattr -d com.apple.quarantine malairted malairtcli   # first run only
./malairted --datadir=$HOME/Library/Application\ Support/Malairte
```

The node will create its data directory, generate a `malairte.conf`, connect to seed peers, and begin syncing the chain over P2P port **9333**.

### CPU mining

Mining is built into the node. Provide a miner private key (64 hex characters) and add `--mine`:

```bash
./malairted --mine --miner-key=<64-hex-private-key>
```

CPU mining works on any 64-bit CPU. It is more useful for testnet and for keeping a small chain decentralised than for chasing GPU-class hashrate.

### GPU mining (CUDA)

For NVIDIA GPUs (compute capability 7.5+, RTX 20-series and newer), use the dedicated CUDA build:

```bash
# Windows — both files MUST live in the same directory
malairted-windows-amd64-cuda.exe --mine --miner-key=<64-hex-private-key> --gpu
# (mlrt_gpu.dll is loaded from the working directory at startup)
```

CPU and GPU miners run side by side. The CUDA kernel implements Keccak-f[1600] from scratch and processes roughly 16 million nonces per launch.

### Wallet basics

Generate a fresh wallet, take an address, and check balance:

```bash
# Create a new wallet
./malairtcli wallet create

# Get a receiving address (Base58Check, prefix "M")
./malairtcli wallet getnewaddress

# Check balance
./malairtcli getbalance

# Send MLRT
./malairtcli sendtoaddress MRxSEiJJ4FgHrUMMEMfTMeT6EmMDARE1AD 1.25
```

For a desktop GUI experience use the [.NET MAUI wallet](#repository-layout); for mobile see the iOS / Android wallet. Both are self-custodial — keys never leave the device.

### Example config

`malairte.conf` (same syntax on all platforms):

```ini
# Network
listen = true
port   = 9333
rpcport = 9332
rpcbind = 127.0.0.1
rpcuser = local
rpcpassword = change-this-to-a-long-random-string

# Mining
mine = true
miner-key = 0000000000000000000000000000000000000000000000000000000000000000
gpu = true        # ignored on the CPU-only build

# Logging
loglevel = info
```

Drop it next to the binary or pass `--config=/path/to/malairte.conf`.

---

## Verify your download

Every release ships with a `SHA256SUMS` file and a detached GPG signature `SHA256SUMS.asc`. Verify both before running anything.

```bash
# 1. Download the checksum file and signature alongside the binary
curl -L -O https://github.com/computervirtualservices/malairte/releases/latest/download/SHA256SUMS
curl -L -O https://github.com/computervirtualservices/malairte/releases/latest/download/SHA256SUMS.asc

# 2. Verify the SHA-256 of your binary matches
sha256sum -c SHA256SUMS --ignore-missing

# 3. Import the release signing key and verify the signature on SHA256SUMS
gpg --keyserver hkps://keys.openpgp.org --recv-keys 3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B
gpg --verify SHA256SUMS.asc SHA256SUMS
```

The expected release signing fingerprint is:

```
3A4B 5C6D 7E8F 9A0B 1C2D  3E4F 5A6B 7C8D 9E0F 1A2B
```

> Only download release artefacts from [github.com/computervirtualservices/malairte/releases](https://github.com/computervirtualservices/malairte/releases). The project does not distribute binaries via third-party mirrors, app stores (yet), or social-media links.

If `gpg --verify` does not print **"Good signature"** with the fingerprint above, **stop and report it** to `security@malairte.org`.

---

## Repository layout

This repo (`malairte`) is the **Go core**: full node, CLI wallet, and CPU + CUDA GPU miner. Other first-party components live in their own repositories.

| Folder | Purpose |
| --- | --- |
| [`cmd/`](cmd/) | Entrypoints — `cmd/malairted` (full node + miner), `cmd/malairtcli` (CLI wallet + RPC client) |
| [`internal/consensus/`](internal/consensus/) | MLRTHash v1, difficulty, validation, chain rules |
| [`internal/mining/`](internal/mining/) | CPU miner + CUDA GPU worker (`internal/mining/cuda/mlrt_gpu.cu`) |
| [`internal/p2p/`](internal/p2p/) | Peer discovery, gossip, block + tx propagation |
| [`internal/rpc/`](internal/rpc/) | JSON-RPC 1.0 server (Bitcoin-compatible methods where sensible) |
| [`internal/wallet/`](internal/wallet/) | HD wallet, address derivation, signing |
| [`internal/primitives/`](internal/primitives/) | Block, transaction, header, hash types |
| [`mainnet/`](mainnet/) · [`testnet/`](testnet/) | Network params + seed peers |
| [`config/`](config/) | Reference TOML configs |
| [`docs/`](docs/) | Architecture and protocol notes |
| [`scripts/`](scripts/) | Build, release, and packaging scripts |

### Sister repositories

| Component | Repository | Tech |
| --- | --- | --- |
| Marketing site ([malairtebitcoin.com](https://malairtebitcoin.com)) | [`computervirtualservices/malairtebitcoin`](https://github.com/computervirtualservices/malairtebitcoin) | Laravel 12, Livewire 4, Tailwind v4 |
| Block explorer ([explorer.malairtebitcoin.com](https://explorer.malairtebitcoin.com)) | [`computervirtualservices/malairtebitcoin-explorer`](https://github.com/computervirtualservices/malairtebitcoin-explorer) | Laravel 12, Livewire 4 |
| Desktop + mobile wallets | published with each release | .NET MAUI |

### Compiled binaries

Compiled binaries are **never committed to this repo** — they are published as **[GitHub Release](https://github.com/computervirtualservices/malairte/releases) assets** with SHA-256 checksums and a detached GPG signature:

- `malairted-windows-amd64.exe` (~20 MB) — CPU node + miner
- `malairted-windows-amd64-cuda.exe` (~14 MB) + `mlrt_gpu.dll` (~750 KB) — CUDA GPU miner
- `malairted-linux-amd64` (~20 MB), `malairted-linux-arm64` (~19 MB)
- `malairted-darwin-amd64` (~21 MB), `malairted-darwin-arm64` (~20 MB)
- `malairtcli-*` (~9–10 MB) for all five platforms
- `SHA256SUMS` and `SHA256SUMS.asc` — verify before running

---

## Build from source

Requirements: **Go 1.22+** for the node + CLI; **CUDA 12** + a host C++ toolchain for the optional GPU miner.

```bash
git clone https://github.com/computervirtualservices/malairte.git
cd malairte

# CPU node + miner + CLI wallet (no GPU dependencies)
go build -o bin/malairted   ./cmd/malairted
go build -o bin/malairtcli  ./cmd/malairtcli

# Cross-compile (no cgo needed for the CPU build)
GOOS=linux  GOARCH=amd64 go build -o bin/malairted-linux-amd64   ./cmd/malairted
GOOS=darwin GOARCH=arm64 go build -o bin/malairted-darwin-arm64  ./cmd/malairted
```

The bundled [`Makefile`](Makefile) wraps the common targets:

```bash
make build         # node + CLI for the host platform
make build-all     # cross-compile for all release targets
make test          # unit tests
make miner-cuda    # build the CUDA GPU miner (requires nvcc)
```

For the CUDA GPU build, see [`internal/mining/cuda/README.md`](internal/mining/cuda/README.md).

---

## Network parameters

| Parameter | Mainnet value |
| --- | --- |
| Coin name | Malairte Bitcoin |
| Ticker | **MLRT** |
| PoW algorithm | **MLRTHash v1** = double SHA-3-256 (NIST FIPS 202) |
| Block header size | 96 bytes |
| Target block time | **120 seconds (2 minutes)** |
| Difficulty retarget | every 2,016 blocks (~67 hours at target) |
| Initial block reward | **50 MLRT** |
| Halving interval | **210,000 blocks** (~9.6 months at target) |
| Maximum supply | **21,000,000 MLRT** (8 decimals → 2,100,000,000,000,000 atoms) |
| Coinbase maturity | 100 blocks |
| Maximum block size (initial) | 1 MB serialised |
| Median-time-past rule | last 11 blocks |
| Address format | **Base58Check, version byte 50 ("M")** |
| Network magic (mainnet) | **`0x4d4c5254`** ("MLRT") |
| P2P port | **9333** |
| RPC port | **9332** |
| Signature scheme (today) | ECDSA / secp256k1 |
| Signature scheme (MLIP-1) | SLH-DSA-128f-SHAKE-256 (FIPS 205) |
| Protocol fee | 10 atoms per coinbase + per non-coinbase tx (transparent treasury) |
| Genesis | April 2026 — see explorer for exact timestamp + hash |

A canonical, machine-readable summary is served at [malairtebitcoin.com/llms.txt](https://malairtebitcoin.com/llms.txt).

---

## MLRTHash v1 in five lines

```text
serialise(header)  = 96 bytes: version | prevHash | merkleRoot | timestamp | bits | nonce | height
inner              = SHA3-256(serialise(header))             # NIST FIPS 202, Keccak-f[1600]
MLRTHash(header)   = SHA3-256(inner)                         # double application
valid_block        = MLRTHash(header) <= CompactToBig(bits)  # 256-bit big-endian compare
mining_loop        = vary `nonce` (offset 80, 8 bytes) until valid_block
```

### Test vectors

If your implementation produces these three outputs, it is correct.

| Input | `MLRTHash` / `DoubleSHA3-256` (hex) |
| --- | --- |
| `""` (empty) | `a1292c11ccdb876535c6699e8217e1a1294190d83e4233ecc490d32df17a4116` |
| `"abc"` | `f6362cbb9fb8a60f03c2f0d8124d2c6a1a828e2db8e8b05a6f699735b4492cbc` |
| 96 zero bytes | `9dcb0d6ee0ade399575e13eaf305066ec61bc65049b94db86f6badf3ae359744` |

The canonical Go implementation is [`internal/consensus/pow.go`](internal/consensus/pow.go); the byte-for-byte CUDA implementation is [`internal/mining/cuda/mlrt_gpu.cu`](internal/mining/cuda/mlrt_gpu.cu).

---

## Roadmap

**Q2 2026 — Mainnet bootstrap**
- Mainnet genesis, seed-peer infrastructure, signed v1.0 binaries on GitHub Releases
- Block explorer live at [explorer.malairtebitcoin.com](https://explorer.malairtebitcoin.com)
- Mobile wallet **public beta** for iOS and Android
- Whitepaper v1.0 published

**Q3 2026 — Tooling and ecosystem**
- Reference **mining pool** software (open source, stratum-compatible)
- **Hardware wallet** integration (Ledger and/or Trezor app)
- Signed Debian/RPM packages, Homebrew tap, Windows MSI installer
- Public testnet faucet and explorer

**Q4 2026 — Post-quantum signatures (testnet)**
- **MLIP-1** activated on a public testnet: SLH-DSA-128f-SHAKE-256 address type
- Wallet, miner, and explorer support for the new address format
- Independent third-party security audit of MLRTHash + MLIP-1

**2027 — Mainnet MLIP-1 and grants**
- MLIP-1 activation on **mainnet** following at least one halving cycle of testnet exposure
- Ecosystem grants programme funded from the on-chain treasury
- First exchange listings (subject to compliance review)

The live, dated roadmap is at [malairtebitcoin.com/roadmap](https://malairtebitcoin.com/roadmap).

---

## Contributing

Contributions are welcome — code, docs, translations, design, mining-pool operators, all of it.

1. Read [`CONTRIBUTING.md`](CONTRIBUTING.md) *(placeholder — being drafted; PR welcome)*.
2. Read [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) — we follow the Contributor Covenant.
3. Open an issue **before** starting work on anything non-trivial; consensus changes need an MLIP.
4. Sign your commits (`git commit -S`) so we can verify authorship through the PGP web of trust.
5. Run the relevant build/test target locally before opening a PR.

For consensus-level changes, file a Malairte Improvement Proposal in [`docs/mlip/`](docs/mlip/) using `MLIP-0` as the template.

---

## Security

Found a security issue? **Do not open a public GitHub issue.**

- Email **`security@malairte.org`** with a clear description and (if possible) a reproducer.
- Encrypt sensitive reports with the release signing key — fingerprint `3A4B 5C6D 7E8F 9A0B 1C2D 3E4F 5A6B 7C8D 9E0F 1A2B`.
- Expect an acknowledgement within 72 hours and a coordinated-disclosure timeline within 14 days.

The full responsible-disclosure policy lives at [malairtebitcoin.com/security](https://malairtebitcoin.com/security).

---

## License

This repository is licensed under the **Apache License 2.0** — see [`LICENSE`](LICENSE).

> *Placeholder — please confirm the licence choice before the public launch. Apache 2.0 is the current default; some Bitcoin-derived ecosystems prefer MIT, and `httpdocs/llms.txt` currently mentions an "MIT-style" licence. Pick one and we will reconcile both files.*

---

## Links

- **Marketing site:** <https://malairtebitcoin.com>
- **Block explorer:** <https://explorer.malairtebitcoin.com>
- **Whitepaper:** <https://malairtebitcoin.com/whitepaper>
- **Technology / MLRTHash spec:** <https://malairtebitcoin.com/technology>
- **Quantum-security page:** <https://malairtebitcoin.com/quantum-security>
- **Mining guide:** <https://malairtebitcoin.com/mining>
- **Wallet downloads:** <https://malairtebitcoin.com/wallet>
- **Roadmap:** <https://malairtebitcoin.com/roadmap>
- **Treasury transparency:** <https://malairtebitcoin.com/treasury>
- **Fair-launch verification:** <https://malairtebitcoin.com/fair-launch>
- **Security policy:** <https://malairtebitcoin.com/security>
- **Press kit:** <https://malairtebitcoin.com/press-kit>
- **GitHub releases:** <https://github.com/computervirtualservices/malairte/releases>
- **Discord:** <https://discord.gg/malairte>
- **X / Twitter:** <https://x.com/malairtebitcoin>
- **Mastodon:** <https://fosstodon.org/@malairte>

---

<p align="center">
  <sub>Malairte Bitcoin is an independent, EU-jurisdiction project. Cryptocurrency is volatile and experimental — use at your own risk and never invest more than you can afford to lose. Nothing in this README is financial advice.</sub>
</p>

<!-- Keywords: malairte, MLRT, quantum-resistant cryptocurrency, post-quantum bitcoin, MLRTHash, SHA-3 cryptocurrency, fair launch coin, CPU mineable cryptocurrency, GPU mineable coin, SLH-DSA, MLIP-1 -->
