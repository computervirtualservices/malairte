# signerd-keygen — offline MLRT_ACCOUNT_XPUB generator

Generates the BIP39 mnemonic + BIP44 **account xpub** that the CoinDock signer
(`signerd`) needs as `MLRT_ACCOUNT_XPUB`.

> **Run this on an OFFLINE machine.** It prints a secret recovery mnemonic that
> controls all derived funds. Write it on paper, store it securely, and never
> paste it anywhere online. Only the **xpub** (public) and the self-test values
> go into the signer config — the mnemonic/seed never leave your control.

## Build

```bash
cd /opt/malairted-src        # the malairte module root
go build -o signerd-keygen ./cmd/signerd-keygen
```

## Generate a new wallet

```bash
./signerd-keygen                 # 24-word mnemonic, path m/44'/0'/0'
```

Output gives you, ready to paste into `/etc/signerd/env`:

```
MLRT_ACCOUNT_XPUB=xpub6C...
MLRT_ADDRESS_VERSION=50
MLRT_SELFTEST_INDEX=1
MLRT_SELFTEST_ADDRESS=M...
```

`signerd` re-derives the self-test address at boot and refuses to start if it
doesn't match — so a wrong xpub or path can never go live.

## Options

| Flag | Default | Meaning |
|------|---------|---------|
| `--words` | `24` | New-wallet mnemonic length (`12` or `24`) |
| `--import "w1 w2 …"` | — | Re-derive the xpub from an existing mnemonic (does not reprint it) |
| `--passphrase` | empty | Optional BIP39 passphrase (25th word) — must be remembered exactly |
| `--coin-type` | `0` | BIP44 coin type. The MLRT wallet app uses `0` |
| `--account` | `0` | BIP44 account index |
| `--change` | `0` | Change level used for deposit addresses (signerd default `0`) |
| `--self-test-index` | `1` | Address index to print for the boot self-test |
| `--address-version` | `50` | Base58 version byte: `50` mainnet `M…`, `111` testnet `m…` |

The derivation path is `m/44'/<coin-type>'/<account>'`; deposit addresses are
`<change>/<user_id>` beneath the account xpub — matching `signerd`'s defaults.

## Correctness

The derivation is validated against the canonical BIP39 and BIP32 specification
test vectors, **and** against the wider ecosystem: the well-known
`abandon … about` mnemonic at `m/44'/0'/0'/0/0` reproduces the same HASH160 as
standard wallets (see `internal/hdwallet/*_test.go`). The generator also derives
the self-test address twice — once via the private chain and once via the public
xpub (the exact code path `signerd` uses) — and aborts if they disagree.

## Recovery

To recover or move the wallet, re-run with `--import "<your mnemonic>"` (plus the
same `--passphrase`/`--coin-type`/`--account`): it reproduces the identical xpub.
The mnemonic is also importable into the NBitcoin-based MLRT wallet app (same
BIP39/BIP44 standard).
