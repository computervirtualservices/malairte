# signerd — CoinDock signer / deriver service

Implements **Phase 1** of the CoinDock signer contract
(`coindock` repo → `docs/coindock-online/api/03-signer-service-api.md`):
watch-only **MLRT deposit-address derivation** from an account **xpub**.

It holds **no private keys**. `POST /v1/sign` returns `501` and stays disabled
until the gated signing phase (security review + pen test + launch sign-off per
`00-master-orchestration.md`).

Built as a third binary inside the `github.com/computervirtualservices/malairte`
module so it reuses the node's audited crypto (`internal/crypto` address
encoding) and the same secp256k1 implementation it signs with.

## Endpoints

| Method & path     | Auth          | Result                                   |
| ----------------- | ------------- | ---------------------------------------- |
| `POST /v1/derive` | Bearer token  | `{ "address": "M…" }`                     |
| `POST /v1/sign`   | Bearer token  | `501 not_implemented` (this build)        |
| `GET  /v1/health` | none          | `200 { "status": "ok" }` (readiness)      |

```bash
curl -s -H "Authorization: Bearer $SIGNER_TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"chain":"MLRT","index":42}' \
     http://127.0.0.1:8088/v1/derive
# {"address":"M..."}
```

`index` is CoinDock's per-user BIP44 address index (the user id). The service
derives `<MLRT_BIP44_CHANGE>/<index>` beneath the account xpub.

## Configuration (environment only)

| Var                     | Required | Default            | Notes                                                        |
| ----------------------- | -------- | ------------------ | ------------------------------------------------------------ |
| `SIGNER_BIND_ADDR`      | no       | `127.0.0.1:8088`   | **Bind to a private interface only.** Never expose publicly. |
| `SIGNER_TOKEN`          | **yes**  | —                  | Bearer token; must equal CoinDock's `COINDOCK_SIGNER_TOKEN`. ≥ 24 chars. |
| `MLRT_ACCOUNT_XPUB`     | **yes**  | —                  | BIP32 account **xpub** (public) for `m/44'/<mlrt>'/0'`.       |
| `MLRT_BIP44_CHANGE`     | no       | `0`                | Change level derived before the index.                       |
| `MLRT_ADDRESS_VERSION`  | no       | `50`               | Base58 version byte: `50`=mainnet `M…`, `111`=testnet `m…`.   |
| `MLRT_SELFTEST_INDEX`   | no       | —                  | If set with the address below, verified at boot.             |
| `MLRT_SELFTEST_ADDRESS` | no       | —                  | Expected address for the self-test index; mismatch ⇒ refuse to start. |

> **Keys never touch this repo or this service.** Only the **public** account
> xpub is provided. Generate the seed offline, in your secure environment, and
> derive the account xpub from it there.

## Boot self-test (strongly recommended)

Set `MLRT_SELFTEST_INDEX` + `MLRT_SELFTEST_ADDRESS` to a deposit address you
have independently verified (e.g. via the MLRT wallet / `malairte-cli`) belongs
to that index under your xpub. If derivation doesn't reproduce it, the service
**refuses to start** — preventing it from ever handing out wrong (unspendable)
addresses because of a mismatched xpub or derivation path.

The contract also notes the account xpub must derive the live reserve address
`MCUFXHADb1n5WmdCYde6gDYWcspTL6uvHR` somewhere in its tree — confirm that before
trusting the xpub in production.

## Run

```bash
# from the blockchain-app module root
go build -o signerd ./cmd/signerd

export SIGNER_BIND_ADDR=127.0.0.1:8088
export SIGNER_TOKEN='<long-random-secret>'
export MLRT_ACCOUNT_XPUB='<your-account-xpub>'
# optional safety:
export MLRT_SELFTEST_INDEX=1
export MLRT_SELFTEST_ADDRESS='<address for index 1>'
./signerd
```

Docker:

```bash
docker build -f cmd/signerd/Dockerfile -t coindock/signerd:dev .
docker run --rm -p 127.0.0.1:8088:8088 \
  -e SIGNER_TOKEN=… -e MLRT_ACCOUNT_XPUB=… \
  coindock/signerd:dev
```

## Wire CoinDock to it

On the Laravel side (`config/coindock.php` → `signer`):

```dotenv
COINDOCK_SIGNER_URL=http://<private-host>:8088
COINDOCK_SIGNER_TOKEN=<same value as SIGNER_TOKEN>
COINDOCK_SIGNER_TIMEOUT=15
```

Then "Show address" on the wallet page resolves via `POST /v1/derive`.

## Tests

```bash
go test ./internal/signer/...
```

`bip32_test.go` proves CKDpub against the canonical BIP32 spec test vectors;
`server_test.go` covers auth, validation, the derive happy path, the `501` sign
response, and the boot self-test.

## Not in this build

- `POST /v1/sign` (withdrawal signing) — gated, later phase.
- ETH / TRON derivation — returns `501 unsupported_chain`; needs keccak/Tron
  address encoding (no reusable code in the node today).
