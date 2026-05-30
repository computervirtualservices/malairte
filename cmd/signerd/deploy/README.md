# signerd — server deploy

Turnkey install for a Linux host (e.g. the malairte source at `/opt/malairted-src`).

```bash
cd /opt/malairted-src
git fetch origin && git checkout feat/signer-derive-service   # or main once merged
sudo ./cmd/signerd/deploy/deploy.sh
```

`deploy.sh` builds the binary, creates the `signer` system user, installs the
hardened systemd unit, and drops an env template at `/etc/signerd/env` (only if
one doesn't already exist). It does **not** start the service.

Then:

```bash
sudo vi /etc/signerd/env            # SIGNER_TOKEN, MLRT_ACCOUNT_XPUB, self-test
sudo systemctl enable --now signerd
sudo systemctl status signerd
```

## Prerequisite

`signerd` refuses to start without `MLRT_ACCOUNT_XPUB`. Generate the seed
**offline**, derive the account xpub for `m/44'/<mlrt>'/0'`, and confirm it
derives the live reserve `MCUFXHADb1n5WmdCYde6gDYWcspTL6uvHR` before deploying.

## Network

- `SIGNER_BIND_ADDR=127.0.0.1:8088` if CoinDock runs on the same host.
- Otherwise bind the private interface and firewall it to the CoinDock app host
  only. Never bind `0.0.0.0` / expose publicly.

## CoinDock wiring

On the CoinDock app (`.env`):

```dotenv
COINDOCK_SIGNER_URL=http://<host-or-127.0.0.1>:8088
COINDOCK_SIGNER_TOKEN=<same as SIGNER_TOKEN>
```

then `php artisan config:cache`.

See [../README.md](../README.md) for the full service/API reference.
