# briij-cli

`briij-cli` is the XRPL-enabled command-line client for Briij/TextRP flows.

It uses:

- `xrpl-mithril` for wallet operations, transaction building, signing, and verification
- `qrcode` + `qr2term` + `urlencoding` for Xaman deep-link QR flows

## Security model

- Private keys are never written to disk by `briij-cli`.
- `--local-sign` is development-only and always warns at runtime.
- Prefer Xaman signing (`--xaman` or `--qr`) for production use.
- If you provide a seed, do it via environment variables and ephemeral shell sessions.

## Build

From the repository root:

`cargo build -p briij-cli`

## Command overview

Show global help:

`cargo run -p briij-cli -- --help`

### 1) XRPL login

Subcommand:

`login-xrpl --address r... [--xaman | --qr | --local-sign]`

Examples:

- Xaman flow with terminal QR + manual signature fallback:

`cargo run -p briij-cli -- login-xrpl --address rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe --xaman`

- Explicit QR flow:

`cargo run -p briij-cli -- login-xrpl --address rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe --qr`

- Local signing flow (development only):

`BRIIJ_XRPL_SEED='your_seed_here' cargo run -p briij-cli -- login-xrpl --address rYourWallet --local-sign`

- Override challenge endpoint when server exposes a nonstandard path:

`cargo run -p briij-cli -- login-xrpl --address rYourWallet --xaman --challenge-endpoint /_matrix/client/v3/xrpl/challenge`

### 2) Send payment

Build/sign payment without submitting:

`cargo run -p briij-cli -- send --from-address rFrom --to-address rTo --amount-drops 1000000 --sequence 1 --fee-drops 12 --last-ledger-sequence 99999999 --seed your_seed_here --algorithm secp256k1`

Submit and wait for validation:

`cargo run -p briij-cli -- send --from-address rFrom --to-address rTo --amount-drops 1000000 --seed your_seed_here --submit --rpc-url https://s.altnet.rippletest.net:51234`

### 3) Pay (trust-aware)

Pay with trust check enabled:

`cargo run -p briij-cli -- pay --payer rPayer --payee rPayee --amount-drops 2000000 --access-token your_matrix_token --seed your_seed_here --submit`

Pay while skipping trust check:

`cargo run -p briij-cli -- pay --payer rPayer --payee rPayee --amount-drops 2000000 --skip-trust-check --seed your_seed_here`

### 4) Verify transaction hash

`cargo run -p briij-cli -- verify --tx-hash E08D6E9754025BA2534A78707605E0601F03ACE063687A0CA1BDDACFCD1698C7 --rpc-url https://s1.ripple.com:51234`

## QR screenshot examples

Xaman deep-link QR sample:

![Xaman deep-link QR example](docs/qr_xaman_deeplink_example.svg)

Fallback challenge QR sample:

![Xaman challenge fallback QR example](docs/qr_xaman_challenge_fallback_example.svg)

To regenerate these QR images:

`cargo run -p briij-cli --example generate_qr_screenshots`
