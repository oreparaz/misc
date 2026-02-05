# blocktime

Tiny C program that fetches the latest block, validates it (header, tx parsing, merkle root, PoW), and prints the block height and time. It also runs a built-in genesis self-test on every run.

## Build

```sh
make
```

## Run

Fetch + validate tip block:

```sh
./blockclock
```

Self-test only (no output; exits nonzero on failure):

```sh
./blockclock --selftest
```

## What validation does

- Parses the block and all transactions with strict bounds checks.
- Computes txids (segwit-aware), recomputes the merkle root, and compares to the header.
- Verifies header PoW against the compact target (`bits`).
- Enforces a minimum PoW floor: block hash must have at least `MIN_POW_LEADING_ZERO_BITS` leading zero bits.

## How it works

`main.c` fetches the tip height and block hash from Blockstream's public API and downloads the raw block bytes using `curl`. It then calls `validate_block_and_get_time(...)` in `blockclock.c`, which performs the parsing and validation and returns the header timestamp.
