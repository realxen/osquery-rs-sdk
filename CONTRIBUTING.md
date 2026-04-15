# Contributing

Thanks for your interest in improving `osquery-rs-sdk`.

## Development

1. Install Rust and the Apache Thrift compiler, or open the repository in the included devcontainer.
2. Install developer tools:
   ```sh
   make setup
   ```
   This installs `cargo-audit`, `cargo-deny`, and `cargo-nextest`.
3. Run `make test` for the default suite.
4. For integration tests that require a live `osqueryd` socket, run `make test-ignored`.
5. To run all CI checks locally before pushing:
   ```sh
   make check
   ```

Run `make` with any target to see available commands — `fmt`, `lint`, `build`, `test`, `audit`, `deny`, etc.

## Pull requests

Please keep changes focused, include tests when behavior changes, and update documentation when public APIs or workflows change.

## Reporting bugs

Open an issue with reproduction steps, expected behavior, actual behavior, and environment details.
