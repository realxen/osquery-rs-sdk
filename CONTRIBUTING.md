# Contributing

Thanks for your interest in improving `osquery-rs-sdk`.

## Development

1. Install Rust and the Apache Thrift compiler, or open the repository in the included devcontainer.
2. Run `cargo test` for the default suite.
3. For integration tests that require a live `osqueryd` socket, run `cargo test -- --ignored`.

## Pull requests

Please keep changes focused, include tests when behavior changes, and update documentation when public APIs or workflows change.

## Reporting bugs

Open an issue with reproduction steps, expected behavior, actual behavior, and environment details.
