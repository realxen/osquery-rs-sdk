# osquery-rs

[osquery](https://github.com/osquery/osquery) exposes an operating system as a high-performance relational database. This allows you to write SQL-based queries to explore operating system data. With osquery, SQL tables represent abstract concepts such as running processes, loaded kernel modules, open network connections, browser plugins, hardware events, or file hashes.

If you're interested in learning more about osquery, visit the [GitHub project](https://github.com/osquery/osquery), the [website](https://osquery.io), and the [user guide](https://osquery.readthedocs.io).

## What is osquery-rs?

In osquery, SQL tables, configuration retrieval, log handling, and similar behaviors are implemented through a plugin and extensions API. This project contains Rust bindings for creating osquery extensions in Rust. To create an extension, build an executable that instantiates an `ExtensionManagerServer` and registers the plugins you want to expose to osquery. You can then load that extension in either `osqueryd` or `osqueryi`. For more background, see the osquery [extension documentation](https://osquery.readthedocs.io/en/latest/deployment/extensions/).

## Building

```bash
cargo build
```

## Testing

```bash
cargo test
```

Tests that require a live `osqueryd` extension socket are ignored by default. Run them explicitly with `cargo test -- --ignored` when an osquery extension manager is available at the standard socket path.

## Dev Container

The repository includes a `.devcontainer/` setup for VS Code and GitHub Codespaces-style workflows. It installs Rust tooling, the Apache Thrift compiler, and a Linux `osqueryd` package inside the container.

When the dev container starts, it automatically launches `osqueryd` on the standard Unix socket path expected by the crate:

```bash
/var/osquery/osquery.em
```

That means the full test suite can be run inside the container without `sudo`:

```bash
cargo test
cargo test -- --ignored
```

If you need to restart the daemon manually:

```bash
.devcontainer/scripts/stop-osqueryd.sh
.devcontainer/scripts/start-osqueryd.sh
```

## Using the library

### Execute queries in Rust

This library can also be used to create a Rust client for the `osqueryd` or `osqueryi` extension socket. You can use this to execute osquery queries from a Rust program. For example:

```rust
fn main() {
    let mut client = osquery_rs::ExtensionManagerClient::new().unwrap();
    let resp = client.query("SELECT * FROM users").unwrap();
    println!("Got results {:?}", resp.response.unwrap());
}
```

### Loading extensions with osqueryd

If you write an extension with a logger or config plugin, you'll likely want to autoload the extensions when `osqueryd` starts. `osqueryd` has a few requirements for autoloading extensions, documented on the [wiki](https://osquery.readthedocs.io/en/latest/deployment/extensions/). Here's a quick example using a logging plugin to get you started:

1. Build the example plugin and rename it with the `.ext` extension expected by osqueryd.

```bash
cargo build --example logger
mv ./target/debug/examples/logger ./target/debug/examples/logger.ext
```

2. Set the correct permissions on the file and directory. If `osqueryd` runs as root, the directory for the extension must only be writable by root.

```bash
sudo chown -R root /usr/local/osquery_extensions/
```

3. Create an `extensions.load` file with the path of your extension.

```bash
echo "/usr/local/osquery_extensions/logger.ext" > /tmp/extensions.load
```

4. Start `osqueryd` with the `--extensions_autoload` flag.

```bash
sudo osqueryd --extensions_autoload=/tmp/extensions.load --logger_plugin=logger --verbose
```

## Examples

```bash
cargo build --example ${plugin_name} && mv ./target/debug/examples/${plugin_name} ./target/debug/examples/${plugin_name}.ext
echo "$PWD/target/debug/examples/${plugin_name}.ext" > /tmp/extensions.load
osqueryd --extensions_autoload=/tmp/extensions.load --distributed_plugin=${plugin_name} --verbose --disable_distributed=false
```

## Vulnerabilities

If you find a vulnerability in this software, please report it privately through GitHub Security Advisories or contact the maintainer directly.

## Acknowledgments

This project was heavily influenced by the implementation of [osquery-go](https://github.com/osquery/osquery-go).
