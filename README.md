# osquery-rs-sdk

A Rust SDK for building [osquery](https://osquery.io) extensions. Create custom tables, loggers, config providers, and distributed query handlers as native Rust binaries that plug into `osqueryd` or `osqueryi`.

## Features

- **Table plugins** -- Create custom virtual tables queryable with SQL
- **Logger plugins** -- Implement custom logging backends for osquery events and results
- **Config plugins** -- Provide dynamic configuration sources for osquery
- **Distributed plugins** -- Handle distributed query scheduling and result collection
- **Client API** -- Connect to a running osquery instance and execute queries from Rust
- **Mock support** -- First-class mocks for unit testing extensions without a live osquery
- **Builder API** -- Configure extensions with version strings, timeouts, and ping intervals
- **Cross-platform** -- Unix sockets on Linux/macOS and named pipes on Windows
- **Pure Rust** -- No C/C++ dependencies, built on the Thrift protocol
- **Minimal footprint** -- Thin layer over osquery's extension API with zero unnecessary overhead

## Quick start

Add the dependency to your `Cargo.toml`:

```toml
[dependencies]
osquery-rs-sdk = "0.1"
```

### Query a running osquery instance

```rust
fn main() -> osquery_rs_sdk::Result<()> {
    let mut client = osquery_rs_sdk::ExtensionManagerClient::connect()?;
    let rows = client.query_rows("SELECT * FROM users LIMIT 5")?;
    println!("{rows:?}");
    Ok(())
}
```

### Create a custom table

```rust
use osquery_rs_sdk::{
    ColumnDefinition, ExtensionManagerServer, QueryContext, Result, Table, TablePlugin,
};
use std::collections::BTreeMap;

fn main() -> Result<()> {
    let mut server = ExtensionManagerServer::new("my_extension", "/var/osquery/osquery.em")?;
    server.register_plugin(TablePlugin::new("my_table", columns(), generate))?;
    server.run()
}

fn columns() -> Vec<ColumnDefinition> {
    vec![
        ColumnDefinition::text("name"),
        ColumnDefinition::integer("age"),
    ]
}

fn generate(_ctx: QueryContext) -> Result<Table> {
    Ok(vec![BTreeMap::from([
        ("name".into(), "Alice".into()),
        ("age".into(), "30".into()),
    ])])
}
```

### Create a logger plugin

```rust
use osquery_rs_sdk::{ExtensionManagerServer, LogType, LoggerPlugin, Result};

fn main() -> Result<()> {
    let mut server = ExtensionManagerServer::new("my_logger", "/var/osquery/osquery.em")?;
    server.register_plugin(LoggerPlugin::new("my_logger", log_string))?;
    server.run()
}

fn log_string(typ: LogType, message: &str) -> Result<()> {
    println!("{typ}: {message}");
    Ok(())
}
```

### Create a config plugin

```rust
use osquery_rs_sdk::{ConfigPlugin, ExtensionManagerServer, Result};
use std::collections::BTreeMap;

fn main() -> Result<()> {
    let mut server = ExtensionManagerServer::new("my_config", "/var/osquery/osquery.em")?;
    server.register_plugin(ConfigPlugin::new("my_config", generate_config))?;
    server.run()
}

fn generate_config() -> Result<BTreeMap<String, String>> {
    Ok(BTreeMap::from([(
        "config1".into(),
        r#"{"schedule": {"info": {"query": "SELECT * FROM osquery_info;", "interval": 60}}}"#.into(),
    )]))
}
```

### Use the builder for advanced configuration

```rust
use osquery_rs_sdk::ExtensionManagerServer;
use std::time::Duration;

let server = ExtensionManagerServer::builder("my_ext", "/var/osquery/osquery.em")
    .version("1.0.0")
    .ping_interval(Duration::from_secs(10))
    .build()
    .unwrap();
```

## Feature flags

| Flag | Default | Description |
|------|---------|-------------|
| `client` | -- | Client-only API for querying osquery |
| `server` | yes | Extension server (includes `client`) |
| `plugins` | yes | Table, logger, config, and distributed plugins (includes `server`) |
| `mock` | -- | Mock implementations for testing |
| `tracing` | -- | Structured logging via the `tracing` crate |

## Loading extensions with osqueryd

1. Build your extension and rename it with the `.ext` suffix:

```bash
cargo build --release --example table
cp target/release/examples/table target/release/examples/table.ext
```

2. Ensure the directory is only writable by the osqueryd user (typically root):

```bash
sudo chown -R root /usr/local/osquery_extensions/
sudo cp target/release/examples/table.ext /usr/local/osquery_extensions/
```

3. Create an `extensions.load` file listing your extension:

```bash
echo "/usr/local/osquery_extensions/table.ext" > /tmp/extensions.load
```

4. Start osqueryd with autoloading:

```bash
sudo osqueryd --extensions_autoload=/tmp/extensions.load --verbose
```

## Testing

```bash
# Unit tests (no osquery required)
cargo test

# Full suite including integration tests (requires osqueryd)
cargo test -- --include-ignored
```

## Dev container

The repository includes a `.devcontainer/` setup that installs Rust, the Thrift compiler, and `osqueryd` inside the container. The daemon starts automatically on the standard socket path (`/var/osquery/osquery.em`), so the full test suite works out of the box:

```bash
cargo test --all-features -- --include-ignored
```

Restart the daemon manually if needed:

```bash
.devcontainer/scripts/stop-osqueryd.sh
.devcontainer/scripts/start-osqueryd.sh
```

## Security

Please see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)

## Acknowledgments

This project was influenced by [osquery-go](https://github.com/osquery/osquery-go).
