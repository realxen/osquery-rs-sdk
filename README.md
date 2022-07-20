# osquery-rs

[`osquery`](https://github.com/facebook/`osquery`) exposes an operating system as a high-performance relational database. This allows you to write SQL-based queries to explore operating system data. With `osquery`, SQL tables represent abstract concepts such as running processes, loaded kernel modules, open network connections, browser plugins, hardware events or file hashes.

If you're interested in learning more about `osquery`, visit the [GitHub project](https://github.com/`osquery`/`osquery`), the [website](https://`osquery`.io), and the [users guide](https://`osquery`.readthedocs.io).

## What is osquery-rs?

In `osquery`, SQL tables, configuration retrieval, log handling, etc. are implemented via a robust plugin and extensions API. This project contains Rust bindings for creating `osquery` extensions in Rust. To create an extension, you must create an executable binary which instantiates an `ExtensionManagerServer` and registers the plugins that you would like to be added to `osquery`. You can then have `osquery` load the extension in your desired context (ie: in a long running instance of `osqueryd` or during an interactive query session with `osqueryi`). For more information about how this process works at a lower level, see the `osquery` [wiki](https://`osquery`.readthedocs.io/en/latest/development/`osquery`-sdk/).

## Using the library

### Execute queries in Rust

This library can also be used to create a Rust client for the `osqueryd` or` osqueryi` extension socket. You can use this to add the ability to performantly execute `osquery` queries in your Rust program. Consider the following example:

```rust
fn main() {
    let mut client = osquery_rs::client::ExtensionManagerClient::default();
    let resp = client.query("Select * from Users").unwrap();
    println!("Got results {:?}", resp.response.unwrap());
}
```

### Loading extensions with osqueryd

If you write an extension with a logger or config plugin, you'll likely want to autoload the extensions when `osqueryd` starts. `osqueryd` has a few requirements for autoloading extensions, documented on the [wiki](https://osquery.readthedocs.io/en/latest/deployment/extensions/). Here's a quick example using a logging plugin to get you started:

1. Build the plugin. Make sure to add `.ext` as the file extension. It is required by osqueryd.
```cargo build -- my_logger.ext```

2. Set the correct permissions on the file and directory. If `osqueryd` runs as root, the directory for the extension must only be writable by root.

```
sudo chown -R root /usr/local/osquery_extensions/
```

3. Create an `extensions.load` file with the path of your extension.

```
echo "/usr/local/osquery_extensions/my_logger.ext" > /tmp/extensions.load
```

4. Start `osqueryd` with the `--extensions_autoload` flag.

```
sudo osqueryd --extensions_autoload=/tmp/extensions.load --logger-plugin=my_logger -verbose
```

## Examples

```bash
cargo build --example ${plugin_name} && mv ./target/debug/examples/${plugin_name} ./target/debug/examples/${plugin_name}.ext
echo "${pwd}/target/debug/examples/${plugin_name}.ext" > /tmp/extensions.load
osqueryd --extensions_autoload=/tmp/extensions.load --distributed_plugin=${plugin_name} -verbose --disable_distributed=false
```

## Vulnerabilities

If you find a vulnerability in this software, please email [security@alphaguard.io](mailto:security@alphaguard.io).

## Acknowledgments

This project was heavily influenced by the implementation of [osquery-go](https://github.com/osquery/osquery-go).