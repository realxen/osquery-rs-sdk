#![allow(clippy::unnecessary_wraps)]

use osquery_rs_sdk::{ConfigPlugin, ExtensionManagerServer, Result};
use std::collections::BTreeMap;

#[cfg(unix)]
const OSQUERY_SOCKET: &str = "/var/osquery/osquery.em";
#[cfg(windows)]
const OSQUERY_SOCKET: &str = r"\\.\pipe\osquery.em";

/// Return the main osquery configuration.
///
/// The map keys are source names and values are JSON config strings.
/// osquery merges all sources into a single configuration.
fn generate_configs() -> Result<BTreeMap<String, String>> {
    Ok(BTreeMap::from([(
        String::from("config1"),
        String::from(
            r#"
            {
                "options": {
                  "host_identifier": "hostname",
                  "schedule_splay_percent": 10
                },
                "schedule": {
                  "macos_kextstat": {
                    "query": "SELECT * FROM kernel_extensions;",
                    "interval": 10
                  },
                  "foobar": {
                    "query": "SELECT foo, bar, pid FROM foobar_table;",
                    "interval": 600
                  }
                }
              }
        "#,
        ),
    )]))
}

/// Generate a query pack on demand.
///
/// osquery calls this when the main config references a pack that should be
/// resolved by this extension. The `name` is the pack identifier and `value`
/// is an opaque string the config associated with it (e.g. a file path, URL,
/// or lookup key).
///
/// The return value should be a JSON string describing the pack's queries.
fn generate_pack(name: &str, _value: &str) -> Result<String> {
    match name {
        "incident_response" => Ok(String::from(
            r#"{
                "queries": {
                    "processes": {
                        "query": "SELECT * FROM processes;",
                        "interval": 60
                    },
                    "open_files": {
                        "query": "SELECT * FROM open_files WHERE pid IN (SELECT pid FROM processes);",
                        "interval": 300
                    }
                }
            }"#,
        )),
        "compliance" => Ok(String::from(
            r#"{
                "queries": {
                    "sshd_config": {
                        "query": "SELECT * FROM sshd_config;",
                        "interval": 3600
                    }
                }
            }"#,
        )),
        _ => Err(format!("unknown pack: {name}").into()),
    }
}

fn main() -> Result<()> {
    let mut server = ExtensionManagerServer::new("example_extension", OSQUERY_SOCKET)?;
    server.register_plugin(
        ConfigPlugin::new("example_config", generate_configs).with_gen_pack(generate_pack),
    )?;
    // Automatically handles SIGINT/SIGTERM (Unix) or Ctrl+C (Windows)
    server.run_with_signal_handling()
}
