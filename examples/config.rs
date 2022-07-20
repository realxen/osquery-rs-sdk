use osquery_rs::{plugin::config::ConfigPlugin, ExtensionManagerServer, Result};
use std::collections::BTreeMap;

#[cfg(unix)]
const OSQUERY_SOCKET: &str = "/var/osquery/osquery.em";
#[cfg(windows)]
const OSQUERY_SOCKET: &str = r"\\.\pipe\osquery.em";

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

fn main() -> Result<()> {
    let mut server = ExtensionManagerServer::new("example_extension", OSQUERY_SOCKET)?;
    server.register_plugin(ConfigPlugin::new("example_config", generate_configs))?;
    server.run()
}
