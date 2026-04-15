#![allow(clippy::print_stdout, clippy::unnecessary_wraps)]

use osquery_rs_sdk::{ExtensionManagerServer, LogType, LoggerPlugin, Result};

#[cfg(unix)]
const OSQUERY_SOCKET: &str = "/var/osquery/osquery.em";
#[cfg(windows)]
const OSQUERY_SOCKET: &str = r"\\.\pipe\osquery.em";

fn main() -> Result<()> {
    let mut server = ExtensionManagerServer::new("my_logger", OSQUERY_SOCKET)?;
    server.register_plugin(LoggerPlugin::new("my_logger", log_string))?;
    server.run()
}

fn log_string(typ: LogType, log_text: &str) -> Result<()> {
    println!("{typ}: {log_text}");
    Ok(())
}
