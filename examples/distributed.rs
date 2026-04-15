#![allow(
    clippy::print_stdout,
    clippy::unnecessary_wraps,
    clippy::needless_pass_by_value
)]

use osquery_rs_sdk::{
    DistributedPlugin, ExtensionManagerServer, QueriesRequest, QueryResponse, Result,
};
use std::collections::BTreeMap;

#[cfg(unix)]
const OSQUERY_SOCKET: &str = "/var/osquery/osquery.em";
#[cfg(windows)]
const OSQUERY_SOCKET: &str = r"\\.\pipe\osquery.em";

fn main() -> Result<()> {
    let mut server = ExtensionManagerServer::new("example_distributed", OSQUERY_SOCKET)?;
    server.register_plugin(DistributedPlugin::new(
        "example_distributed",
        get_queries,
        write_results,
    ))?;
    server.run()
}

fn get_queries() -> Result<QueriesRequest> {
    Ok(QueriesRequest::new(BTreeMap::from([(
        "time".to_string(),
        "select * from time".to_string(),
    )])))
}

fn write_results(query_resp: Vec<QueryResponse>) -> Result<()> {
    println!("{query_resp:?}");
    Ok(())
}
