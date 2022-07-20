use osquery_rs::{
    plugin::distributed::{DistributedPlugin, QueriesResquest, QueryResponse},
    ExtensionManagerServer, Result,
};
use std::collections::BTreeMap;

#[cfg(unix)]
const OSQUERY_SOCKET: &str = "/var/osquery/osquery.em";
#[cfg(windows)]
const OSQUERY_SOCKET: &str = r"\\.\pipe\osquery.em";

fn main() -> Result<()> {
    let mut server = ExtensionManagerServer::new("example_distributed", OSQUERY_SOCKET).unwrap();
    server.register_plugin(DistributedPlugin::new(
        "example_distributed",
        get_queries,
        write_results,
    ))?;
    server.run()
}

fn get_queries() -> Result<QueriesResquest> {
    Ok(QueriesResquest::new(BTreeMap::from([(
        "time".to_string(),
        "select * from time".to_string(),
    )])))
}

fn write_results(query_resp: Vec<QueryResponse>) -> Result<()> {
    println!("{:?}", query_resp);
    Ok(())
}
