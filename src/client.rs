use crate::{osquery, transport};
use std::collections::BTreeMap;
use thrift::Error;

// ExtensionManagerClient is a wrapper for the osquery Thrift extensions API.
pub struct ExtensionManagerClient {
    client: Box<dyn osquery::TExtensionManagerSyncClient>,
}

// ExtensionManagerClient is a wrapper for the osquery Thrift extensions API.
impl ExtensionManagerClient {
    // creates a new client communicating to osquery over the default socket path.
    pub fn new() -> thrift::Result<Self> {
        #[cfg(unix)]
        return Self::new_with_path("/var/osquery/osquery.em");
        #[cfg(windows)]
        return Self::new_with_path(r"\\.\pipe\osquery.em");
    }

    // creates a new client communicating to osquery over the provided socket path.
    pub fn new_with_path(path: &str) -> thrift::Result<Self> {
        let (protocol_in, protocol_out) = transport::bind(path)?;
        Ok(Self {
            client: Box::new(osquery::ExtensionManagerSyncClient::new(
                protocol_in,
                protocol_out,
            )),
        })
    }

    // shutdown should be called to close the transport when use of the client is completed.
    pub fn shutdown(&mut self) -> thrift::Result<()> {
        self.client.shutdown()
    }

    // query requests a query to be run and returns the extension response.
    // Consider using the QueryRow or QueryRows helpers for a more friendly
    // interface.
    pub fn query(&mut self, sql: &str) -> thrift::Result<osquery::ExtensionResponse> {
        self.client.query(String::from(sql))
    }

    // query_rows is a helper that executes the requested query and returns the results.
    // It handles checking both the transport level errors and the osquery internal errors
    // by returning a normal Go error type.
    pub fn query_rows(&mut self, sql: &str) -> thrift::Result<Vec<BTreeMap<String, String>>> {
        let res = self
            .client
            .query(String::from(sql))
            .map_err(|err| Error::from(format!("transport error in query: {}", err)))?;

        // (Error::from("no response returned in query"))
        let status = res.status.unwrap_or_default();
        match status.code {
            None => Err(Error::from("query returned nil status")),
            Some(0) => Ok(res.response.unwrap_or_default()),
            _ => Err(Error::from(format!(
                "query returned error: {}",
                status.message.unwrap_or_default()
            ))),
        }
    }

    // query_row behaves similarly to query_rows, but it returns an error if the query
    // does not return exactly one row.
    pub fn query_row(&mut self, sql: &str) -> thrift::Result<BTreeMap<String, String>> {
        let res = self.query_rows(sql)?;
        match res.len() {
            1 => Ok(res.into_iter().next().unwrap()),
            _ => Err(Error::from(format!("expected 1 row, got {}", res.len()))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[cfg(unix)]
    pub static TEST_SOCKET: &str = "/var/osquery/osquery.em";
    #[cfg(windows)]
    pub static TEST_SOCKET: &str = r"\\.\pipe\osquery.em";

    #[test]
    fn query() {
        assert!(
            Path::new(TEST_SOCKET).exists(),
            "Socket path is not avaible, run osqueryd"
        );
        let mut client = ExtensionManagerClient::new().unwrap();
        if let Ok(res) = client.query("SELECT * FROM users") {
            assert!(
                res.status.unwrap().code == Some(0),
                "Status code should be Ok"
            );
        }
    }

    #[test]
    fn query_rows() {
        let mut client = ExtensionManagerClient::new().unwrap();
        client.query_rows("SELECT * FROM users").unwrap();
    }

    #[test]
    fn query_row() {
        let mut client = ExtensionManagerClient::new().unwrap();
        client.query_row("SELECT * FROM users limit 1").unwrap();
    }
}
