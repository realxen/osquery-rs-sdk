use crate::osquery;
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, Mutex},
};
use thrift::{
    protocol::{TBinaryInputProtocol, TBinaryOutputProtocol, TInputProtocol, TOutputProtocol},
    transport::{TBufferedReadTransport, TBufferedWriteTransport},
    Result as TResult,
};

#[cfg(unix)]
type TClient = std::os::unix::net::UnixStream;
#[cfg(windows)]
type TClient = super::named_pipe::NamedPipeClient;

/// ExtensionManager represents an extension manager, which handles the
/// communication with the osquery core process.
pub trait ExtensionManager: Send + Sync {
    /// ping requests metadata from the extension manager.
    fn ping(&mut self) -> TResult<osquery::ExtensionStatus>;
    /// call requests a call to an extension (or core) registry plugin.
    fn call(
        &mut self,
        registry: String,
        item: String,
        request: osquery::ExtensionPluginRequest,
    ) -> TResult<osquery::ExtensionResponse>;
    /// shutdown should be called to close the transport when use of the client is completed.
    fn shutdown(&mut self) -> TResult<()>;
    /// extensions requests the list of active registered extensions.
    fn extensions(&mut self) -> TResult<osquery::InternalExtensionList>;
    /// options requests the list of bootstrap or configuration options.
    fn options(&mut self) -> TResult<osquery::InternalOptionList>;
    /// register_extension registers the extension plugins with the osquery process.
    fn register_extension(
        &mut self,
        info: osquery::InternalExtensionInfo,
        registry: osquery::ExtensionRegistry,
    ) -> TResult<osquery::ExtensionStatus>;
    /// deregister_extension de-registers the extension plugins with the osquery process.
    fn deregister_extension(
        &mut self,
        uuid: osquery::ExtensionRouteUUID,
    ) -> TResult<osquery::ExtensionStatus>;
    /// query requests a query to be run and returns the extension response.
    fn query(&mut self, sql: String) -> TResult<osquery::ExtensionResponse>;
    /// get_query_columns requests the columns returned by the parsed query.
    fn get_query_columns(&mut self, sql: String) -> TResult<osquery::ExtensionResponse>;
}

/// ExtensionManagerClient is a wrapper for the osquery Thrift extensions API.
pub struct ExtensionManagerClient {
    client: Arc<Mutex<dyn osquery::TExtensionManagerSyncClient + Send + Sync>>,
}

/// ExtensionManagerClient is a wrapper for the osquery Thrift extensions API.
impl ExtensionManagerClient {
    /// creates a new client communicating to osquery over the default socket path.
    pub fn new() -> TResult<Self> {
        #[cfg(unix)]
        return Self::new_with_path("/var/osquery/osquery.em");
        #[cfg(windows)]
        return Self::new_with_path(r"\\.\pipe\osquery.em");
    }

    /// create a new client communicating to osquery over the provided socket path.
    /// by default it will use a `TBinary` protocol with a `TBuffered` transport
    pub fn new_with_path<P: AsRef<Path>>(path: P) -> TResult<Self> {
        let client = TClient::connect(&path)
            .map_err(|e| format!("connecting to {}: {}", path.as_ref().display(), e))?;

        let transport_in = TBufferedReadTransport::new(client.try_clone().unwrap());
        let transport_out = TBufferedWriteTransport::new(client.try_clone().unwrap());
        let protocol_in = Box::new(TBinaryInputProtocol::new(transport_in, false));
        let protocol_out = Box::new(TBinaryOutputProtocol::new(transport_out, true));

        Ok(Self::new_with_proto(protocol_in, protocol_out))
    }

    /// creates a new client communicating to osquery over the provided transports.
    pub fn new_with_proto(
        input_protocol: Box<dyn TInputProtocol + Send + Sync>,
        output_protocol: Box<dyn TOutputProtocol + Send + Sync>,
    ) -> Self {
        Self {
            client: Arc::from(Mutex::new(osquery::ExtensionManagerSyncClient::new(
                input_protocol,
                output_protocol,
            ))),
        }
    }

    /// ping requests metadata from the extension manager.
    pub fn ping(&mut self) -> TResult<osquery::ExtensionStatus> {
        self.client
            .lock()
            .map_err(|_| "cloud not lock thread in ping")?
            .ping()
    }

    /// call requests a call to an extension (or core) registry plugin.
    pub fn call(
        &mut self,
        registry: String,
        item: String,
        request: osquery::ExtensionPluginRequest,
    ) -> TResult<osquery::ExtensionResponse> {
        self.client
            .lock()
            .map_err(|_| "cloud not lock thread in call")?
            .call(registry, item, request)
    }

    /// shutdown should be called to close the transport when use of the client is completed.
    pub fn shutdown(&mut self) -> TResult<()> {
        self.client
            .lock()
            .map_err(|_| "cloud not lock thread in shutdown")?
            .shutdown()
    }

    /// extensions requests the list of active registered extensions.
    pub fn extensions(&mut self) -> TResult<osquery::InternalExtensionList> {
        self.client
            .lock()
            .map_err(|_| "cloud not lock thread getting extensions")?
            .extensions()
    }

    /// options requests the list of bootstrap or configuration options.
    pub fn options(&mut self) -> TResult<osquery::InternalOptionList> {
        self.client
            .lock()
            .map_err(|_| "cloud not lock thread getting options")?
            .options()
    }

    /// register_extension registers the extension plugins with the osquery process.
    pub fn register_extension(
        &mut self,
        info: osquery::InternalExtensionInfo,
        registry: osquery::ExtensionRegistry,
    ) -> TResult<osquery::ExtensionStatus> {
        self.client
            .lock()
            .map_err(|_| "cloud not lock thread registering extension")?
            .register_extension(info, registry)
    }

    /// deregister_extension de-registers the extension plugins with the osquery process.
    pub fn deregister_extension(
        &mut self,
        uuid: osquery::ExtensionRouteUUID,
    ) -> TResult<osquery::ExtensionStatus> {
        self.client
            .lock()
            .map_err(|_| "cloud not lock thread deregister extension")?
            .deregister_extension(uuid)
    }

    /// query requests a query to be run and returns the extension response.
    /// Consider using the query_row or query_rows helpers for a more friendly interface.
    pub fn query(&mut self, sql: String) -> TResult<osquery::ExtensionResponse> {
        self.client
            .lock()
            .map_err(|_| "cloud not lock thread for query")?
            .query(sql)
    }

    /// get_query_columns requests the columns returned by the parsed query.
    pub fn get_query_columns(&mut self, sql: String) -> TResult<osquery::ExtensionResponse> {
        self.client
            .lock()
            .map_err(|_| "cloud not lock thread for columns query")?
            .get_query_columns(sql)
    }

    /// query_rows is a helper that executes the requested query and returns the TResults.
    /// It handles checking both the transport level TErrors and the osquery internal TErrors
    /// by returning a Thrift TError type.
    pub fn query_rows(&mut self, sql: &str) -> TResult<Vec<BTreeMap<String, String>>> {
        let res = self
            .client
            .lock()
            .map_err(|_| "cloud not lock thread in query")?
            .query(String::from(sql))
            .map_err(|err| format!("transport TError in query: {}", err))?;

        let status = res.status.ok_or("query returned nil status")?;

        match status.code {
            None => Err("query returned nil status".into()),
            Some(0) => Ok(res.response.unwrap_or_default()),
            _ => Err(format!(
                "query returned TError: {}",
                status.message.unwrap_or_default()
            )
            .into()),
        }
    }

    /// query_row behaves similarly to query_rows, but it returns an TError if the query
    /// does not return exactly one row.
    pub fn query_row(&mut self, sql: &str) -> TResult<BTreeMap<String, String>> {
        let res = self.query_rows(sql)?;
        match res.len() {
            1 => Ok(res.into_iter().next().unwrap()),
            _ => Err(format!("expected 1 row, got {}", res.len()).into()),
        }
    }
}

impl ExtensionManager for ExtensionManagerClient {
    /// ping requests metadata from the extension manager.
    fn ping(&mut self) -> TResult<osquery::ExtensionStatus> {
        self.ping()
    }

    /// call requests a call to an extension (or core) registry plugin.
    fn call(
        &mut self,
        registry: String,
        item: String,
        request: osquery::ExtensionPluginRequest,
    ) -> TResult<osquery::ExtensionResponse> {
        self.call(registry, item, request)
    }

    /// shutdown should be called to close the transport when use of the client is completed.
    fn shutdown(&mut self) -> TResult<()> {
        self.shutdown()
    }

    /// extensions requests the list of active registered extensions.
    fn extensions(&mut self) -> TResult<osquery::InternalExtensionList> {
        self.extensions()
    }

    /// options requests the list of bootstrap or configuration options.
    fn options(&mut self) -> TResult<osquery::InternalOptionList> {
        self.options()
    }

    /// register_extension registers the extension plugins with the osquery process.
    fn register_extension(
        &mut self,
        info: osquery::InternalExtensionInfo,
        registry: osquery::ExtensionRegistry,
    ) -> TResult<osquery::ExtensionStatus> {
        self.register_extension(info, registry)
    }

    /// deregister_extension de-registers the extension plugins with the osquery process.
    fn deregister_extension(
        &mut self,
        uuid: osquery::ExtensionRouteUUID,
    ) -> TResult<osquery::ExtensionStatus> {
        self.deregister_extension(uuid)
    }

    /// query requests a query to be run and returns the extension response.
    /// Consider using the query_row or query_rows helpers for a more friendly interface.
    fn query(&mut self, sql: String) -> TResult<osquery::ExtensionResponse> {
        self.query(sql)
    }

    /// get_query_columns requests the columns returned by the parsed query.
    fn get_query_columns(&mut self, sql: String) -> TResult<osquery::ExtensionResponse> {
        self.get_query_columns(sql)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[cfg(unix)]
    pub static TEST_SOCKET: &str = "/var/osquery/osquery.em";
    #[cfg(windows)]
    pub static TEST_SOCKET: &str = r"\\.\pipe\osquery.em";

    #[test]
    #[ignore = "requires a running osqueryd extension socket"]
    #[serial]
    fn query_rows() {
        let mut client = ExtensionManagerClient::new_with_path(TEST_SOCKET).unwrap();
        client.query_rows("SELECT * FROM users").unwrap();
    }

    #[test]
    #[ignore = "requires a running osqueryd extension socket"]
    #[serial]
    fn query_row() {
        let mut client = ExtensionManagerClient::new_with_path(TEST_SOCKET).unwrap();
        client.query_row("SELECT * FROM users limit 1").unwrap();
    }
}
