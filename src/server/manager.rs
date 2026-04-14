use super::{
    threaded::{ExtensionServer, StopHandle},
    OsqueryPlugin,
};
use crate::{client, osquery, Error, Result};
use std::path::PathBuf;
use std::sync::mpsc;
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, Mutex},
    time,
};

/// Plugins represents a map of server plugins for a registry
type Plugins = BTreeMap<Arc<String>, Box<dyn OsqueryPlugin>>;

/// Registry represents the server plugins registry
type Registry = Arc<Mutex<BTreeMap<String, Plugins>>>;

/// sender for server shutdown
type ShutdownSignal = mpsc::SyncSender<Option<Error>>;

/// Default timeout for connecting to the osquery socket.
const DEFAULT_TIMEOUT: time::Duration = time::Duration::from_secs(1);

/// Default interval for pinging osquery to check connectivity.
const DEFAULT_PING_INTERVAL: time::Duration = time::Duration::from_secs(5);

/// Maximum characters allowed in a socket path. A UUID suffix (e.g., ".12345")
/// is appended downstream, which could exceed the Unix socket path limit of
/// ~103 characters.
/// See: <https://unix.stackexchange.com/questions/367008/why-is-socket-path-length-limited-to-a-hundred-chars>
pub const MAX_SOCKET_PATH_CHARACTERS: usize = 97;

/// ServerOption configures an [`ExtensionManagerServer`].
pub enum ServerOption {
    /// Set the extension version string reported to osquery.
    ExtensionVersion(String),
    /// Set the timeout for connecting to the osquery socket.
    /// Currently stored for forward-compatibility; will be used when the
    /// transport layer supports connection timeouts.
    ServerTimeout(time::Duration),
    /// Set how often the extension pings osquery to check connectivity.
    ServerPingInterval(time::Duration),
    /// Use an existing client instead of creating a new one.
    /// When set, the server will not shut down the client on server shutdown.
    WithClient(Box<dyn client::ExtensionManager>),
}

// ExtensionManagerServer is an implementation of the full ExtensionManager
// API. Plugins can register with an extension manager, which handles the
// communication with the osquery process.
pub struct ExtensionManagerServer {
    name: String,
    version: Option<String>,
    osquery_client: Arc<Mutex<Option<Box<dyn client::ExtensionManager>>>>,
    server_client_should_shutdown: bool,
    registry: Registry,
    socket_path: PathBuf,
    listen_path: Option<PathBuf>,
    uuid: Option<osquery::ExtensionRouteUUID>,
    server_stop_handle: Option<StopHandle>,
    #[allow(dead_code)] // Stored for forward-compatibility with transport-layer timeouts.
    timeout: time::Duration,
    ping_interval: time::Duration, // How often to ping osquery server
}

impl ExtensionManagerServer {
    /// new creates a new extension management server
    /// communicating with osquery over the socket at the provided path. If
    /// resolving the address or connecting to the socket fails, this function will
    /// error.
    pub fn new<P: AsRef<Path>>(name: &str, socket_path: P) -> Result<Self> {
        Self::new_with_opts(name, socket_path, vec![])
    }

    /// new_with_opts creates a new extension management server with the given
    /// options. If resolving the address or connecting to the socket fails,
    /// this function will error.
    pub fn new_with_opts<P: AsRef<Path>>(
        name: &str,
        socket_path: P,
        opts: Vec<ServerOption>,
    ) -> Result<Self> {
        let path = socket_path.as_ref();
        let path_len = path.as_os_str().len();
        if path_len > MAX_SOCKET_PATH_CHARACTERS {
            return Err(format!(
                "socket path {} ({} characters) exceeded the maximum socket path character length of {}",
                path.display(),
                path_len,
                MAX_SOCKET_PATH_CHARACTERS
            )
            .into());
        }

        let mut version = None;
        let mut timeout = DEFAULT_TIMEOUT;
        let mut ping_interval = DEFAULT_PING_INTERVAL;
        let mut provided_client: Option<Box<dyn client::ExtensionManager>> = None;

        for opt in opts {
            match opt {
                ServerOption::ExtensionVersion(v) => version = Some(v),
                ServerOption::ServerTimeout(t) => timeout = t,
                ServerOption::ServerPingInterval(i) => ping_interval = i,
                ServerOption::WithClient(c) => provided_client = Some(c),
            }
        }

        let (osquery_client, server_client_should_shutdown) = match provided_client {
            Some(c) => (c, false),
            None => {
                let c = client::ExtensionManagerClient::new_with_path(&socket_path)?;
                (Box::new(c) as Box<dyn client::ExtensionManager>, true)
            }
        };

        Ok(Self {
            name: name.to_string(),
            registry: Arc::from(Mutex::new(BTreeMap::new())),
            socket_path: path.to_path_buf(),
            osquery_client: Arc::from(Mutex::new(Some(osquery_client))),
            server_client_should_shutdown,
            uuid: None,
            server_stop_handle: None,
            version,
            listen_path: None,
            timeout,
            ping_interval,
        })
    }

    /// get extension uuid
    pub fn uuid(&self) -> Option<osquery::ExtensionRouteUUID> {
        self.uuid
    }

    /// register_plugin adds an `OsqueryPlugin` to this extension manager registry.
    pub fn register_plugin(&mut self, plugin: Box<dyn OsqueryPlugin>) -> Result<()> {
        self.registry
            .try_lock()
            .map_err(|_| "could not lock thread register plugin error")?
            .entry(format!("{}", plugin.registry_name()))
            .or_insert_with(BTreeMap::new)
            .entry(plugin.name())
            .or_insert(plugin);

        Ok(())
    }

    /// register_plugins adds multiple [`OsqueryPlugin`]s to this extension manager registry.
    pub fn register_plugins(&mut self, plugins: Vec<Box<dyn OsqueryPlugin>>) -> Result<()> {
        for plugin in plugins {
            self.register_plugin(plugin)?;
        }
        Ok(())
    }

    fn gen_registry(&mut self) -> Result<osquery::ExtensionRegistry> {
        let mut ext_registry = osquery::ExtensionRegistry::new();
        let mut registry = self
            .registry
            .try_lock()
            .map_err(|_| "thread lock error generating osquery extension registry")?;

        for (reg_name, plugins) in registry.iter_mut() {
            let routes = ext_registry.entry(reg_name.clone()).or_default();
            for (plug_name, plugin) in plugins {
                routes
                    .entry(plug_name.to_string())
                    .or_insert_with(|| plugin.routes());
            }
        }

        Ok(ext_registry)
    }

    /// register_extension registers the extension and plugins.
    /// All plugins should be registered with register_plugin() before calling register_extension().
    /// Return the ExtensionRouteUUID
    fn register_extension(&mut self) -> Result<i64> {
        let registry = self.gen_registry()?;
        let response = self
            .osquery_client
            .try_lock()
            .map_err(|_| "thread lock error for server_client on start")?
            .as_mut()
            .ok_or("cannot start, shutdown in progress")?
            .register_extension(
                osquery::InternalExtensionInfo::new(
                    self.name.clone(),
                    self.version.clone(),
                    None,
                    None,
                ),
                registry,
            )?;

        // Check the registration status code (matching Go's server.go:216-218)
        let code = response.code.unwrap_or_default();
        if code != 0 {
            return Err(format!(
                "status {} registering extension: {}",
                code,
                response.message.unwrap_or_default()
            )
            .into());
        }

        self.uuid = response.uuid;

        let mut listen_path = self.socket_path.clone();
        self.listen_path = match listen_path
            .set_extension(format!("em.{}", self.uuid.ok_or("uuid returned nil")?))
        {
            true => Some(listen_path),
            false => return Err("socket_path is not valid file".into()),
        };
        self.uuid.ok_or_else(|| "uuid returned nil".into())
    }

    /// start open a new thread and begins listening for requests from the osquery process.
    /// All plugins should be registered with register_plugin() before calling start().
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self, shutdown)))]
    fn start(&mut self, shutdown: ShutdownSignal) -> Result<()> {
        // will set the uuid and listen_path for the server
        self.register_extension()?;

        let listen_path = self
            .listen_path
            .clone()
            .ok_or("set the listen_path to start server")?;

        let handler = ExtensionServerHandler {
            registry: self.registry.clone(),
            shutdown: shutdown.clone(),
        };
        let processor = osquery::ExtensionSyncProcessor::new(handler);
        let mut server = ExtensionServer::new(processor)?;

        // Store the stop handle so shutdown() can stop the listener
        self.server_stop_handle = Some(server.stop_handle());

        std::thread::spawn(move || {
            // start listen for connections
            if let Err(err) = server.listen(&listen_path) {
                shutdown.send(Some(err.into())).unwrap();
            }
        });

        Ok(())
    }

    /// shutdown deregisters the extension, stops the server and closes all sockets.
    /// This method is idempotent: calling it multiple times is safe and will
    /// not return an error on subsequent calls.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self)))]
    pub fn shutdown(&mut self) -> Result<()> {
        let mut client_guard = self
            .osquery_client
            .try_lock()
            .map_err(|_| "could not lock osquery client error")?;

        // Deregister the extension if we have a client and uuid
        if let Some(client) = client_guard.as_mut() {
            if let Some(uuid) = self.uuid {
                match client.deregister_extension(uuid) {
                    Err(err) => {
                        // Log but don't fail -- we still want to stop the server
                        #[cfg(feature = "tracing")]
                        tracing::warn!("error deregistering extension {}: {}", uuid, err);
                        let _ =
                            Error::from(err).message(&format!("deregistering extension {}", uuid));
                    }
                    Ok(res) if res.code.unwrap_or_default() != 0 => {
                        #[cfg(feature = "tracing")]
                        tracing::warn!(
                            "status {} deregistering extension: {}",
                            res.code.unwrap_or_default(),
                            res.message.as_deref().unwrap_or_default()
                        );
                    }
                    Ok(_) => {}
                }
            }
        }

        // Stop the thrift server asynchronously (matching Go's server.go:341-351)
        if let Some(stop_handle) = self.server_stop_handle.take() {
            stop_handle.stop();
        }

        // Shutdown the client, if appropriate (matching Go's server.go:353-357)
        if self.server_client_should_shutdown {
            if let Some(client) = client_guard.as_mut() {
                client.close();
            }
            *client_guard = None;
        }

        Ok(())
    }

    /// run starts the extension manager until osquery calls for a shutdown
    /// or the osquery instance goes away.
    /// Takes `&mut self` instead of consuming `self` so that external code
    /// (e.g., signal handlers) can call [`shutdown`](Self::shutdown) concurrently.
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(skip(self), fields(name = %self.name))
    )]
    pub fn run(&mut self) -> Result<()> {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let ping_interval = self.ping_interval;
        let osquery_client = self.osquery_client.clone();

        self.start(tx.clone())?;

        // Watch for the osquery process going away. If so, initiate shutdown.
        std::thread::spawn(move || loop {
            std::thread::sleep(ping_interval);

            match osquery_client.lock() {
                Ok(mut guard) => match guard.as_mut() {
                    // Client was set to None by shutdown -- exit the ping loop
                    None => break,
                    Some(client) => match client.ping() {
                        Err(e) => {
                            let msg = Error::from(e).message("extension ping failed");
                            tx.send(Some(msg)).ok();
                            break;
                        }
                        Ok(status) if status.code.unwrap_or_default() != 0 => {
                            tx.send(Some(Error::from(format!(
                                "ping returned status {}",
                                status.code.unwrap_or_default()
                            ))))
                            .ok();
                            break;
                        }
                        Ok(_) => {}
                    },
                },
                Err(_) => {
                    tx.send(Some(Error::from("could not lock osquery client for ping")))
                        .ok();
                    break;
                }
            }
        });

        // wait for the shutdown signal and initiate shutdown.
        let stop_signal = rx.recv();
        self.shutdown().and_then(move |_| match stop_signal {
            Ok(signal) if signal.is_some() => Err(signal.unwrap()),
            Err(_) => Err("shutdown signal error".into()),
            Ok(_) => Ok(()),
        })
    }
}

/// ExtensionServerHandler handles requests to the extension server and is used
/// as the ExtensionSyncProcessor for the thrift server
struct ExtensionServerHandler {
    registry: Registry,
    shutdown: ShutdownSignal,
}

impl osquery::ExtensionSyncHandler for ExtensionServerHandler {
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), level = "debug"))]
    fn handle_ping(&self) -> thrift::Result<osquery::ExtensionStatus> {
        Ok(osquery::ExtensionStatus::new(0, "OK".to_string(), None))
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(skip(self, request), fields(registry = %registry, item = %item))
    )]
    fn handle_call(
        &self,
        registry: String,
        item: String,
        request: osquery::ExtensionPluginRequest,
    ) -> thrift::Result<osquery::ExtensionResponse> {
        match self
            .registry
            .try_lock()
            .map_err(|_| "could not lock register error")?
            .get_mut(&registry)
        {
            Some(subreg) => match subreg.get_mut(&item) {
                Some(plugin) => Ok(plugin.call(request)),
                None => {
                    let msg = format!("Unknown registry item: {}", item);
                    #[cfg(feature = "tracing")]
                    tracing::warn!("{}", msg);
                    Ok(osquery::ExtensionResponse::new(
                        osquery::ExtensionStatus::new(1, msg, None),
                        None,
                    ))
                }
            },
            None => {
                let msg = format!("Unknown registry: {}", registry);
                #[cfg(feature = "tracing")]
                tracing::warn!("{}", msg);
                Ok(osquery::ExtensionResponse::new(
                    osquery::ExtensionStatus::new(1, msg, None),
                    None,
                ))
            }
        }
    }

    fn handle_shutdown(&self) -> thrift::Result<()> {
        self.shutdown
            .send(None)
            .map_err(|_| "could not send shutdown signal".into())
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::osquery::ExtensionSyncHandler;
    use crate::server::mock;
    use crate::server::RegistryName;
    use serial_test::serial;

    #[cfg(unix)]
    const SOCKET: &str = "/var/osquery/osquery.em";
    #[cfg(windows)]
    const SOCKET: &str = r"\\.\pipe\osquery.em";

    fn init_server() -> ExtensionManagerServer {
        let mut server = ExtensionManagerServer::new("test_server", String::from(SOCKET)).unwrap();
        server.ping_interval = std::time::Duration::from_secs(1);
        server
    }

    fn wait_for_extension_server<P: AsRef<std::path::Path>>(path: P) {
        for _ in 0..50 {
            if let Ok(mut client) = client::ExtensionManagerClient::new_with_path(&path) {
                if client.ping().is_ok() {
                    return;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }

        panic!(
            "timed out waiting for extension server at {}",
            path.as_ref().display()
        );
    }

    #[test]
    #[ignore = "requires a running osqueryd extension socket"]
    #[serial]
    fn register_plugin() {
        let name = "test_plugin";
        let plugin = mock::MockPlugin::new(name, RegistryName::Table);
        let mut server = init_server();

        server.register_plugin(plugin).unwrap();

        server
            .registry
            .lock()
            .unwrap()
            .get("table")
            .expect("plugin not found in table registry found")
            .get(&name.to_string());
    }

    #[test]
    #[ignore = "requires a running osqueryd extension socket"]
    #[serial]
    fn gen_registry() {
        let name = "test_plugin";
        let plugin = mock::MockPlugin::new(name, RegistryName::Table);
        let mut server = init_server();

        server.register_plugin(plugin).unwrap();
        let registry = server.gen_registry().unwrap();
        assert!(
            registry.contains_key("table"),
            "test_plugin should in registry"
        );
        assert!(
            registry.get("table").unwrap().contains_key("test_plugin"),
            "test_plugin should in registry"
        )
    }

    #[test]
    #[ignore = "requires a running osqueryd extension socket"]
    #[serial]
    fn register_extension() {
        let name = "test_plugin";
        let plugin = mock::MockPlugin::new(name, RegistryName::Table);
        let mut server = init_server();

        server.register_plugin(plugin).unwrap();
        let uuid = server.register_extension();

        assert!(uuid.is_ok(), "extension plugin should be in registry");
        assert!(
            server.uuid.is_some(),
            "uuid should be set by register_extension"
        );
        assert!(
            server.listen_path.is_some(),
            "listen_path should be set by register_extension"
        )
    }

    #[test]
    #[ignore = "requires a running osqueryd extension socket"]
    #[serial]
    fn start() {
        let mut server = init_server();
        let (tx, _) = std::sync::mpsc::sync_channel(1);
        server.start(tx).unwrap();
        let listen_path = server.listen_path.clone().unwrap();
        wait_for_extension_server(&listen_path);
    }

    #[test]
    #[ignore = "requires a running osqueryd extension socket"]
    #[serial]
    fn shutdown() {
        let mut server = init_server();
        let (tx, _) = std::sync::mpsc::sync_channel(1);

        // Shutdown without uuid should succeed (idempotent -- no uuid means nothing to deregister)
        assert!(
            server.shutdown().is_ok(),
            "shutdown without uuid should succeed (idempotent)"
        );

        server.start(tx).unwrap();

        let listen_path = server.listen_path.clone().unwrap();
        wait_for_extension_server(&listen_path);

        let shutdown_err = server.shutdown().err();
        assert!(
            shutdown_err.is_none(),
            "shutdown should be ok: {:?}",
            shutdown_err
        );

        // Second shutdown should also succeed (idempotent)
        let shutdown_err = server.shutdown().err();
        assert!(
            shutdown_err.is_none(),
            "second shutdown should be ok (idempotent): {:?}",
            shutdown_err
        );
    }

    #[test]
    fn handle_shutdown() {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let handler = ExtensionServerHandler {
            registry: Arc::from(Mutex::new(BTreeMap::new())),
            shutdown: tx,
        };
        std::thread::spawn(move || handler.handle_shutdown());
        assert!(rx.recv().unwrap().is_none(), "shutdown should not fail");
    }

    #[test]
    fn handle_call() {
        let (tx, _) = std::sync::mpsc::sync_channel(1);
        let reg = Arc::from(Mutex::new(BTreeMap::new()));
        let handler = ExtensionServerHandler {
            registry: reg.clone(),
            shutdown: tx,
        };
        let res = handler
            .handle_call(
                String::from("table"),
                String::from(""),
                osquery::ExtensionPluginRequest::new(),
            )
            .unwrap();

        assert_eq!(
            res.status.unwrap().code.unwrap(),
            1,
            "status code should be 1 if table not found"
        );
        let name = "test_plugin";
        let plugin = mock::MockPlugin::new(name, RegistryName::Table);

        reg.lock()
            .unwrap()
            .entry("table".to_string())
            .or_insert_with(BTreeMap::new)
            .entry(plugin.name())
            .or_insert(plugin);

        let res = handler
            .handle_call(
                String::from("table"),
                name.to_string(),
                osquery::ExtensionPluginRequest::new(),
            )
            .unwrap();

        assert_eq!(
            res.status.unwrap().code.unwrap(),
            mock::STATUS_CODE,
            "status code should be 1 if table not found"
        );

        let res = handler
            .handle_call(
                String::from("table"),
                String::from("hello"),
                osquery::ExtensionPluginRequest::new(),
            )
            .unwrap();

        assert_eq!(
            res.status.unwrap().message.unwrap(),
            "Unknown registry item: hello",
            "hello should not be found"
        );
    }

    #[test]
    fn socket_path_too_long() {
        let long_path = "a".repeat(MAX_SOCKET_PATH_CHARACTERS + 1);
        let result = ExtensionManagerServer::new("test", &long_path);
        match result {
            Err(e) => assert!(
                e.to_string()
                    .contains("exceeded the maximum socket path character length"),
                "should report socket path length error, got: {}",
                e
            ),
            Ok(_) => panic!("expected error for long socket path"),
        }
    }

    #[test]
    fn socket_path_at_limit() {
        // A path exactly at the limit should not fail with a length error.
        // It will fail trying to connect (no such socket), which is expected.
        let limit_path = "a".repeat(MAX_SOCKET_PATH_CHARACTERS);
        let result = ExtensionManagerServer::new("test", &limit_path);
        match result {
            Err(e) => assert!(
                !e.to_string()
                    .contains("exceeded the maximum socket path character length"),
                "should not be a path length error, got: {}",
                e
            ),
            Ok(_) => panic!("expected connection error for non-existent socket"),
        }
    }

    #[test]
    #[ignore = "requires a running osqueryd extension socket"]
    #[serial]
    fn new_with_opts() {
        let server = ExtensionManagerServer::new_with_opts(
            "test_opts",
            String::from(SOCKET),
            vec![
                ServerOption::ExtensionVersion("1.0.0".to_string()),
                ServerOption::ServerTimeout(time::Duration::from_secs(2)),
                ServerOption::ServerPingInterval(time::Duration::from_secs(10)),
            ],
        )
        .unwrap();
        assert_eq!(server.version, Some("1.0.0".to_string()));
        assert_eq!(server.timeout, time::Duration::from_secs(2));
        assert_eq!(server.ping_interval, time::Duration::from_secs(10));
        assert!(
            server.server_client_should_shutdown,
            "server-created client should be marked for shutdown"
        );
    }

    #[test]
    #[ignore = "requires a running osqueryd extension socket"]
    #[serial]
    fn register_plugins_batch() {
        let mut server = init_server();
        let plugins: Vec<Box<dyn OsqueryPlugin>> = vec![
            mock::MockPlugin::new("plugin_a", RegistryName::Table),
            mock::MockPlugin::new("plugin_b", RegistryName::Logger),
            mock::MockPlugin::new("plugin_c", RegistryName::Config),
        ];
        server.register_plugins(plugins).unwrap();

        let registry = server.registry.lock().unwrap();
        assert!(
            registry
                .get("table")
                .and_then(|r| r.get(&"plugin_a".to_string()))
                .is_some(),
            "plugin_a should be in table registry"
        );
        assert!(
            registry
                .get("logger")
                .and_then(|r| r.get(&"plugin_b".to_string()))
                .is_some(),
            "plugin_b should be in logger registry"
        );
        assert!(
            registry
                .get("config")
                .and_then(|r| r.get(&"plugin_c".to_string()))
                .is_some(),
            "plugin_c should be in config registry"
        );
    }
}
