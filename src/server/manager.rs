use super::{
    threaded::{ExtensionServer, StopHandle},
    OsqueryPlugin, RegistryName,
};
use crate::{client, osquery, Error, Result};
use std::path::PathBuf;
use std::sync::mpsc;
use std::{
    collections::HashMap,
    fmt,
    path::Path,
    sync::{Arc, Mutex},
    time,
};

/// Plugins represents a map of plugin name → plugin for a single registry.
type Plugins = HashMap<String, Arc<Mutex<Box<dyn OsqueryPlugin>>>>;

/// Registry maps each `RegistryName` to its plugins.
type Registry = Arc<Mutex<HashMap<RegistryName, Plugins>>>;

/// sender for server shutdown
type ShutdownSignal = mpsc::SyncSender<Option<Error>>;

/// Default timeout for connecting to the osquery socket.
const DEFAULT_TIMEOUT: time::Duration = time::Duration::from_secs(1);

/// Default interval for pinging osquery to check connectivity.
const DEFAULT_PING_INTERVAL: time::Duration = time::Duration::from_secs(5);

/// Whether the server owns the osquery client and should close it on shutdown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClientOwnership {
    /// Server created the client; it will be closed on shutdown.
    Owned,
    /// Caller provided the client; the server will not close it.
    Borrowed,
}

/// Maximum characters allowed in a socket path. A UUID suffix (e.g., ".12345")
/// is appended downstream, which could exceed the Unix socket path limit of
/// ~103 characters.
/// See: <https://unix.stackexchange.com/questions/367008/why-is-socket-path-length-limited-to-a-hundred-chars>
pub(crate) const MAX_SOCKET_PATH_CHARACTERS: usize = 97;

/// Builder for constructing an [`ExtensionManagerServer`] with custom configuration.
///
/// # Example
/// ```no_run
/// use osquery_rs_sdk::ExtensionManagerServer;
/// use std::time::Duration;
///
/// let server = ExtensionManagerServer::builder("my_ext", "/var/osquery/osquery.em")
///     .version("1.0.0")
///     .ping_interval(Duration::from_secs(10))
///     .build()
///     .unwrap();
/// ```
pub struct ExtensionManagerServerBuilder<P: AsRef<Path>> {
    name: String,
    socket_path: P,
    version: Option<String>,
    timeout: time::Duration,
    ping_interval: time::Duration,
    client: Option<Box<dyn client::ExtensionManager>>,
}

impl<P: AsRef<Path>> ExtensionManagerServerBuilder<P> {
    fn new(name: &str, socket_path: P) -> Self {
        Self {
            name: name.to_string(),
            socket_path,
            version: None,
            timeout: DEFAULT_TIMEOUT,
            ping_interval: DEFAULT_PING_INTERVAL,
            client: None,
        }
    }

    /// Set the extension version string reported to osquery.
    #[must_use]
    pub fn version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Set the timeout for connecting to the osquery socket.
    /// Currently stored for forward-compatibility; will be used when the
    /// transport layer supports connection timeouts.
    #[must_use]
    pub fn timeout(mut self, timeout: time::Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set how often the extension pings osquery to check connectivity.
    #[must_use]
    pub fn ping_interval(mut self, interval: time::Duration) -> Self {
        self.ping_interval = interval;
        self
    }

    /// Use an existing client instead of creating a new one.
    /// When set, the server will not shut down the client on server shutdown.
    #[must_use]
    pub fn client(mut self, client: Box<dyn client::ExtensionManager>) -> Self {
        self.client = Some(client);
        self
    }

    /// Build the [`ExtensionManagerServer`], connecting to the osquery socket.
    ///
    /// # Errors
    ///
    /// Returns an error if the socket path exceeds `MAX_SOCKET_PATH_CHARACTERS`
    /// or if connecting to the `osqueryd` socket fails.
    pub fn build(self) -> Result<ExtensionManagerServer> {
        let path = self.socket_path.as_ref();
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

        let (osquery_client, client_ownership) = if let Some(c) = self.client {
            (c, ClientOwnership::Borrowed)
        } else {
            let c = client::ExtensionManagerClient::connect_with_path(&self.socket_path)?;
            (
                Box::new(c) as Box<dyn client::ExtensionManager>,
                ClientOwnership::Owned,
            )
        };

        Ok(ExtensionManagerServer {
            name: self.name,
            registry: Arc::from(Mutex::new(HashMap::new())),
            socket_path: path.to_path_buf(),
            osquery_client: Arc::from(Mutex::new(Some(osquery_client))),
            client_ownership,
            uuid: None,
            server_stop_handle: None,
            version: self.version,
            listen_path: None,
            timeout: self.timeout,
            ping_interval: self.ping_interval,
        })
    }
}

/// `ExtensionManagerServer` is an implementation of the full `ExtensionManager`
/// API. Plugins can register with an extension manager, which handles the
/// communication with the osquery process.
pub struct ExtensionManagerServer {
    name: String,
    version: Option<String>,
    osquery_client: Arc<Mutex<Option<Box<dyn client::ExtensionManager>>>>,
    client_ownership: ClientOwnership,
    registry: Registry,
    socket_path: PathBuf,
    listen_path: Option<PathBuf>,
    uuid: Option<osquery::ExtensionRouteUUID>,
    server_stop_handle: Option<StopHandle>,
    #[allow(dead_code)] // Stored for forward-compatibility with transport-layer timeouts.
    timeout: time::Duration,
    ping_interval: time::Duration, // How often to ping osquery server
}

impl fmt::Debug for ExtensionManagerServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExtensionManagerServer")
            .field("name", &self.name)
            .field("version", &self.version)
            .field("socket_path", &self.socket_path)
            .field("listen_path", &self.listen_path)
            .field("uuid", &self.uuid)
            .field("client_ownership", &self.client_ownership)
            .field("timeout", &self.timeout)
            .field("ping_interval", &self.ping_interval)
            .finish_non_exhaustive()
    }
}

impl ExtensionManagerServer {
    /// Create a new extension management server communicating with osquery
    /// over the socket at the provided path. If resolving the address or
    /// connecting to the socket fails, this function will error.
    ///
    /// For additional configuration (version, timeout, ping interval, custom client),
    /// use [`builder`](Self::builder) instead.
    ///
    /// # Errors
    ///
    /// Returns an error if connecting to the `osqueryd` socket at `socket_path` fails.
    pub fn new<P: AsRef<Path>>(name: &str, socket_path: P) -> Result<Self> {
        Self::builder(name, socket_path).build()
    }

    /// Return a builder for constructing an `ExtensionManagerServer` with custom options.
    pub fn builder<P: AsRef<Path>>(name: &str, socket_path: P) -> ExtensionManagerServerBuilder<P> {
        ExtensionManagerServerBuilder::new(name, socket_path)
    }

    /// Return the extension uuid assigned by osquery after registration.
    #[must_use]
    pub fn uuid(&self) -> Option<osquery::ExtensionRouteUUID> {
        self.uuid
    }

    /// Add an `OsqueryPlugin` to this extension manager registry.
    ///
    /// # Errors
    ///
    /// Returns an error if a plugin with the same name and registry already exists,
    /// or if the registry lock is poisoned.
    pub fn register_plugin(&mut self, plugin: impl OsqueryPlugin + 'static) -> Result<()> {
        let name = plugin.name().to_string();
        let registry_name = plugin.registry_name();
        let mut registry = self.registry.lock().map_err(|_| "registry lock poisoned")?;
        let plugins = registry.entry(registry_name).or_default();
        if plugins.contains_key(&name) {
            return Err(format!(
                "plugin \"{name}\" already registered in {registry_name} registry"
            )
            .into());
        }
        plugins.insert(name, Arc::new(Mutex::new(Box::new(plugin))));
        Ok(())
    }

    /// Add multiple [`OsqueryPlugin`]s to this extension manager registry.
    ///
    /// # Errors
    ///
    /// Returns an error if any plugin has a duplicate name or if the registry lock is poisoned.
    pub fn register_plugins(
        &mut self,
        plugins: impl IntoIterator<Item = Box<dyn OsqueryPlugin>>,
    ) -> Result<()> {
        let mut registry = self.registry.lock().map_err(|_| "registry lock poisoned")?;
        for plugin in plugins {
            let name = plugin.name().to_string();
            let registry_name = plugin.registry_name();
            let entries = registry.entry(registry_name).or_default();
            if entries.contains_key(&name) {
                return Err(format!(
                    "plugin \"{name}\" already registered in {registry_name} registry"
                )
                .into());
            }
            entries.insert(name, Arc::new(Mutex::new(plugin)));
        }
        Ok(())
    }

    fn gen_registry(&mut self) -> Result<osquery::ExtensionRegistry> {
        let mut ext_registry = osquery::ExtensionRegistry::new();
        let registry = self.registry.lock().map_err(|_| "registry lock poisoned")?;

        for (reg_name, plugins) in registry.iter() {
            let routes = ext_registry.entry(reg_name.to_string()).or_default();
            for (plug_name, plugin) in plugins {
                let plugin = plugin.lock().map_err(|_| "plugin lock poisoned")?;
                routes
                    .entry(plug_name.clone())
                    .or_insert_with(|| plugin.routes());
            }
        }

        Ok(ext_registry)
    }

    /// Register the extension and plugins.
    /// All plugins should be registered with `register_plugin()` before calling this method.
    /// Returns the `ExtensionRouteUUID`.
    fn register_extension(&mut self) -> Result<i64> {
        let registry = self.gen_registry()?;
        let response = self
            .osquery_client
            .lock()
            .map_err(|_| "osquery client lock poisoned")?
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

        // Check the registration status code
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
        self.listen_path =
            if listen_path.set_extension(format!("em.{}", self.uuid.ok_or("uuid returned nil")?)) {
                Some(listen_path)
            } else {
                return Err("socket_path is not valid file".into());
            };
        self.uuid.ok_or_else(|| "uuid returned nil".into())
    }

    /// Open a new thread and begin listening for requests from the osquery process.
    /// All plugins should be registered with `register_plugin()` before calling `start()`.
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
                let _ = shutdown.send(Some(err.into()));
            }
        });

        Ok(())
    }

    /// Deregister the extension, stop the server, and close all sockets.
    /// This method is idempotent: calling it multiple times is safe and will
    /// not return an error on subsequent calls.
    ///
    /// # Errors
    ///
    /// Returns an error if the osquery client lock is poisoned.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self)))]
    pub fn shutdown(&mut self) -> Result<()> {
        let mut client_guard = self
            .osquery_client
            .lock()
            .map_err(|_| "osquery client lock poisoned")?;

        // Nothing to do if we never registered
        let Some(uuid) = self.uuid.take() else {
            return Ok(());
        };

        // Deregister the extension if we have a client
        if let Some(client) = client_guard.as_mut() {
            match client.deregister_extension(uuid) {
                Err(err) => {
                    // Log but don't fail -- we still want to stop the server
                    #[cfg(feature = "tracing")]
                    tracing::warn!("error deregistering extension {}: {}", uuid, err);
                    #[cfg(not(feature = "tracing"))]
                    let _ = err;
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

        // Stop the thrift server asynchronously
        if let Some(stop_handle) = self.server_stop_handle.take() {
            stop_handle.stop();
        }

        // Shutdown the client if we own it (not if the caller provided one)
        if self.client_ownership == ClientOwnership::Owned {
            if let Some(client) = client_guard.as_mut() {
                client.close();
            }
            *client_guard = None;
        }

        Ok(())
    }

    /// Start the extension manager and run until osquery calls for a shutdown
    /// or the osquery instance goes away.
    /// Takes `&mut self` instead of consuming `self` so that external code
    /// (e.g., signal handlers) can call [`shutdown`](Self::shutdown) concurrently.
    ///
    /// # Errors
    ///
    /// Returns an error if starting the server fails, if the osquery process
    /// goes away (ping failure), or if shutdown encounters an error.
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

            if let Ok(mut guard) = osquery_client.lock() {
                match guard.as_mut() {
                    // Client was set to None by shutdown -- exit the ping loop
                    None => break,
                    Some(client) => match client.ping() {
                        Err(e) => {
                            let msg = Error::from(e).context("extension ping failed");
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
                }
            } else {
                tx.send(Some(Error::from("could not lock osquery client for ping")))
                    .ok();
                break;
            }
        });

        // wait for the shutdown signal and initiate shutdown.
        let stop_signal = rx.recv();
        self.shutdown().and_then(move |()| match stop_signal {
            Ok(Some(err)) => Err(err),
            Err(_) => Err("shutdown signal error".into()),
            Ok(None) => Ok(()),
        })
    }
}

impl Drop for ExtensionManagerServer {
    fn drop(&mut self) {
        // Best-effort shutdown; ignore errors since we're in Drop
        let _ = self.shutdown();
    }
}

/// `ExtensionServerHandler` handles requests to the extension server and is used
/// as the `ExtensionSyncProcessor` for the thrift server
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
        // Phase 1: Lookup (holds registry lock briefly, then releases)
        let lookup_result = {
            let reg_name: super::RegistryName = match registry.parse() {
                Ok(r) => r,
                Err(msg) => {
                    return Ok(osquery::ExtensionResponse::new(
                        osquery::ExtensionStatus::new(1, msg, None),
                        None,
                    ))
                }
            };
            let reg = self.registry.lock().map_err(|_| "registry lock poisoned")?;
            match reg.get(&reg_name) {
                None => Err(format!("Unknown registry: {registry}")),
                Some(subreg) => match subreg.get(item.as_str()) {
                    None => Err(format!("Unknown registry item: {item}")),
                    Some(p) => Ok(Arc::clone(p)),
                },
            }
        }; // registry lock dropped here

        // Phase 2: Execute (no registry lock held — other plugins can run concurrently)
        match lookup_result {
            Ok(plugin) => {
                let mut plugin = plugin.lock().map_err(|_| "plugin lock poisoned")?;
                Ok(plugin.call(request))
            }
            Err(msg) => {
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
    use crate::plugin::table::{ColumnDefinition, TablePlugin};
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
            if let Ok(mut client) = client::ExtensionManagerClient::connect_with_path(&path) {
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
            .get(&RegistryName::Table)
            .expect("plugin not found in table registry found")
            .get(name);
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
        let plugin = TablePlugin::new(
            "test_register_ext",
            vec![ColumnDefinition::text("col1")],
            |_ctx| Ok(vec![]),
        );
        let mut server = init_server();

        server.register_plugin(plugin).unwrap();
        let uuid = server.register_extension();

        assert!(
            uuid.is_ok(),
            "extension plugin should be in registry: {:?}",
            uuid.err()
        );
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
            "shutdown should be ok: {shutdown_err:?}"
        );

        // Second shutdown should also succeed (idempotent)
        let shutdown_err = server.shutdown().err();
        assert!(
            shutdown_err.is_none(),
            "second shutdown should be ok (idempotent): {shutdown_err:?}"
        );
    }

    #[test]
    fn handle_shutdown() {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let handler = ExtensionServerHandler {
            registry: Arc::from(Mutex::new(HashMap::new())),
            shutdown: tx,
        };
        std::thread::spawn(move || handler.handle_shutdown());
        assert!(rx.recv().unwrap().is_none(), "shutdown should not fail");
    }

    #[test]
    fn handle_call() {
        let (tx, _) = std::sync::mpsc::sync_channel(1);
        let reg: Registry = Arc::from(Mutex::new(HashMap::new()));
        let handler = ExtensionServerHandler {
            registry: reg.clone(),
            shutdown: tx,
        };
        let res = handler
            .handle_call(
                String::from("table"),
                String::new(),
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
        let plugin_name = plugin.name().to_string();

        reg.lock()
            .unwrap()
            .entry(RegistryName::Table)
            .or_default()
            .entry(plugin_name)
            .or_insert_with(|| Arc::new(Mutex::new(Box::new(plugin))));

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
                "should report socket path length error, got: {e}"
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
                "should not be a path length error, got: {e}"
            ),
            Ok(_) => panic!("expected connection error for non-existent socket"),
        }
    }

    #[test]
    #[ignore = "requires a running osqueryd extension socket"]
    #[serial]
    fn builder_custom_options() {
        let server = ExtensionManagerServer::builder("test_opts", String::from(SOCKET))
            .version("1.0.0")
            .timeout(time::Duration::from_secs(2))
            .ping_interval(time::Duration::from_secs(10))
            .build()
            .unwrap();
        assert_eq!(server.version, Some("1.0.0".to_string()));
        assert_eq!(server.timeout, time::Duration::from_secs(2));
        assert_eq!(server.ping_interval, time::Duration::from_secs(10));
        assert!(
            server.client_ownership == ClientOwnership::Owned,
            "server-created client should be marked as Owned"
        );
    }

    #[test]
    #[ignore = "requires a running osqueryd extension socket"]
    #[serial]
    fn register_plugins_batch() {
        let mut server = init_server();
        let plugins: Vec<Box<dyn OsqueryPlugin>> = vec![
            Box::new(mock::MockPlugin::new("plugin_a", RegistryName::Table)),
            Box::new(mock::MockPlugin::new("plugin_b", RegistryName::Logger)),
            Box::new(mock::MockPlugin::new("plugin_c", RegistryName::Config)),
        ];
        server.register_plugins(plugins).unwrap();

        let registry = server.registry.lock().unwrap();
        assert!(
            registry
                .get(&RegistryName::Table)
                .and_then(|r| r.get("plugin_a"))
                .is_some(),
            "plugin_a should be in table registry"
        );
        assert!(
            registry
                .get(&RegistryName::Logger)
                .and_then(|r| r.get("plugin_b"))
                .is_some(),
            "plugin_b should be in logger registry"
        );
        assert!(
            registry
                .get(&RegistryName::Config)
                .and_then(|r| r.get("plugin_c"))
                .is_some(),
            "plugin_c should be in config registry"
        );
    }
}
