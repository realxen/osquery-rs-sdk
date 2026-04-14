use super::{threaded::ExtensionServer, OsqueryPlugin};
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

// ExtensionManagerServer is an implementation of the full ExtensionManager
// API. Plugins can register with an extension manager, which handles the
// communication with the osquery process.
pub struct ExtensionManagerServer {
    name: String,
    version: Option<String>,
    osquery_client: Arc<Mutex<client::ExtensionManagerClient>>,
    registry: Registry,
    socket_path: PathBuf,
    listen_path: Option<PathBuf>,
    uuid: Arc<Option<osquery::ExtensionRouteUUID>>,
    ping_interval: time::Duration, // How often to ping osquery server
}

impl ExtensionManagerServer {
    /// new creates a new extension management server
    /// communicating with osquery over the socket at the provided path. If
    /// resolving the address or connecting to the socket fails, this function will
    /// error.
    pub fn new<P: AsRef<Path>>(name: &str, socket_path: P) -> Result<Self> {
        let client = client::ExtensionManagerClient::new_with_path(&socket_path)?;
        Ok(Self::new_with_client(name, socket_path, client))
    }

    /// create a new extension management server
    /// communicating with osquery with provided client
    fn new_with_client<P: AsRef<Path>>(
        name: &str,
        socket_path: P,
        client: client::ExtensionManagerClient,
    ) -> Self {
        Self {
            name: name.to_string(),
            registry: Arc::from(Mutex::new(BTreeMap::new())),
            socket_path: socket_path.as_ref().to_path_buf(),
            osquery_client: Arc::from(Mutex::new(client)),
            uuid: Arc::from(None),
            version: None,
            listen_path: None,
            ping_interval: time::Duration::from_secs(5),
        }
    }

    /// get extension uuid
    pub fn uuid(&self) -> Option<osquery::ExtensionRouteUUID> {
        *self.uuid
    }

    /// register_plugin add an `OsqueryPlugin` to this extension manager registry.
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
        let stat = self
            .osquery_client
            .try_lock()
            .map_err(|_| "thread lock error for server_client on start")?
            .register_extension(
                osquery::InternalExtensionInfo::new(
                    self.name.clone(),
                    self.version.clone(),
                    None,
                    None,
                ),
                registry,
            );

        // registering extension
        self.uuid = match stat {
            Ok(response) => Arc::from(response.uuid),
            Err(err) => return Err(err.into()),
        };

        let mut listen_path = self.socket_path.clone();
        self.listen_path = match listen_path.set_extension(format!("em.{}", self.uuid.unwrap())) {
            true => Some(listen_path),
            false => return Err("socket_path is not valid file".into()),
        };
        self.uuid.ok_or_else(|| "uuid returned nil".into())
    }

    /// start open a new thread and begins listening for requests from the osquery process.
    /// All plugins should be registered with register_plugin() before calling start().
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

        std::thread::spawn(move || {
            // start listen for connections
            if let Err(err) = server.listen(&listen_path) {
                shutdown.send(Some(err.into())).unwrap();
            }
        });

        Ok(())
    }

    /// shutdown deregisters the extension, stops the server and closes all sockets.
    fn shutdown(&mut self) -> Result<()> {
        let uuid = self.uuid.ok_or_else(|| "uuid returned nil")?;
        let mut client = self
            .osquery_client
            .try_lock()
            .map_err(|_| "could not lock osquery client error")?;

        match client.deregister_extension(uuid) {
            Err(err) => Err(Error::from(err).message(&format!("deregistering extension {}", uuid))),
            Ok(res) if res.code.unwrap_or_default() != 0 => Err(format!(
                "status {} deregistering extension: {}",
                res.code.unwrap_or_default(),
                res.message.unwrap_or_default()
            )
            .into()),
            Ok(_) => client.shutdown().map_err(Error::from),
        }
    }

    /// run starts the extension manager until osquery calls for a shutdown
    /// or the osquery instance goes away.
    pub fn run(mut self) -> Result<()> {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let ping_interval = self.ping_interval;
        let socket_path = self.socket_path.clone();

        self.start(tx.clone())?;

        // Watch for the osquery process going away. If so, initiate shutdown.
        std::thread::spawn(move || {
            match client::ExtensionManagerClient::new_with_path(&socket_path) {
                Ok(mut client) => loop {
                    std::thread::sleep(ping_interval);
                    if let Err(e) = client.ping() {
                        let msg = Error::from(e).message("extension ping failed");
                        tx.send(Some(msg)).ok();
                        break;
                    }
                },
                Err(e) => tx
                    .send(Some(Error::from(e).message("ping client failed")))
                    .unwrap(),
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
    fn handle_ping(&self) -> thrift::Result<osquery::ExtensionStatus> {
        Ok(osquery::ExtensionStatus::new(0, "OK".to_string(), None))
    }

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
                None => Ok(osquery::ExtensionResponse::new(
                    osquery::ExtensionStatus::new(
                        1,
                        format!("Unknown registry item: {}", item),
                        None,
                    ),
                    None,
                )),
            },
            None => Ok(osquery::ExtensionResponse::new(
                osquery::ExtensionStatus::new(1, format!("Unknown registry: {}", registry), None),
                None,
            )),
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

    // TODO: Once osqueryd mock is implemented then unit test run
    // #[test]
    // fn run() {
    //     let mut server = ExtensionManagerServer::new(
    //         String::from("test_server"),
    //         String::from("/var/osquery/osquery.em"),
    //     )
    //     .unwrap();
    //     server.ping_interval = std::time::Duration::from_secs(1);
    //     assert!(server.run().is_err(), "should fail if osqueryd is killed");
    // }

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
        let uuid = std::mem::replace(&mut server.uuid, Arc::new(None));

        assert!(server.shutdown().is_err(), "should error with uuid nil");

        server.uuid = uuid;
        server.start(tx).unwrap();

        let listen_path = server.listen_path.clone().unwrap();
        wait_for_extension_server(&listen_path);

        let shutdown_err = server.shutdown().err();
        assert!(
            shutdown_err.is_none(),
            "shutdown should be ok: {:?}",
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
}
