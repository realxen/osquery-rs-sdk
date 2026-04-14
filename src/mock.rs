//! Public mock implementations for testing osquery extensions.
//!
//! Enable with the `mock` feature flag:
//! ```toml
//! [dev-dependencies]
//! osquery-rs-sdk = { version = "0.1", features = ["mock"] }
//! ```
//!
//! # MockExtensionManager
//!
//! Implements [`ExtensionManager`](crate::client::ExtensionManager) with injectable
//! function fields and invocation tracking. Unset functions return sensible defaults.
//!
//! ```rust,no_run
//! use osquery_rs_sdk::mock::MockExtensionManager;
//! use osquery_rs_sdk::ServerOption;
//!
//! let mock = MockExtensionManager::new();
//! // Use as a server client:
//! // ServerOption::WithClient(Box::new(mock))
//! ```

use crate::{client::ExtensionManager, osquery};
use std::sync::Mutex;
use thrift::Result as TResult;

// ---------------------------------------------------------------------------
// Type aliases for mock function fields
// ---------------------------------------------------------------------------

type CloseFn = Box<dyn FnMut() + Send>;

type PingFn = Box<dyn FnMut() -> TResult<osquery::ExtensionStatus> + Send>;

type CallFn = Box<
    dyn FnMut(
            String,
            String,
            osquery::ExtensionPluginRequest,
        ) -> TResult<osquery::ExtensionResponse>
        + Send,
>;

type ShutdownMockFn = Box<dyn FnMut() -> TResult<()> + Send>;

type ExtensionsFn = Box<dyn FnMut() -> TResult<osquery::InternalExtensionList> + Send>;

type OptionsFn = Box<dyn FnMut() -> TResult<osquery::InternalOptionList> + Send>;

type RegisterExtensionFn = Box<
    dyn FnMut(
            osquery::InternalExtensionInfo,
            osquery::ExtensionRegistry,
        ) -> TResult<osquery::ExtensionStatus>
        + Send,
>;

type DeregisterExtensionFn =
    Box<dyn FnMut(osquery::ExtensionRouteUUID) -> TResult<osquery::ExtensionStatus> + Send>;

type QueryFn = Box<dyn FnMut(String) -> TResult<osquery::ExtensionResponse> + Send>;

// ---------------------------------------------------------------------------
// MockExtensionManager
// ---------------------------------------------------------------------------

/// A mock implementation of [`ExtensionManager`] for testing.
///
/// Each trait method has a corresponding `*_fn` field that can be set to
/// override the default behavior, and a `*_invoked` field that tracks
/// whether the method was called.
///
/// By default, methods return success with reasonable values (status code 0,
/// empty responses). Set a `*_fn` field to inject custom behavior.
pub struct MockExtensionManager {
    /// Override for [`ExtensionManager::close`]. Default: no-op.
    pub close_fn: Option<Mutex<CloseFn>>,
    /// Whether `close` was called.
    pub close_invoked: bool,

    /// Override for [`ExtensionManager::ping`]. Default: returns OK status.
    pub ping_fn: Option<Mutex<PingFn>>,
    /// Whether `ping` was called.
    pub ping_invoked: bool,

    /// Override for [`ExtensionManager::call`]. Default: returns OK with empty response.
    pub call_fn: Option<Mutex<CallFn>>,
    /// Whether `call` was called.
    pub call_invoked: bool,

    /// Override for [`ExtensionManager::shutdown`]. Default: returns Ok(()).
    pub shutdown_fn: Option<Mutex<ShutdownMockFn>>,
    /// Whether `shutdown` was called.
    pub shutdown_invoked: bool,

    /// Override for [`ExtensionManager::extensions`]. Default: returns empty list.
    pub extensions_fn: Option<Mutex<ExtensionsFn>>,
    /// Whether `extensions` was called.
    pub extensions_invoked: bool,

    /// Override for [`ExtensionManager::options`]. Default: returns empty list.
    pub options_fn: Option<Mutex<OptionsFn>>,
    /// Whether `options` was called.
    pub options_invoked: bool,

    /// Override for [`ExtensionManager::register_extension`]. Default: returns OK status with UUID 1.
    pub register_extension_fn: Option<Mutex<RegisterExtensionFn>>,
    /// Whether `register_extension` was called.
    pub register_extension_invoked: bool,

    /// Override for [`ExtensionManager::deregister_extension`]. Default: returns OK status.
    pub deregister_extension_fn: Option<Mutex<DeregisterExtensionFn>>,
    /// Whether `deregister_extension` was called.
    pub deregister_extension_invoked: bool,

    /// Override for [`ExtensionManager::query`]. Default: returns OK with empty response.
    pub query_fn: Option<Mutex<QueryFn>>,
    /// Whether `query` was called.
    pub query_invoked: bool,

    /// Override for [`ExtensionManager::get_query_columns`]. Default: returns OK with empty response.
    pub get_query_columns_fn: Option<Mutex<QueryFn>>,
    /// Whether `get_query_columns` was called.
    pub get_query_columns_invoked: bool,
}

impl MockExtensionManager {
    /// Creates a new mock with default (success) behavior for all methods.
    pub fn new() -> Self {
        Self {
            close_fn: None,
            close_invoked: false,
            ping_fn: None,
            ping_invoked: false,
            call_fn: None,
            call_invoked: false,
            shutdown_fn: None,
            shutdown_invoked: false,
            extensions_fn: None,
            extensions_invoked: false,
            options_fn: None,
            options_invoked: false,
            register_extension_fn: None,
            register_extension_invoked: false,
            deregister_extension_fn: None,
            deregister_extension_invoked: false,
            query_fn: None,
            query_invoked: false,
            get_query_columns_fn: None,
            get_query_columns_invoked: false,
        }
    }
}

impl Default for MockExtensionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns a default OK [`osquery::ExtensionStatus`].
fn ok_status() -> osquery::ExtensionStatus {
    osquery::ExtensionStatus::new(0, "OK".to_string(), None)
}

/// Returns a default OK [`osquery::ExtensionResponse`] with empty response.
fn ok_response() -> osquery::ExtensionResponse {
    osquery::ExtensionResponse::new(ok_status(), None)
}

impl ExtensionManager for MockExtensionManager {
    fn close(&mut self) {
        self.close_invoked = true;
        if let Some(f) = &self.close_fn {
            let mut guard = f.lock().expect("mock fn lock poisoned");
            guard();
        }
    }

    fn ping(&mut self) -> TResult<osquery::ExtensionStatus> {
        self.ping_invoked = true;
        match &self.ping_fn {
            Some(f) => {
                let mut guard = f.lock().expect("mock fn lock poisoned");
                guard()
            }
            None => Ok(ok_status()),
        }
    }

    fn call(
        &mut self,
        registry: String,
        item: String,
        request: osquery::ExtensionPluginRequest,
    ) -> TResult<osquery::ExtensionResponse> {
        self.call_invoked = true;
        match &self.call_fn {
            Some(f) => {
                let mut guard = f.lock().expect("mock fn lock poisoned");
                guard(registry, item, request)
            }
            None => Ok(ok_response()),
        }
    }

    fn shutdown(&mut self) -> TResult<()> {
        self.shutdown_invoked = true;
        match &self.shutdown_fn {
            Some(f) => {
                let mut guard = f.lock().expect("mock fn lock poisoned");
                guard()
            }
            None => Ok(()),
        }
    }

    fn extensions(&mut self) -> TResult<osquery::InternalExtensionList> {
        self.extensions_invoked = true;
        match &self.extensions_fn {
            Some(f) => {
                let mut guard = f.lock().expect("mock fn lock poisoned");
                guard()
            }
            None => Ok(osquery::InternalExtensionList::new()),
        }
    }

    fn options(&mut self) -> TResult<osquery::InternalOptionList> {
        self.options_invoked = true;
        match &self.options_fn {
            Some(f) => {
                let mut guard = f.lock().expect("mock fn lock poisoned");
                guard()
            }
            None => Ok(osquery::InternalOptionList::new()),
        }
    }

    fn register_extension(
        &mut self,
        info: osquery::InternalExtensionInfo,
        registry: osquery::ExtensionRegistry,
    ) -> TResult<osquery::ExtensionStatus> {
        self.register_extension_invoked = true;
        match &self.register_extension_fn {
            Some(f) => {
                let mut guard = f.lock().expect("mock fn lock poisoned");
                guard(info, registry)
            }
            None => Ok(osquery::ExtensionStatus::new(0, "OK".to_string(), Some(1))),
        }
    }

    fn deregister_extension(
        &mut self,
        uuid: osquery::ExtensionRouteUUID,
    ) -> TResult<osquery::ExtensionStatus> {
        self.deregister_extension_invoked = true;
        match &self.deregister_extension_fn {
            Some(f) => {
                let mut guard = f.lock().expect("mock fn lock poisoned");
                guard(uuid)
            }
            None => Ok(ok_status()),
        }
    }

    fn query(&mut self, sql: String) -> TResult<osquery::ExtensionResponse> {
        self.query_invoked = true;
        match &self.query_fn {
            Some(f) => {
                let mut guard = f.lock().expect("mock fn lock poisoned");
                guard(sql)
            }
            None => Ok(ok_response()),
        }
    }

    fn get_query_columns(&mut self, sql: String) -> TResult<osquery::ExtensionResponse> {
        self.get_query_columns_invoked = true;
        match &self.get_query_columns_fn {
            Some(f) => {
                let mut guard = f.lock().expect("mock fn lock poisoned");
                guard(sql)
            }
            None => Ok(ok_response()),
        }
    }
}

// ---------------------------------------------------------------------------
// MockPlugin
// ---------------------------------------------------------------------------

#[cfg(feature = "server")]
use crate::{OsqueryPlugin, RegistryName};
#[cfg(feature = "server")]
use std::sync::Arc;

/// A mock implementation of [`OsqueryPlugin`] for testing.
///
/// Each method has a corresponding `*_fn` field for overriding default behavior.
/// By default, `call` returns an empty response with status code 0.
#[cfg(feature = "server")]
pub struct MockPlugin {
    name: Arc<str>,
    registry_name: RegistryName,

    /// Override for [`OsqueryPlugin::call`]. Default: returns OK with empty response.
    pub call_fn: Option<
        Box<dyn FnMut(osquery::ExtensionPluginRequest) -> osquery::ExtensionResponse + Send + Sync>,
    >,
    /// Whether `call` was called.
    pub call_invoked: bool,

    /// Override for [`OsqueryPlugin::routes`]. Default: returns empty response.
    pub routes_fn: Option<Box<dyn FnMut() -> osquery::ExtensionPluginResponse + Send + Sync>>,
    /// Whether `routes` was called.
    pub routes_invoked: bool,

    /// Override for [`OsqueryPlugin::ping`]. Default: returns OK status.
    pub ping_fn: Option<Box<dyn FnMut() -> osquery::ExtensionStatus + Send + Sync>>,
    /// Whether `ping` was called.
    pub ping_invoked: bool,

    /// Override for [`OsqueryPlugin::shutdown`]. Default: no-op.
    pub shutdown_fn: Option<Box<dyn Fn() + Send + Sync>>,
    /// Whether `shutdown` was called.
    pub shutdown_invoked: bool,
}

#[cfg(feature = "server")]
impl MockPlugin {
    /// Creates a new mock plugin with the given name and registry.
    pub fn new(name: &str, registry_name: RegistryName) -> Box<Self> {
        Box::new(Self {
            name: Arc::from(name),
            registry_name,
            call_fn: None,
            call_invoked: false,
            routes_fn: None,
            routes_invoked: false,
            ping_fn: None,
            ping_invoked: false,
            shutdown_fn: None,
            shutdown_invoked: false,
        })
    }
}

#[cfg(feature = "server")]
impl OsqueryPlugin for MockPlugin {
    fn name(&self) -> Arc<str> {
        Arc::clone(&self.name)
    }

    fn registry_name(&self) -> &RegistryName {
        &self.registry_name
    }

    fn routes(&mut self) -> osquery::ExtensionPluginResponse {
        self.routes_invoked = true;
        match &mut self.routes_fn {
            Some(f) => f(),
            None => osquery::ExtensionPluginResponse::new(),
        }
    }

    fn ping(&mut self) -> osquery::ExtensionStatus {
        self.ping_invoked = true;
        match &mut self.ping_fn {
            Some(f) => f(),
            None => osquery::ExtensionStatus::new(0, "OK".to_string(), None),
        }
    }

    fn call(&mut self, req: osquery::ExtensionPluginRequest) -> osquery::ExtensionResponse {
        self.call_invoked = true;
        match &mut self.call_fn {
            Some(f) => f(req),
            None => ok_response(),
        }
    }

    fn shutdown(&self) {
        // Note: shutdown takes &self so we can't set shutdown_invoked here.
        // Use the shutdown_fn for custom behavior.
        if let Some(f) = &self.shutdown_fn {
            f();
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_extension_manager_defaults() {
        let mut mock = MockExtensionManager::new();

        // All invoked flags start false
        assert!(!mock.ping_invoked);
        assert!(!mock.call_invoked);
        assert!(!mock.close_invoked);

        // Ping returns OK by default
        let status = mock.ping().unwrap();
        assert_eq!(status.code.unwrap(), 0);
        assert!(mock.ping_invoked);

        // Call returns OK by default
        let resp = mock
            .call(
                "table".to_string(),
                "test".to_string(),
                osquery::ExtensionPluginRequest::new(),
            )
            .unwrap();
        assert_eq!(resp.status.unwrap().code.unwrap(), 0);
        assert!(mock.call_invoked);

        // Register returns OK with UUID 1
        let status = mock
            .register_extension(
                osquery::InternalExtensionInfo::new("test".to_string(), None, None, None),
                osquery::ExtensionRegistry::new(),
            )
            .unwrap();
        assert_eq!(status.code.unwrap(), 0);
        assert_eq!(status.uuid.unwrap(), 1);
        assert!(mock.register_extension_invoked);
    }

    #[test]
    fn mock_extension_manager_custom_fns() {
        let mut mock = MockExtensionManager::new();
        mock.ping_fn = Some(Mutex::new(Box::new(|| {
            Ok(osquery::ExtensionStatus::new(
                1,
                "custom error".to_string(),
                None,
            ))
        })));

        let status = mock.ping().unwrap();
        assert_eq!(status.code.unwrap(), 1);
        assert_eq!(status.message.unwrap(), "custom error");
        assert!(mock.ping_invoked);
    }

    #[test]
    fn mock_extension_manager_query() {
        let mut mock = MockExtensionManager::new();
        mock.query_fn = Some(Mutex::new(Box::new(|sql| {
            assert_eq!(sql, "SELECT 1");
            Ok(osquery::ExtensionResponse::new(
                osquery::ExtensionStatus::new(0, "OK".to_string(), None),
                Some(vec![std::collections::BTreeMap::from([(
                    "1".to_string(),
                    "1".to_string(),
                )])]),
            ))
        })));

        let resp = mock.query("SELECT 1".to_string()).unwrap();
        assert!(mock.query_invoked);
        assert_eq!(resp.response.unwrap().len(), 1);
    }

    #[test]
    fn mock_extension_manager_close_tracking() {
        let mut mock = MockExtensionManager::new();
        assert!(!mock.close_invoked);
        mock.close();
        assert!(mock.close_invoked);
    }

    #[cfg(feature = "server")]
    mod plugin_tests {
        use super::*;
        use crate::RegistryName;

        #[test]
        fn mock_plugin_defaults() {
            let mut plugin = MockPlugin::new("test_table", RegistryName::Table);

            assert_eq!(&*plugin.name(), "test_table");
            assert_eq!(*plugin.registry_name(), RegistryName::Table);

            // Call returns OK by default
            let resp = plugin.call(osquery::ExtensionPluginRequest::new());
            assert_eq!(resp.status.unwrap().code.unwrap(), 0);
            assert!(plugin.call_invoked);
        }

        #[test]
        fn mock_plugin_custom_call() {
            let mut plugin = MockPlugin::new("test_table", RegistryName::Table);
            plugin.call_fn = Some(Box::new(|_req| {
                osquery::ExtensionResponse::new(
                    osquery::ExtensionStatus::new(42, "custom".to_string(), None),
                    None,
                )
            }));

            let resp = plugin.call(osquery::ExtensionPluginRequest::new());
            assert_eq!(resp.status.unwrap().code.unwrap(), 42);
            assert!(plugin.call_invoked);
        }
    }
}
