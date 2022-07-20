use crate::osquery;
use std::{fmt, sync::Arc};

mod manager;
mod threaded;
pub use manager::*;

/// RegistryNames contains the allowable registry_name values. If a plugin
/// attempts to register with another value, the program will panic.
#[derive(PartialEq, Debug)]
pub enum RegistryName {
    Table,
    Logger,
    Config,
    Distributed,
}

impl fmt::Display for RegistryName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            RegistryName::Table => write!(f, "table"),
            RegistryName::Logger => write!(f, "logger"),
            RegistryName::Config => write!(f, "config"),
            RegistryName::Distributed => write!(f, "distributed"),
        }
    }
}

/// OsqueryPlugin represents an osquery plugin.
pub trait OsqueryPlugin: Send + Sync {
    /// Name used to refer to the plugin (eg. the name of the
    /// table the plugin implements).
    fn name(&self) -> Arc<String>;

    /// Which "registry" the plugin should be added to.
    fn registry_name(&self) -> &RegistryName;

    /// Returns the detailed information about the interface exposed
    /// by the plugin. See the example plugins for samples.
    fn routes(&mut self) -> osquery::ExtensionPluginResponse {
        osquery::ExtensionPluginResponse::new()
    }

    /// Implements a health check for the plugin. If the plugin is in a
    /// healthy state, StatusOK should be returned.
    fn ping(&mut self) -> osquery::ExtensionStatus {
        osquery::ExtensionStatus::new(0, "OK".to_string(), None)
    }

    /// Requests the plugin to perform its defined behavior, returning
    /// a response containing the result.
    fn call(&mut self, req: osquery::ExtensionPluginRequest) -> osquery::ExtensionResponse;

    /// Alerts the plugin to stop.
    fn shutdown(&self) {}
}

impl std::fmt::Debug for Box<dyn OsqueryPlugin> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Box::OsqueryPlugin")
            .field(&self.name())
            .field(&self.registry_name().to_string())
            .finish()
    }
}

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_name() {
        assert_eq!(RegistryName::Table.to_string(), String::from("table"));
        assert_eq!(RegistryName::Logger.to_string(), String::from("logger"));
        assert_eq!(RegistryName::Config.to_string(), String::from("config"));
        assert_eq!(
            RegistryName::Distributed.to_string(),
            String::from("distributed")
        );
    }
}
