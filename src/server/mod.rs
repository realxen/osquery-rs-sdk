use crate::osquery;
use std::fmt;

mod manager;
mod threaded;
pub use manager::{ExtensionManagerServer, ExtensionManagerServerBuilder, ShutdownHandle};

/// Supported plugin registry types.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RegistryName {
    Table,
    Logger,
    Config,
    Distributed,
}

impl fmt::Display for RegistryName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistryName::Table => write!(f, "table"),
            RegistryName::Logger => write!(f, "logger"),
            RegistryName::Config => write!(f, "config"),
            RegistryName::Distributed => write!(f, "distributed"),
        }
    }
}

impl std::str::FromStr for RegistryName {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "table" => Ok(RegistryName::Table),
            "logger" => Ok(RegistryName::Logger),
            "config" => Ok(RegistryName::Config),
            "distributed" => Ok(RegistryName::Distributed),
            other => Err(format!("Unknown registry: {other}")),
        }
    }
}

/// An osquery extension plugin.
pub trait OsqueryPlugin: Send + Sync {
    /// Return the plugin name (e.g. the table name it implements).
    fn name(&self) -> &str;

    /// Return the registry this plugin belongs to.
    fn registry_name(&self) -> RegistryName;

    /// Return the routes (column definitions, etc.) exposed by the plugin.
    fn routes(&self) -> osquery::ExtensionPluginResponse {
        osquery::ExtensionPluginResponse::new()
    }

    /// Health check. Returns status OK by default.
    fn ping(&self) -> osquery::ExtensionStatus {
        osquery::ExtensionStatus::new(0, "OK".to_string(), None)
    }

    /// Handle an incoming request from osquery.
    fn call(&mut self, req: osquery::ExtensionPluginRequest) -> osquery::ExtensionResponse;

    /// Called when the plugin is being shut down.
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
