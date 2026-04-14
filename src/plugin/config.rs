//! Create an osquery configuration plugin.
//!
//! See https://osquery.readthedocs.io/en/latest/development/config-plugins/ for more.
use crate::{osquery, OsqueryPlugin, RegistryName, Result};
use std::collections::BTreeMap;
use std::sync::Arc;

/// A map that should use the source name as key, and the config JSON as values.
type Config = BTreeMap<String, String>;

/// Osquery configuration plugin. That implement the OsqueryPlugin interface
/// * [`GenFunc`]: returns a map that should use the source name as key, and the config
///   JSON as values.
pub struct ConfigPlugin<GenFunc: FnMut() -> Result<Config>> {
    name: Arc<String>,
    registry: RegistryName,
    generate: GenFunc,
}

impl<GenFunc: FnMut() -> Result<Config>> ConfigPlugin<GenFunc> {
    /// creates a ConfigPlugin plugin.
    /// * [`GenFunc`]: should return a [`Result<BTreeMap<String, String>>`]
    ///   that uses the source name as key, and the config JSON as values.
    pub fn new(name: &str, generate: GenFunc) -> Box<Self> {
        Box::new(Self {
            name: Arc::from(name.to_string()),
            registry: RegistryName::Config,
            generate,
        })
    }
}

impl<GenFunc: FnMut() -> Result<Config> + Send + Sync> OsqueryPlugin for ConfigPlugin<GenFunc> {
    fn name(&self) -> std::sync::Arc<String> {
        Arc::clone(&self.name)
    }

    fn registry_name(&self) -> &RegistryName {
        &self.registry
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(skip(self, req), fields(plugin = %self.name))
    )]
    fn call(&mut self, req: osquery::ExtensionPluginRequest) -> osquery::ExtensionResponse {
        match req.get("action") {
            Some(action) if action == "genConfig" => match (self.generate)() {
                Ok(conf) => osquery::ExtensionResponse::new(
                    osquery::ExtensionStatus::new(0, String::from("OK"), None),
                    osquery::ExtensionPluginResponse::from([conf]),
                ),
                Err(err) => {
                    #[cfg(feature = "tracing")]
                    tracing::error!("error getting config: {}", err);
                    osquery::ExtensionResponse::new(
                        osquery::ExtensionStatus::new(1, err.message("error getting config"), None),
                        None,
                    )
                }
            },
            Some(action) => osquery::ExtensionResponse::new(
                osquery::ExtensionStatus::new(1, format!("unknown action: {}", action), None),
                None,
            ),
            None => osquery::ExtensionResponse::new(
                osquery::ExtensionStatus::new(1, String::from("action is nil"), None),
                None,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_plugin() {
        let mut called = false;
        let status_ok = osquery::ExtensionStatus::new(0, String::from("OK"), None);

        let mut plugin = ConfigPlugin::new("mock", || {
            called = true;
            Ok(BTreeMap::from([(
                "conf1".to_string(),
                "foobar".to_string(),
            )]))
        });

        assert_eq!(plugin.name().as_str(), "mock");
        assert_eq!(*plugin.registry_name(), RegistryName::Config);

        let res = plugin.call(osquery::ExtensionPluginRequest::from([(
            String::from("action"),
            String::from("genConfig"),
        )]));

        assert!(called, "generate function never called");
        assert_eq!(res.status.unwrap(), status_ok);
        assert_eq!(
            res.response.unwrap(),
            osquery::ExtensionPluginResponse::from([BTreeMap::from([(
                "conf1".to_string(),
                "foobar".to_string(),
            )])])
        );
    }

    #[test]
    fn config_plugin_error() {
        let mut plugin = ConfigPlugin::new("mock", || Err("foobar".into()));

        let res = plugin.call(osquery::ExtensionPluginRequest::from([(
            String::from("action"),
            String::from("genConfig"),
        )]));
        assert_eq!(res.status.clone().unwrap().code.unwrap(), 1);
        assert_eq!(
            res.status.unwrap().message.unwrap(),
            String::from(r#"error getting config - foobar"#)
        );
    }
}
