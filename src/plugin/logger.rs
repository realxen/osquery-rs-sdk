//! Create an osquery logging plugin.
//!
//! See <https://osquery.readthedocs.io/en/latest/development/logger-plugins/> for more.
use crate::{osquery, OsqueryPlugin, RegistryName, Result};
use serde_json::Value;
use std::{fmt, str::FromStr};

// encodes the type of log osquery is outputting.
#[non_exhaustive]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum LogType {
    Health,
    Init,
    Snapshot,
    Status,
    String,
    Log,
}

impl fmt::Display for LogType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogType::Health => write!(f, "health"),
            LogType::Init => write!(f, "init"),
            LogType::Snapshot => write!(f, "snapshot"),
            LogType::Status => write!(f, "status"),
            LogType::String => write!(f, "string"),
            LogType::Log => write!(f, "log"),
        }
    }
}

impl std::str::FromStr for LogType {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "health" => Ok(LogType::Health),
            "init" => Ok(LogType::Init),
            "snapshot" => Ok(LogType::Snapshot),
            "status" => Ok(LogType::Status),
            "log" => Ok(LogType::Log),
            "string" => Ok(LogType::String),
            other => Err(format!("unknown log type: {other}")),
        }
    }
}

/// Osquery logger plugin. That implement the `OsqueryPlugin` interface
/// * `LogFunc`: should log the provided result string. The `LogType`
// argument can be optionally used to log differently depending on the
// type of log received.
pub struct LoggerPlugin<LogFunc: FnMut(LogType, &str) -> Result<()>> {
    name: String,
    log_fn: LogFunc,
}

impl<LogFunc: FnMut(LogType, &str) -> Result<()>> LoggerPlugin<LogFunc> {
    /// Create a `LoggerPlugin` plugin.
    /// * [`LogFunc`]: should log the provided result string.
    pub fn new(name: &str, log_fn: LogFunc) -> Self {
        Self {
            name: name.to_string(),
            log_fn,
        }
    }
}

impl<LogFunc: FnMut(LogType, &str) -> Result<()> + Send + Sync> OsqueryPlugin
    for LoggerPlugin<LogFunc>
{
    fn name(&self) -> &str {
        &self.name
    }

    fn registry_name(&self) -> RegistryName {
        RegistryName::Logger
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(skip(self, req), fields(plugin = %self.name))
    )]
    fn call(&mut self, req: osquery::ExtensionPluginRequest) -> osquery::ExtensionResponse {
        let mut errors = Vec::new();
        for (typ, log) in &req {
            match LogType::from_str(typ) {
                Err(_) => errors.push(format!("cannot log request type: {typ}")),
                Ok(LogType::Status) => match req.get("log") {
                    Some(data) if data.is_empty() => errors.push(String::from("got empty status")),
                    Some(data) => {
                        // Dirty hack because osquery gives us malformed JSON.
                        let mut status_json = data.replace(r#""":"#, "");
                        status_json = status_json.replacen('{', "[", 1);
                        if let Some(last) = status_json.rfind('}') {
                            status_json.replace_range(last.., "]");
                        }

                        match serde_json::from_str::<Value>(&status_json) {
                            Err(err) => errors.push(format!("error parsing status logs: {err}")),
                            Ok(Value::Array(arr)) => {
                                for s in &arr {
                                    if let Err(err) = (self.log_fn)(LogType::Status, &s.to_string())
                                    {
                                        errors.push(format!("error logging status: {err}"));
                                    }
                                }
                            }
                            _ => errors.push(String::from("error parsing status logs")),
                        }
                    }
                    None => errors.push(String::from("got empty status")),
                },
                Ok(LogType::Log) => {}
                Ok(ltype) => {
                    if let Err(err) = (self.log_fn)(ltype, log) {
                        errors.push(format!("{err} for type: {typ}"));
                    }
                }
            }
        }

        if !errors.is_empty() {
            return osquery::ExtensionResponse::new(
                osquery::ExtensionStatus::new(1, format!("error {}", errors.join(", ")), None),
                None,
            );
        }

        osquery::ExtensionResponse::new(
            osquery::ExtensionStatus::new(0, String::from("OK"), None),
            osquery::ExtensionPluginResponse::new(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logger_plugin() {
        let mut status_calls = 0;
        let mut last_status_log = String::new();
        let status_ok = osquery::ExtensionStatus::new(0, String::from("OK"), None);

        // Basic methods and Log string
        let mut plugin = LoggerPlugin::new("mock", |typ, log| {
            match typ {
                LogType::Health => {
                    assert_eq!(typ.to_string(), "health".to_string());
                    assert_eq!(log, "logged health");
                }
                LogType::Init => {
                    assert_eq!(typ.to_string(), "init".to_string());
                    assert_eq!(log, "logged init");
                }
                LogType::Snapshot => {
                    assert_eq!(typ.to_string(), "snapshot".to_string());
                    assert_eq!(log, "logged snapshot");
                }
                LogType::Status => {
                    last_status_log = log.to_string();
                    status_calls += 1;
                }
                LogType::String => {
                    assert_eq!(typ.to_string(), "string".to_string());
                    assert_eq!(log, "logged string");
                }
                _ => {}
            };
            Ok(())
        });

        assert_eq!(plugin.name(), "mock");
        assert_eq!(plugin.registry_name(), RegistryName::Logger);

        let res = plugin.call(osquery::ExtensionPluginRequest::from([
            ("snapshot".to_string(), "logged snapshot".to_string()),
            ("string".to_string(), "logged string".to_string()),
            ("health".to_string(), "logged health".to_string()),
            ("init".to_string(), "logged init".to_string()),
            ("status".to_string(), "true".to_string()),
            (String::from("log"), String::from(r#"{"":{"s":"0","f":"events.cpp","i":"828","m":"Event publisher failed setup: kernel: Cannot access \/dev\/osquery"},"":{"s":"0","f":"events.cpp","i":"828","m":"Event publisher failed setup: scnetwork: Publisher not used"},"":{"s":"0","f":"scheduler.cpp","i":"74","m":"Executing scheduled query macos_kextstat: SELECT * FROM time"}}"#)),
        ]));

        assert_eq!(res.status.unwrap(), status_ok);
        assert_eq!(last_status_log, r#"{"f":"scheduler.cpp","i":"74","m":"Executing scheduled query macos_kextstat: SELECT * FROM time","s":"0"}"#.to_string());
        assert_eq!(
            status_calls, 3,
            "status should be called based on the logs log array"
        );
    }

    #[test]
    fn logger_plugin_error() {
        let mut called = false;
        // Basic methods and Log string
        let mut plugin = LoggerPlugin::new("mock", |_typ, _log| {
            called = true;
            Err("log_fn_foobar".into())
        });

        assert_eq!(
            0,
            plugin
                .call(osquery::ExtensionPluginRequest::from([]))
                .status
                .unwrap()
                .code
                .unwrap()
        );

        // Unknown log types should now return error status
        assert_eq!(
            1,
            plugin
                .call(osquery::ExtensionPluginRequest::from([(
                    "custom".to_string(),
                    "".to_string()
                )]))
                .status
                .unwrap()
                .code
                .unwrap()
        );

        // Call with empty status
        assert_eq!(
            1,
            plugin
                .call(osquery::ExtensionPluginRequest::from([
                    ("status".to_string(), "true".to_string()),
                    ("log".to_string(), "".to_string())
                ]))
                .status
                .unwrap()
                .code
                .unwrap()
        );

        // Call with good action but logging fails
        let res = plugin
            .call(osquery::ExtensionPluginRequest::from([(
                "string".to_string(),
                "logged true".to_string(),
            )]))
            .status
            .unwrap();

        assert_eq!(1, res.code.unwrap());
        assert_eq!(
            "error log_fn_foobar for type: string".to_string(),
            res.message.unwrap()
        );

        // call with multiple errors
        let res = plugin
            .call(osquery::ExtensionPluginRequest::from([
                ("string".to_string(), "logged true".to_string()),
                ("init".to_string(), "logged true".to_string()),
                ("unknown_type".to_string(), "logged true".to_string()),
            ]))
            .status
            .unwrap();

        // BTreeMap iterates in sorted order: init, string, unknown_type
        let msg = res.message.unwrap();
        assert!(
            msg.contains("log_fn_foobar for type: init"),
            "should contain init error: {msg}"
        );
        assert!(
            msg.contains("log_fn_foobar for type: string"),
            "should contain string error: {msg}"
        );
        assert!(
            msg.contains("cannot log request type: unknown_type"),
            "should contain unknown_type error: {msg}"
        );
    }
}
