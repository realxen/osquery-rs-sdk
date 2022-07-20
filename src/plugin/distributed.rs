//! Create an osquery distributed plugin.
//!
//! See https://osquery.readthedocs.io/en/latest/development/config-plugins/ for more.
use crate::{osquery, OsqueryPlugin, RegistryName, Result};
use serde::{
    de::{self, IntoDeserializer},
    Deserialize, Deserializer, Serialize,
};
use serde_json::Value;
use std::{collections::BTreeMap, result, sync::Arc};

// Returns the queries that should be executed.
// The returned map should include the query name as the keys, and the query
// text as values. Results will be returned corresponding to the provided name.
// The context argument can optionally be used for cancellation in long-running
// operations.
pub type QueriesResquestFunc = fn() -> Result<QueriesResquest>;

/// writes the results of the executed distributed queries. The
/// query results will be serialized JSON in the results map with the query name
/// as the key.
pub type QueriesResponseFunc = fn(Vec<QueryResponse>) -> Result<()>;

//// Contains the information about which queries the
/// distributed system should run.
#[derive(Debug, Deserialize, Serialize)]
pub struct QueriesResquest {
    /// Map from query name to query SQL
    queries: BTreeMap<String, String>,

    /// Used for "discovery" queries in the distributed
    /// system. When used, discovery queries should be specified with query
    /// name as the key and the discover query SQL as the value. If this is
    /// nonempty, only queries for which the associated discovery query
    /// returns results will be run in osquery.
    #[serde(default)]
    discovery: BTreeMap<String, String>,

    /// Can be specified to have "accelerated" checkins
    /// for a given number of seconds after this checkin. Currently this
    /// means that checkins will occur every 5 seconds.
    #[serde(default, rename = "accelerate")]
    accelerate_seconds: i64,
}

impl QueriesResquest {
    pub fn new(queries: BTreeMap<String, String>) -> Self {
        Self {
            queries,
            discovery: BTreeMap::new(),
            accelerate_seconds: 5,
        }
    }
}

/// Contains the status and results for a distributed query.
#[derive(Debug, Default, Deserialize)]
pub struct QueryResponse {
    /// Name that was originally provided for the query.
    pub query_name: String,
    /// Status code for the query execution (0 = OK)
    pub status: i64,
    /// Result rows of the query.
    pub rows: Vec<BTreeMap<String, String>>,
}

// Handles deserializing integers in noncanonical osquery json.
#[derive(Debug)]
struct OsqueryStatus(i64);

impl std::ops::Deref for OsqueryStatus {
    type Target = i64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<i64> for OsqueryStatus {
    fn from(inner: i64) -> Self {
        OsqueryStatus(inner)
    }
}

impl From<OsqueryStatus> for i64 {
    fn from(this: OsqueryStatus) -> Self {
        this.0
    }
}

impl TryFrom<&str> for OsqueryStatus {
    type Error = std::num::ParseIntError;
    fn try_from(value: &str) -> result::Result<Self, Self::Error> {
        Ok(OsqueryStatus(value.parse::<i64>()?))
    }
}

impl<'de> Deserialize<'de> for OsqueryStatus {
    fn deserialize<D>(deserializer: D) -> result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let helper: Value = Deserialize::deserialize(deserializer)?;
        match helper {
            // osquery < v3.0 with stringy types
            Value::String(s) if !s.is_empty() => {
                let op = s.parse::<i64>().map_err(de::Error::custom)?;
                OsqueryStatus::try_from(op)
                    .map_err(|_| de::Error::custom(format!("invalid value {}", op)))
            }
            // osquery > v3.0 with strong types
            Value::Number(n) if n.is_i64() => {
                let op = n
                    .as_i64()
                    .ok_or_else(|| de::Error::custom("expected int"))?;
                OsqueryStatus::try_from(op)
                    .map_err(|_| de::Error::custom(format!("invalid value {}", op)))
            }
            value => Err(de::Error::custom(format!(
                "invalid value {}, expected int",
                value,
            ))),
        }
    }
}

/// Used for deserializing the results passed from osquery.
#[derive(Debug, Deserialize)]
struct QueriesResponse {
    queries: BTreeMap<String, Value>,
    statuses: BTreeMap<String, OsqueryStatus>,
}

impl TryFrom<QueriesResponse> for Vec<QueryResponse> {
    type Error = String;

    fn try_from(this: QueriesResponse) -> result::Result<Self, Self::Error> {
        let mut responses = vec![];

        for (query_name, status) in this.statuses {
            if let Some(Value::Array(rows)) = this.queries.get(&query_name) {
                let rows: Vec<BTreeMap<String, String>> =
                    serde::Deserialize::deserialize(rows.clone().into_deserializer())
                        .map_err(|err| format!("{}: {}", query_name, err))?;
                responses.push(QueryResponse {
                    query_name,
                    status: status.into(),
                    rows,
                });
            }
        }

        Ok(responses)
    }
}

/// Osquery distributed plugin. That implement the OsqueryPlugin interface
pub struct DistributedPlugin {
    name: Arc<String>,
    registry: RegistryName,
    get_queries: QueriesResquestFunc,
    write_queries: QueriesResponseFunc,
}

impl DistributedPlugin {
    pub fn new(
        name: &str,
        get_queries: QueriesResquestFunc,
        write_queries: QueriesResponseFunc,
    ) -> Box<Self> {
        Box::new(Self {
            name: Arc::from(name.to_string()),
            registry: RegistryName::Distributed,
            get_queries,
            write_queries,
        })
    }
}

impl OsqueryPlugin for DistributedPlugin {
    fn name(&self) -> std::sync::Arc<String> {
        Arc::clone(&self.name)
    }

    fn registry_name(&self) -> &RegistryName {
        &self.registry
    }

    fn call(&mut self, req: osquery::ExtensionPluginRequest) -> osquery::ExtensionResponse {
        let result: Result<_> = match req.get("action") {
            // Call QueriesResquestFunc
            Some(action) if action == "getQueries" => {
                match (self.get_queries)() {
                    Ok(resq) => match serde_json::to_string(&resq) {
                        Ok(query_json) => Ok(osquery::ExtensionPluginResponse::from([
                            BTreeMap::from([("results".to_string(), query_json)]),
                        ])),
                        Err(err) => Err(format!("error deserializing queries: {}", err).into()),
                    },
                    Err(err) => Err(format!("error serializing queries: {}", err).into()),
                }
            }
            // Call QueriesResponseFunc
            Some(action) if action == "writeResults" => match req.get("results") {
                Some(results_json) => match serde_json::from_str::<QueriesResponse>(results_json) {
                    Ok(queries) => {
                        let query_resp: result::Result<Vec<QueryResponse>, _> = queries.try_into();
                        match query_resp {
                            Ok(results) => match (self.write_queries)(results) {
                                Ok(_) => Ok(osquery::ExtensionPluginResponse::default()),
                                Err(err) => Err(format!("error writing results: {}", err).into()),
                            },
                            Err(err) => Err(format!("error writing results: {}", err).into()),
                        }
                    }
                    Err(err) => Err(format!("error unmarshalling results: {}", err).into()),
                },
                None => Err(String::from("error results is nil").into()),
            },
            Some(action) => Err(format!("unknown action: {}", action).into()),
            None => Err(String::from("action is nil").into()),
        };

        match result {
            Ok(resp) => osquery::ExtensionResponse::new(
                osquery::ExtensionStatus::new(0, String::from("Ok"), None),
                resp,
            ),
            Err(err) => {
                let status = osquery::ExtensionStatus::new(1, err, None);
                osquery::ExtensionResponse::new(status, None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distributed_plugin() {
        let status_ok = osquery::ExtensionStatus::new(0, String::from("Ok"), None);
        let mut plugin = DistributedPlugin::new(
            "mock",
            move || {
                Ok(QueriesResquest::new(BTreeMap::from([
                    (
                        "query1".to_string(),
                        "select iso_8601 from time".to_string(),
                    ),
                    (
                        "query2".to_string(),
                        "select version from osquery_info".to_string(),
                    ),
                    ("query3".to_string(), "select foo from bar".to_string()),
                ])))
            },
            move |res| {
                assert_eq!(res.len(), 2);
                assert!(res.first().is_some());
                assert_eq!(res.first().unwrap().query_name, "query1".to_string());
                assert_eq!(res.first().unwrap().status, 0);
                assert_eq!(
                    res.first().unwrap().rows,
                    vec![BTreeMap::from([(
                        "iso_8601".to_string(),
                        "2017-07-10T22:08:40Z".to_string()
                    )])]
                );
                assert!(res.last().is_some());
                assert_eq!(res.last().unwrap().query_name, "query2".to_string());
                assert_eq!(res.last().unwrap().status, 0);
                assert_eq!(
                    res.last().unwrap().rows,
                    vec![BTreeMap::from([(
                        "version".to_string(),
                        "2.4.0".to_string()
                    )])]
                );
                Ok(())
            },
        );

        assert_eq!(plugin.name().as_str(), "mock");
        assert_eq!(*plugin.registry_name(), RegistryName::Distributed);

        // Call getQueries
        let resp = plugin.call(osquery::ExtensionPluginRequest::from([(
            String::from("action"),
            String::from("getQueries"),
        )]));
        assert_eq!(resp.status.unwrap(), status_ok);
        assert!(resp.response.is_some());

        assert!(resp.response.clone().unwrap()[0].contains_key("results"));
        assert!(resp.response.clone().unwrap()[0].get("results").is_some());
        assert_eq!(
            r#"{"queries":{"query1":"select iso_8601 from time","query2":"select version from osquery_info","query3":"select foo from bar"},"discovery":{},"accelerate":5}"#,
            resp.response.unwrap()[0].get("results").unwrap()
        );

        // Call writeResults with osquery < v3.0 with stringy types
        let resp = plugin.call(osquery::ExtensionPluginRequest::from([
            (String::from("action"), String::from("writeResults")),
            (String::from("results"), String::from(r#"{"queries":{"query1":[{"iso_8601":"2017-07-10T22:08:40Z"}],"query2":[{"version":"2.4.0"}]},"statuses":{"query1":"0","query2":"0","query3":"1"}}"#)),
        ]));
        assert_eq!(resp.status.unwrap(), status_ok);
        // Call writeResults with osquery > v3.0 with stringy types
        let resp = plugin.call(osquery::ExtensionPluginRequest::from([
            (String::from("action"), String::from("writeResults")),
            (String::from("results"), String::from(r#"{"queries":{"query1":[{"iso_8601":"2017-07-10T22:08:40Z"}],"query2":[{"version":"2.4.0"}]},"statuses":{"query1":0,"query2":0,"query3":1}}"#)),
        ]));
        assert_eq!(resp.status.unwrap(), status_ok);
    }

    #[test]
    fn distributed_plugin_accelerate_discovery() {
        let status_ok = osquery::ExtensionStatus::new(0, String::from("Ok"), None);
        let mut plugin = DistributedPlugin::new(
            "mock",
            move || {
                Ok(QueriesResquest {
                    queries: BTreeMap::from([(
                        "query1".to_string(),
                        "select * from time".to_string(),
                    )]),
                    discovery: BTreeMap::from([(
                        "query1".to_string(),
                        r#"select version from osquery_info where version = "2.4.0""#.to_string(),
                    )]),
                    accelerate_seconds: 30,
                })
            },
            move |_| Ok(()),
        );
        // Call getQueries
        let resp = plugin.call(osquery::ExtensionPluginRequest::from([(
            String::from("action"),
            String::from("getQueries"),
        )]));
        assert_eq!(resp.status.unwrap(), status_ok);
        assert!(resp.response.is_some());
        assert_eq!(resp.response.clone().unwrap().len(), 1);
        assert_eq!(
            *resp
                .response
                .unwrap()
                .get(0)
                .unwrap()
                .get("results")
                .unwrap(),
            r#"{"queries":{"query1":"select * from time"},"discovery":{"query1":"select version from osquery_info where version = \"2.4.0\""},"accelerate":30}"#.to_string()
        );
    }

    #[test]
    fn distributed_plugin_errors() {
        let mut plugin = DistributedPlugin::new(
            "mock",
            || Err("getQueries failed".into()),
            |_| Err("writeResults failed".into()),
        );
        // Call with bad actions
        let resp = plugin.call(osquery::ExtensionPluginRequest::from([(
            String::from("action"),
            String::from("bad"),
        )]));
        assert!(resp.response.is_none());
        assert!(resp.status.is_some());
        assert_eq!(resp.status.clone().unwrap().code.unwrap_or(0), 1);
        assert_eq!(
            resp.status.unwrap().message.unwrap(),
            "unknown action: bad".to_string()
        );

        // Call with good action but getQueries fails
        let resp = plugin.call(osquery::ExtensionPluginRequest::from([(
            String::from("action"),
            String::from("getQueries"),
        )]));
        assert!(resp.response.is_none());
        assert!(resp.status.is_some());
        assert_eq!(resp.status.clone().unwrap().code.unwrap_or(0), 1);
        assert_eq!(
            resp.status.unwrap().message.unwrap(),
            "error serializing queries: getQueries failed".to_string()
        );
        // Call with good action but getQueries fails
        let resp = plugin.call(osquery::ExtensionPluginRequest::from([
            (String::from("action"), String::from("writeResults")),
            (
                String::from("results"),
                String::from(r#"{"statuses": {"query1": "foo"}}"#),
            ),
        ]));
        assert!(resp.response.is_none());
        assert!(resp.status.is_some());
        assert_eq!(resp.status.clone().unwrap().code.unwrap_or(0), 1);
        assert_eq!(
            resp.status.unwrap().message.unwrap(),
            "error unmarshalling results: invalid digit found in string at line 1 column 30"
                .to_string()
        );
        // Call with good action but getQueries fails
        let resp = plugin.call(osquery::ExtensionPluginRequest::from([
            (String::from("action"), String::from("writeResults")),
            (
                String::from("results"),
                String::from(r#"{"statuses": {"query1": []}}"#),
            ),
        ]));
        assert!(resp.response.is_none());
        assert!(resp.status.is_some());
        assert_eq!(resp.status.clone().unwrap().code.unwrap_or(0), 1);
        assert_eq!(
            resp.status.unwrap().message.unwrap(),
            "error unmarshalling results: invalid value [], expected int at line 1 column 27"
                .to_string()
        );
        // Call with good action but getQueries fails
        let resp = plugin.call(osquery::ExtensionPluginRequest::from([
            (String::from("action"), String::from("writeResults")),
            (String::from("results"), String::from(r#"{"statuses": {}}"#)),
        ]));
        assert!(resp.response.is_none());
        assert!(resp.status.is_some());
        assert_eq!(resp.status.clone().unwrap().code.unwrap_or(0), 1);
        assert_eq!(
            resp.status.unwrap().message.unwrap(),
            "error unmarshalling results: missing field `queries` at line 1 column 16".to_string()
        )
    }

    #[test]
    fn deserialize_response() {
        const RAW_JSON_QUERY: &str = r#"{"queries":{"detail_query_network_interface":[{"interface":"en0","mac":"78:4f:43:9c:3c:8d","type":"","mtu":"1500","metric":"0","ipackets":"7071136","opackets":"6408727","ibytes":"1481456771","obytes":"1633052673","ierrors":"0","oerrors":"0","idrops":"0","odrops":"0","last_change":"1501077669","description":"","manufacturer":"","connection_id":"","connection_status":"","enabled":"","physical_adapter":"","speed":"","dhcp_enabled":"","dhcp_lease_expires":"","dhcp_lease_obtained":"","dhcp_server":"","dns_domain":"","dns_domain_suffix_search_order":"","dns_host_name":"","dns_server_search_order":"","interface":"en0","address":"192.168.1.135","mask":"255.255.255.0","broadcast":"192.168.1.255","point_to_point":"","type":""}],"detail_query_os_version":[{"name":"Mac OS X","version":"10.12.6","major":"10","minor":"12","patch":"6","build":"16G29","platform":"darwin","platform_like":"darwin","codename":""}],"detail_query_osquery_flags":[{"name":"config_refresh","value":"10"},{"name":"distributed_interval","value":"10"},{"name":"logger_tls_period","value":"10"}],"detail_query_osquery_info":[{"pid":"75680","uuid":"DE56C776-2F5A-56DF-81C7-F64EE1BBEC8C","instance_id":"89f267fa-9a17-4a73-87d6-05197491f2e8","version":"2.5.0","config_hash":"960121acb9bcbb136ce49fe77000752f237fd0dd","config_valid":"1","extensions":"active","build_platform":"darwin","build_distro":"10.12","start_time":"1502371429","watcher":"75678"}],"detail_query_system_info":[{"hostname":"Johns-MacBook-Pro.local","uuid":"DE56C776-2F5A-56DF-81C7-F64EE1BBEC8C","cpu_type":"x86_64h","cpu_subtype":"Intel x86-64h Haswell","cpu_brand":"Intel(R) Core(TM) i7-6820HQ CPU @ 2.70GHz","cpu_physical_cores":"4","cpu_logical_cores":"8","physical_memory":"17179869184","hardware_vendor":"Apple Inc.","hardware_model":"MacBookPro13,3","hardware_version":"1.0","hardware_serial":"C02SP067H040","computer_name":"","local_hostname":"Johns-MacBook-Pro"}],"detail_query_uptime":[{"days":"21","hours":"18","minutes":"44","seconds":"28","total_seconds":"1881868"}],"label_query_6":[{"1":"1"}],"label_query_9":"","detail_query_network_interface":[{"interface":"en0","mac":"78:4f:43:9c:3c:8d","type":"","mtu":"1500","metric":"0","ipackets":"7071178","opackets":"6408775","ibytes":"1481473778","obytes":"1633061382","ierrors":"0","oerrors":"0","idrops":"0","odrops":"0","last_change":"1501077680","description":"","manufacturer":"","connection_id":"","connection_status":"","enabled":"","physical_adapter":"","speed":"","dhcp_enabled":"","dhcp_lease_expires":"","dhcp_lease_obtained":"","dhcp_server":"","dns_domain":"","dns_domain_suffix_search_order":"","dns_host_name":"","dns_server_search_order":"","interface":"en0","address":"192.168.1.135","mask":"255.255.255.0","broadcast":"192.168.1.255","point_to_point":"","type":""}],"detail_query_os_version":[{"name":"Mac OS X","version":"10.12.6","major":"10","minor":"12","patch":"6","build":"16G29","platform":"darwin","platform_like":"darwin","codename":""}],"detail_query_osquery_flags":[{"name":"config_refresh","value":"10"},{"name":"distributed_interval","value":"10"},{"name":"logger_tls_period","value":"10"}],"detail_query_osquery_info":[{"pid":"75680","uuid":"DE56C776-2F5A-56DF-81C7-F64EE1BBEC8C","instance_id":"89f267fa-9a17-4a73-87d6-05197491f2e8","version":"2.5.0","config_hash":"960121acb9bcbb136ce49fe77000752f237fd0dd","config_valid":"1","extensions":"active","build_platform":"darwin","build_distro":"10.12","start_time":"1502371429","watcher":"75678"}],"detail_query_system_info":[{"hostname":"Johns-MacBook-Pro.local","uuid":"DE56C776-2F5A-56DF-81C7-F64EE1BBEC8C","cpu_type":"x86_64h","cpu_subtype":"Intel x86-64h Haswell","cpu_brand":"Intel(R) Core(TM) i7-6820HQ CPU @ 2.70GHz","cpu_physical_cores":"4","cpu_logical_cores":"8","physical_memory":"17179869184","hardware_vendor":"Apple Inc.","hardware_model":"MacBookPro13,3","hardware_version":"1.0","hardware_serial":"C02SP067H040","computer_name":"","local_hostname":"Johns-MacBook-Pro"}],"detail_query_uptime":[{"days":"21","hours":"18","minutes":"44","seconds":"38","total_seconds":"1881878"}],"label_query_6":[{"1":"1"}],"label_query_9":"","detail_query_network_interface":[{"interface":"en0","mac":"78:4f:43:9c:3c:8d","type":"","mtu":"1500","metric":"0","ipackets":"7071216","opackets":"6408814","ibytes":"1481486677","obytes":"1633066361","ierrors":"0","oerrors":"0","idrops":"0","odrops":"0","last_change":"1501077688","description":"","manufacturer":"","connection_id":"","connection_status":"","enabled":"","physical_adapter":"","speed":"","dhcp_enabled":"","dhcp_lease_expires":"","dhcp_lease_obtained":"","dhcp_server":"","dns_domain":"","dns_domain_suffix_search_order":"","dns_host_name":"","dns_server_search_order":"","interface":"en0","address":"192.168.1.135","mask":"255.255.255.0","broadcast":"192.168.1.255","point_to_point":"","type":""}],"detail_query_os_version":[{"name":"Mac OS X","version":"10.12.6","major":"10","minor":"12","patch":"6","build":"16G29","platform":"darwin","platform_like":"darwin","codename":""}],"detail_query_osquery_flags":[{"name":"config_refresh","value":"10"},{"name":"distributed_interval","value":"10"},{"name":"logger_tls_period","value":"10"}],"detail_query_osquery_info":[{"pid":"75680","uuid":"DE56C776-2F5A-56DF-81C7-F64EE1BBEC8C","instance_id":"89f267fa-9a17-4a73-87d6-05197491f2e8","version":"2.5.0","config_hash":"960121acb9bcbb136ce49fe77000752f237fd0dd","config_valid":"1","extensions":"active","build_platform":"darwin","build_distro":"10.12","start_time":"1502371429","watcher":"75678"}],"detail_query_system_info":[{"hostname":"Johns-MacBook-Pro.local","uuid":"DE56C776-2F5A-56DF-81C7-F64EE1BBEC8C","cpu_type":"x86_64h","cpu_subtype":"Intel x86-64h Haswell","cpu_brand":"Intel(R) Core(TM) i7-6820HQ CPU @ 2.70GHz","cpu_physical_cores":"4","cpu_logical_cores":"8","physical_memory":"17179869184","hardware_vendor":"Apple Inc.","hardware_model":"MacBookPro13,3","hardware_version":"1.0","hardware_serial":"C02SP067H040","computer_name":"","local_hostname":"Johns-MacBook-Pro"}],"detail_query_uptime":[{"days":"21","hours":"18","minutes":"44","seconds":"49","total_seconds":"1881889"}],"label_query_6":[{"1":"1"}],"label_query_9":""},"statuses":{"detail_query_network_interface":"0","detail_query_os_version":"0","detail_query_osquery_flags":"0","detail_query_osquery_info":"0","detail_query_system_info":"0","detail_query_uptime":"0","label_query_6":"0","label_query_9":"0"}}"#;
        let queries: QueriesResponse = serde_json::from_str(RAW_JSON_QUERY).unwrap();
        let resp: result::Result<Vec<QueryResponse>, _> = queries.try_into();
        assert!(resp.is_ok());
        assert_eq!(resp.unwrap().len(), 7);
    }

    #[test]
    fn deserialize_status() {
        // should_fail, data, expected
        let test_cases = vec![
            // from str
            (false, r#"{"status": "0"}"#, OsqueryStatus(0)),
            (false, r#"{"status": "1"}"#, OsqueryStatus(1)),
            (false, r#"{"status": "000"}"#, OsqueryStatus(0)),
            (false, r#"{"status": "-12"}"#, OsqueryStatus(-12)),
            // from int
            (false, r#"{"status": 0}"#, OsqueryStatus(0)),
            (false, r#"{"status": 1}"#, OsqueryStatus(1)),
            (false, r#"{"status": -12}"#, OsqueryStatus(-12)),
            // should fail
            (true, r#"foo"#, OsqueryStatus(0)),
            (true, r#"{"status": ""}"#, OsqueryStatus(0)),
            (true, r#"{"status": 000}"#, OsqueryStatus(0)),
            (
                true,
                r#"{"status": "9223372036854775807887766554433"}"#,
                OsqueryStatus(0),
            ),
            (
                true,
                r#"{"status": 9223372036854775807887766554433}"#,
                OsqueryStatus(0),
            ),
            (true, r#"{"status": []}"#, OsqueryStatus(0)),
        ];
        for (should_err, data, expected) in test_cases {
            let status: result::Result<BTreeMap<String, OsqueryStatus>, _> =
                serde_json::from_str(data);
            match status {
                Ok(s) => {
                    assert!(!should_err);
                    assert_eq!(expected.0, s.get("status").unwrap().0);
                }
                Err(err) => {
                    println!("{:?}", err);
                    assert!(should_err);
                }
            }
        }
        let stat: i64 = OsqueryStatus(12).into();
        assert_eq!(12, stat);
    }
}
