#![allow(
    clippy::print_stdout,
    clippy::unwrap_used,
    clippy::needless_pass_by_value,
    clippy::unnecessary_wraps
)]

//! Example: writable table plugin with INSERT, UPDATE, and DELETE support.
//!
//! This demonstrates a simple key-value store exposed as a writable osquery
//! table. Rows can be queried with `SELECT`, added with `INSERT`, modified
//! with `UPDATE`, and removed with `DELETE`.
//!
//! ```sql
//! SELECT * FROM kv_store;
//! INSERT INTO kv_store (key, value) VALUES ('greeting', 'hello');
//! UPDATE kv_store SET value = 'world' WHERE key = 'greeting';
//! DELETE FROM kv_store WHERE key = 'greeting';
//! ```

use osquery_rs_sdk::{
    ColumnDefinition, DeleteRequest, ExtensionManagerServer, InsertRequest, MutationResult,
    QueryContext, Result, Table, TablePlugin, UpdateRequest,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

#[cfg(unix)]
const OSQUERY_SOCKET: &str = "/var/osquery/osquery.em";
#[cfg(windows)]
const OSQUERY_SOCKET: &str = r"\\.\pipe\osquery.em";

/// Shared in-memory store: row_id -> (key, value).
type Store = Arc<Mutex<BTreeMap<i64, (String, String)>>>;

fn main() -> Result<()> {
    let store: Store = Arc::new(Mutex::new(BTreeMap::new()));

    let gen_store = store.clone();
    let ins_store = store.clone();
    let upd_store = store.clone();
    let del_store = store.clone();

    let plugin = TablePlugin::writable(
        "kv_store",
        vec![
            ColumnDefinition::text("key").index(),
            ColumnDefinition::text("value"),
        ],
        move |_ctx: QueryContext| -> Result<Table> {
            let data = gen_store.lock().unwrap();
            Ok(data
                .values()
                .map(|(k, v)| {
                    BTreeMap::from([
                        ("key".to_string(), k.clone()),
                        ("value".to_string(), v.clone()),
                    ])
                })
                .collect())
        },
        move |req: InsertRequest| -> Result<MutationResult> {
            // values are in column-definition order: [key, value]
            let key = req
                .values
                .first()
                .and_then(|v| v.clone())
                .unwrap_or_default();
            let value = req
                .values
                .get(1)
                .and_then(|v| v.clone())
                .unwrap_or_default();
            let row_id = req.row_id.unwrap_or(0);
            println!("INSERT: key={key}, value={value}, row_id={row_id}");
            ins_store.lock().unwrap().insert(row_id, (key, value));
            Ok(MutationResult::Success {
                row_id: Some(row_id),
            })
        },
        move |req: UpdateRequest| -> Result<MutationResult> {
            // values are in column-definition order: [key, value]
            let key = req
                .values
                .first()
                .and_then(|v| v.clone())
                .unwrap_or_default();
            let value = req
                .values
                .get(1)
                .and_then(|v| v.clone())
                .unwrap_or_default();
            let id = req.new_row_id.unwrap_or(req.row_id);
            println!("UPDATE: row_id={} -> key={key}, value={value}", req.row_id);
            let mut data = upd_store.lock().unwrap();
            data.remove(&req.row_id);
            data.insert(id, (key, value));
            Ok(MutationResult::Success { row_id: None })
        },
        move |req: DeleteRequest| -> Result<MutationResult> {
            println!("DELETE: row_id={}", req.row_id);
            del_store.lock().unwrap().remove(&req.row_id);
            Ok(MutationResult::Success { row_id: None })
        },
    );

    let mut server = ExtensionManagerServer::new("writable_table_ext", OSQUERY_SOCKET)?;
    server.register_plugin(plugin)?;
    server.run_with_signal_handling()
}
