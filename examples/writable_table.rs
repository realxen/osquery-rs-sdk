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
    QueryContext, Result, Table, UpdateRequest, WritableTable, WritableTablePlugin,
};
use std::collections::BTreeMap;

#[cfg(unix)]
const OSQUERY_SOCKET: &str = "/var/osquery/osquery.em";
#[cfg(windows)]
const OSQUERY_SOCKET: &str = r"\\.\pipe\osquery.em";

/// In-memory key-value store exposed as a writable osquery table.
struct KvStore {
    data: BTreeMap<i64, (String, String)>,
}

impl KvStore {
    fn new() -> Self {
        Self {
            data: BTreeMap::new(),
        }
    }
}

impl WritableTable for KvStore {
    fn name(&self) -> &str {
        "kv_store"
    }

    fn columns(&self) -> Vec<ColumnDefinition> {
        vec![
            ColumnDefinition::text("key").index(),
            ColumnDefinition::text("value"),
        ]
    }

    fn generate(&mut self, _ctx: QueryContext) -> Result<Table> {
        Ok(self
            .data
            .values()
            .map(|(k, v)| {
                BTreeMap::from([
                    ("key".to_string(), k.clone()),
                    ("value".to_string(), v.clone()),
                ])
            })
            .collect())
    }

    fn insert(&mut self, req: InsertRequest) -> Result<MutationResult> {
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
        self.data.insert(row_id, (key, value));
        Ok(MutationResult::Success {
            row_id: Some(row_id),
        })
    }

    fn update(&mut self, req: UpdateRequest) -> Result<MutationResult> {
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
        self.data.remove(&req.row_id);
        self.data.insert(id, (key, value));
        Ok(MutationResult::Success { row_id: None })
    }

    fn delete(&mut self, req: DeleteRequest) -> Result<MutationResult> {
        println!("DELETE: row_id={}", req.row_id);
        self.data.remove(&req.row_id);
        Ok(MutationResult::Success { row_id: None })
    }
}

fn main() -> Result<()> {
    let mut server = ExtensionManagerServer::new("writable_table_ext", OSQUERY_SOCKET)?;
    server.register_plugin(WritableTablePlugin::new(KvStore::new()))?;
    server.run_with_signal_handling()
}
