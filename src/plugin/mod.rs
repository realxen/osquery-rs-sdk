pub mod config;
pub mod distributed;
pub mod logger;
pub mod table;

// Flat re-exports so users can write `use osquery_rs_sdk::plugin::*` or
// import individual items from the crate root.
pub use config::ConfigPlugin;
pub use distributed::{DistributedPlugin, QueriesRequest, QueryResponse, Stats};
pub use logger::{LogType, LoggerPlugin};
pub use table::{
    ColumnDefinition, ColumnType, Constraint, ConstraintList, InvalidOperator, Operator,
    QueryContext, Table, TablePlugin,
};
