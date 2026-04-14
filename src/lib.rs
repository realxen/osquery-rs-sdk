//! Rust bindings for creating `osquery` extensions in Rust.
//!
//! This crate implements the components required to build a working
//! osquery plugin server and client.

use std::{fmt, io, result};

mod osquery; // Auto-generated bindings from Thrift.

#[cfg(feature = "client")]
mod client;

#[cfg(feature = "server")]
mod server;

#[cfg(feature = "plugins")]
pub mod plugin;

#[cfg(feature = "client")]
pub use crate::client::*;
#[cfg(feature = "server")]
pub use crate::server::*;

/// A specialized [`Result`] type for Plugin operations.
///
/// This type is broadly used across [`osquery_rs::plugin`] for any operation which may
/// produce an error.
///
/// This typedef is generally used to avoid writing out [`osquery_rs::plugin::Error`] directly and
/// is otherwise a direct mapping to [`Result`].
pub type Result<T> = result::Result<T, Error>;

/// Error type returned by all the plugins.
pub struct Error {
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
    message: Option<String>,
}

impl std::error::Error for Error {}

impl Error {
    pub fn message(self, message: &str) -> Self {
        let message = Some(message.to_string());
        match self.message {
            Some(_) => Self {
                message,
                source: Some(self.into()),
            },
            None => Self {
                source: self.source,
                message,
            },
        }
    }
}

impl<'a> From<&'a str> for Error {
    fn from(s: &'a str) -> Self {
        Error {
            source: None,
            message: Some(s.to_string()),
        }
    }
}
impl From<String> for Error {
    fn from(s: String) -> Self {
        Error {
            source: None,
            message: Some(s),
        }
    }
}
impl From<thrift::Error> for Error {
    fn from(err: thrift::Error) -> Self {
        Error {
            source: Some(match err {
                thrift::Error::Transport(src) => {
                    format!("{}: TransportKind({:?})", src.message, src.kind).into()
                }
                thrift::Error::Protocol(src) => {
                    format!("{}: ProtocolKind({:?})", src.message, src.kind).into()
                }
                thrift::Error::Application(src) => {
                    format!("{}: ApplicationKind({:?})", src.message, src.kind).into()
                }
                thrift::Error::User(src) => src,
            }),
            message: None,
        }
    }
}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error {
            source: Some(Box::new(e)),
            message: None,
        }
    }
}
impl From<Error> for Option<String> {
    fn from(this: Error) -> Self {
        Some(format!("{}", this))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(e) = &self.message {
            write!(f, "{}", e)?;
            if self.source.is_some() {
                write!(f, " - ")?;
            }
        }
        if let Some(e) = &self.source {
            write!(f, "{}", e)?;
        }
        Ok(())
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("Error");
        if let Some(e) = &self.message {
            debug.field("message", e);
        }
        if let Some(e) = &self.source {
            debug.field("source", e);
        }
        debug.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_from_thrift() {
        let err = Error::from(thrift::Error::from("test"));
        assert_eq!("test: ApplicationKind(Unknown)", err.to_string());
    }

    #[test]
    fn error_from_str() {
        let err = Error::from("test");
        assert_eq!("test", err.to_string());
        let err = Error::from(String::from("test1"));
        assert_eq!("test1", err.to_string());
    }

    #[test]
    fn error_with_msg() {
        let terr = thrift::Error::from("test");
        let err = Error::from(terr).message("hello");
        assert_eq!("hello - test: ApplicationKind(Unknown)", err.to_string());
    }

    #[test]
    fn error_msg_into() {
        let err: Error = "test".into();
        assert_eq!(err.message, Error::from("test").message);
        let err: Error = String::from("hello").into();
        assert_eq!(err.message, Error::from("hello").message);
        let err: Error = thrift::Error::from("test").into();
        assert_eq!("test: ApplicationKind(Unknown)", err.to_string());
    }

    #[test]
    fn error_msg_fmt() {
        let err: Error = "testing".into();
        assert_eq!(err.to_string(), "testing".to_string());
        let err: Error = thrift::Error::from("thrift err msg").into();
        assert_eq!(
            err.to_string(),
            r#"thrift err msg: ApplicationKind(Unknown)"#.to_string()
        );
        let err: Error = thrift::Error::Transport(thrift::TransportError::new(
            thrift::TransportErrorKind::AlreadyOpen,
            "hello transport",
        ))
        .into();
        assert_eq!(
            err.to_string(),
            r#"hello transport: TransportKind(AlreadyOpen)"#.to_string()
        );
        let err: Error = thrift::Error::from("thrift err msg").into();
        assert_eq!(
            err.message("error from thrift with message").to_string(),
            r#"error from thrift with message - thrift err msg: ApplicationKind(Unknown)"#
                .to_string()
        );
        assert_eq!(
            Error::from("initial msg test")
                .message("hello test")
                .to_string(),
            r#"hello test - initial msg test"#.to_string()
        );
        assert_eq!(
            Error::from(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
                .message("hello io")
                .to_string(),
            "hello io - broken pipe".to_string()
        );
    }
}
