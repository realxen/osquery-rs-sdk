//! Half-asynchronous, half-synchronous implementation of an [Apache Thrift] server.
//! Full compatibility with code generation from the [`thrift`] crate (fully
//! synchronous), hence the almost-asynchronous (or half async, half sync)  model.

use std::{io, path::Path, sync::Arc};
use thrift::{
    Error as TError, TransportErrorKind as TErrorKind,
    protocol::{TBinaryInputProtocol, TBinaryOutputProtocol},
    server::TProcessor,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    runtime::Runtime,
    sync::watch,
};

#[cfg(unix)]
use tokio::net::UnixListener;
#[cfg(windows)]
use tokio::net::windows::named_pipe::ServerOptions;

/// A handle that can be used to stop a running [`ExtensionServer`].
///
/// Dropping the handle or calling [`stop`](StopHandle::stop) signals the
/// server's accept loop to exit. The server listener thread will finish
/// after completing any in-flight request.
#[derive(Clone, Debug)]
pub struct StopHandle {
    sender: watch::Sender<bool>,
}

impl StopHandle {
    /// Signal the server to stop accepting new connections and exit.
    pub fn stop(&self) {
        let _ = self.sender.send(true);
    }
}

pub struct ExtensionServer<PRC: TProcessor + Send + Sync + 'static> {
    processor: Arc<PRC>,
    runtime: Runtime,
    stop_rx: watch::Receiver<bool>,
    stop_tx: watch::Sender<bool>,
}

impl<PRC: TProcessor + Send + Sync + 'static> ExtensionServer<PRC> {
    /// Create a new almost-asynchronous server, from a synchronous request `TProcessor`.
    /// Input/Output protocol **must** be binary.
    pub fn new(processor: PRC) -> io::Result<ExtensionServer<PRC>> {
        let (stop_tx, stop_rx) = watch::channel(false);
        Ok(ExtensionServer {
            processor: Arc::new(processor),
            runtime: Runtime::new()?,
            stop_rx,
            stop_tx,
        })
    }

    /// Returns a [`StopHandle`] that can be used to stop the server from
    /// another thread. Calling [`StopHandle::stop`] will cause the accept
    /// loop in [`listen`](ExtensionServer::listen) to exit.
    pub fn stop_handle(&self) -> StopHandle {
        StopHandle {
            sender: self.stop_tx.clone(),
        }
    }

    /// Listen for incoming connections on a `listen_path`.
    pub fn listen<P: AsRef<Path>>(&mut self, path: P) -> io::Result<()> {
        #[cfg(unix)]
        return self.listen_uds(path);
        #[cfg(windows)]
        return self.listen_pipe(path);
    }

    #[cfg(windows)]
    fn listen_pipe<P: AsRef<Path>>(&mut self, path: P) -> io::Result<()> {
        let mut stop_rx = self.stop_rx.clone();
        self.runtime.block_on(async {
            let pipe_name = path.as_ref();
            let mut server = ServerOptions::new()
                .first_pipe_instance(true)
                .create(path.as_ref())?;
            loop {
                tokio::select! {
                    result = server.connect() => {
                        match result {
                            Ok(_) => {
                                // Rotate to a fresh pipe instance before handing the connected one to a task.
                                self.handle_connection(std::mem::replace(
                                    &mut server,
                                    ServerOptions::new().create(pipe_name)?,
                                ));
                            }
                            Err(e) => {
                                #[cfg(feature = "tracing")]
                                tracing::error!("failed to accept remote connection: {e:?}");
                                break;
                            }
                        }
                    }
                    _ = stop_rx.changed() => {
                        break;
                    }
                }
            }
            Ok(())
        })
    }

    #[cfg(unix)]
    #[allow(unused_variables)]
    fn listen_uds<P: AsRef<Path>>(&mut self, socket_path: P) -> io::Result<()> {
        let mut stop_rx = self.stop_rx.clone();
        self.runtime.block_on(async {
            let listener = UnixListener::bind(socket_path)?;
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        match result {
                            Ok((stream, _)) => self.handle_connection(stream),
                            Err(e) => {
                                #[cfg(feature = "tracing")]
                                tracing::error!("failed to accept remote connection: {e:?}");
                                break;
                            }
                        }
                    }
                    _ = stop_rx.changed() => {
                        break;
                    }
                }
            }
            Ok(())
        })
    }

    /// Handle incoming connections, keeping a `BufReader`. All read/write operations happen
    /// asynchronously (leveraging [`tokio`]). Processing happens synchronously within tokio's runtime.
    ///
    /// # Panics
    /// This function panics if thread-local runtime is not set.
    fn handle_connection<RW: AsyncRead + AsyncWrite + Send + 'static>(&self, stream: RW) {
        let processor = self.processor.clone();
        self.runtime.spawn(async move {
            let (mut reader, mut writer) = tokio::io::split(stream);
            let mut read_transport = BufReader::new(&mut reader);
            let mut write_buf = Vec::with_capacity(4096);
            loop {
                match read_transport.fill_buf().await {
                    Ok([]) => break, // EOF: peer closed connection
                    Ok(s) => {
                        let buf_count = s.len();
                        write_buf.clear();
                        let mut i_proto = TBinaryInputProtocol::new(s, false);
                        let mut o_proto = TBinaryOutputProtocol::new(&mut write_buf, true);

                        match processor.process(&mut i_proto, &mut o_proto) {
                            Ok(()) => {}
                            Err(err) => {
                                match err {
                                    TError::Transport(terr)
                                        if terr.kind == TErrorKind::EndOfFile => {}
                                    #[allow(unused_variables)]
                                    other => {
                                        #[cfg(feature = "tracing")]
                                        tracing::error!(
                                            "processor completed with error: {other:?}"
                                        );
                                    }
                                }
                                break;
                            }
                        }
                        // TODO: Break out on persistent write failures instead of retrying forever.
                        if writer.write_all(write_buf.as_ref()).await.is_ok() {
                            // Advance the read buffer only after the response has been written.
                            read_transport.consume(buf_count);
                        }
                    }
                    #[allow(unused_variables)]
                    Err(e) => {
                        #[cfg(feature = "tracing")]
                        tracing::error!("error reading stream: {e:?}");
                        break;
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::mock::MockExtensionServerHandler;
    use crate::{client, osquery};
    use std::path::PathBuf;

    // Use a unique socket per test case to avoid cross-test interference.
    fn init_server(name: &str) -> (PathBuf, StopHandle) {
        #[cfg(unix)]
        let socket: PathBuf = format!("/tmp/osquery_rs_sdk.server.{name}.test.em").into();
        #[cfg(windows)]
        let socket: PathBuf = format!(r"\\.\pipe\osquery_rs_sdk.server.{}.test.em", name).into();

        std::fs::remove_file(&socket).ok();

        let handler = MockExtensionServerHandler {};
        let processor = osquery::ExtensionSyncProcessor::new(handler);
        let mut server = ExtensionServer::new(processor).unwrap();
        let stop_handle = server.stop_handle();

        let socket_path = socket.clone();
        std::thread::spawn(move || {
            server.listen(socket_path).unwrap();
        });
        std::thread::sleep(std::time::Duration::from_millis(100));

        (socket, stop_handle)
    }

    #[test]
    fn client_ping() {
        let (test_socket, _stop) = init_server("client_ping_me");
        let mut client = client::ExtensionManagerClient::connect_with_path(test_socket).unwrap();
        client.ping().unwrap();
    }

    #[test]
    fn handle_connection() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (read_chan, mut write_chan) = tokio::io::duplex(64);
        let server = ExtensionServer::new(osquery::ExtensionSyncProcessor::new(
            MockExtensionServerHandler {},
        ))
        .unwrap();
        ExtensionServer::handle_connection(&server, read_chan);
        rt.block_on(async move {
            write_chan
                // TODO: Fix, this can fail if the protocol version changes
                // byte-slice = osquery::ExtensionStatus::new(0, "OK".to_string(), None)
                .write_all(&[128, 1, 0, 1, 0, 0, 0, 4, 112, 105, 110, 103, 0, 0, 0, 1, 0])
                .await
                .unwrap();
        });
    }

    #[test]
    fn processor() {
        const NTHREADS: u32 = 10;
        let (test_socket, _stop) = init_server("processor");
        let (tx, rx) = std::sync::mpsc::channel();
        let mut children = Vec::new();

        for id in 0..NTHREADS {
            let test_socket = test_socket.clone();
            // The sender endpoint can be copied
            let thread_tx = tx.clone();
            let child = std::thread::spawn(move || {
                let mut client = client::ExtensionManagerClient::connect_with_path(test_socket)
                    .unwrap_or_else(|e| panic!("error connecting id: {id} {e}"));
                for i in 0..(NTHREADS * 100) {
                    client
                        .ping()
                        .unwrap_or_else(|_| panic!("ping failed id: {id} {i}"));
                }
                thread_tx.send(id).unwrap();
            });
            children.push(child);
        }
        for _ in 0..NTHREADS {
            rx.recv().unwrap();
        }
    }

    #[test]
    fn stop_handle_stops_server() {
        let (test_socket, stop) = init_server("stop_handle");

        // Verify the server is running
        let mut client = client::ExtensionManagerClient::connect_with_path(&test_socket).unwrap();
        client.ping().unwrap();

        // Stop the server
        stop.stop();

        // Give the server time to shut down
        std::thread::sleep(std::time::Duration::from_millis(200));

        // New connections should fail
        let result = client::ExtensionManagerClient::connect_with_path(&test_socket);
        assert!(result.is_err(), "should not connect after stop");
    }
}
