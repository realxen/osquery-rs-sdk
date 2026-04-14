//! Half-asynchrounous, half-synchrounous implementation of an [Apache Thrift] server.
//! Full compatibility with code generation from the [`thrift`] crate (fully
//! synchronous), hence the almost-asynchronous (or half async, half sync)  model.

use std::{io, path::Path, sync::Arc};
use thrift::{
    protocol::{TBinaryInputProtocol, TBinaryOutputProtocol},
    server::TProcessor,
    Error as TError, TransportErrorKind as TErrorKind,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    runtime::Runtime,
};

#[cfg(windows)]
use tokio::net::windows::named_pipe::ServerOptions;
#[cfg(unix)]
use tokio::net::UnixListener;

pub struct ExtensionServer<PRC: TProcessor + Send + Sync + 'static> {
    processor: Arc<PRC>,
    runtime: Runtime,
}

impl<PRC: TProcessor + Send + Sync + 'static> ExtensionServer<PRC> {
    /// Create a new almost-asynchronous server, from a synchronous request `TProcessor`.
    /// Input/Output protocol **must** be binary.
    pub fn new(processor: PRC) -> io::Result<ExtensionServer<PRC>> {
        Ok(ExtensionServer {
            processor: Arc::new(processor),
            runtime: Runtime::new()?,
        })
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
        self.runtime.block_on(async {
            let pipe_name = path.as_ref();
            let mut server = ServerOptions::new()
                .first_pipe_instance(true)
                .create(path.as_ref())?;
            loop {
                match server.connect().await {
                    Ok(_) => {
                        // Rotate to a fresh pipe instance before handing the connected one to a task.
                        self.handle_connection(std::mem::replace(
                            &mut server,
                            ServerOptions::new().create(pipe_name)?,
                        ))?;
                    }
                    Err(e) => {
                        break eprintln!("failed to accept remote connection with error {:?}", e)
                    }
                }
            }
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "aborted listen loop",
            ))
        })
    }

    #[cfg(unix)]
    fn listen_uds<P: AsRef<Path>>(&mut self, socket_path: P) -> io::Result<()> {
        self.runtime.block_on(async {
            let listener = UnixListener::bind(socket_path)?;
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => self.handle_connection(stream)?,
                    Err(e) => {
                        break eprintln!("failed to accept remote connection with error {:?}", e)
                    }
                }
            }
            Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "aborted listen loop",
            ))
        })
    }

    /// handles incoming connections, keeping a `BufReader`: All read/write operations happen
    /// asynchronously (leveraging [`tokio`]). processing happen synchronously within tokio's runtime.
    ///
    /// # Panics
    /// This function panics if thread-local runtime is not set.
    fn handle_connection<RW: AsyncRead + AsyncWrite + Send + 'static>(
        &self,
        stream: RW,
    ) -> io::Result<()> {
        let processor = self.processor.clone();
        self.runtime.spawn(async move {
            let (mut reader, mut writer) = tokio::io::split(stream);
            let mut read_transport = BufReader::new(&mut reader);
            loop {
                match read_transport.fill_buf().await {
                    Ok(s) => {
                        let buf_count = s.len();
                        let mut write_tran = Vec::new(); // TODO: Reuse or buffer writes to avoid per-request allocations.
                        let mut i_proto = TBinaryInputProtocol::new(s, false);
                        let mut o_proto = TBinaryOutputProtocol::new(&mut write_tran, true);

                        match processor.process(&mut i_proto, &mut o_proto) {
                            Ok(()) => {}
                            Err(err) => {
                                match err {
                                    TError::Transport(terr)
                                        if terr.kind == TErrorKind::EndOfFile => {}
                                    other => {
                                        eprintln!("processor completed with error: {:?}", other)
                                    }
                                };
                                break;
                            }
                        }
                        // TODO: Break out on persistent write failures instead of retrying forever.
                        if writer.write_all(write_tran.as_ref()).await.is_ok() {
                            // Advance the read buffer only after the response has been written.
                            read_transport.consume(buf_count);
                        }
                    }
                    Err(e) => eprintln!("Error reading stream - {:?}", e),
                }
            }
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::mock::MockExtensionServerHandler;
    use crate::{client, osquery};
    use std::path::PathBuf;

    // Use a unique socket per test case to avoid cross-test interference.
    fn init_server(name: &str) -> PathBuf {
        #[cfg(unix)]
        let socket: PathBuf = format!("/tmp/osquery_rs_sdk.server.{}.test.em", name).into();
        #[cfg(windows)]
        let socket: PathBuf = format!(r"\\.\pipe\osquery_rs_sdk.server.{}.test.em", name).into();

        std::fs::remove_file(&socket).ok();

        let handler = MockExtensionServerHandler {};
        let processor = osquery::ExtensionSyncProcessor::new(handler);
        let mut server = ExtensionServer::new(processor).unwrap();

        let socket_path = socket.clone();
        std::thread::spawn(move || {
            server.listen(socket_path).unwrap();
        });
        std::thread::sleep(std::time::Duration::from_millis(100));

        socket
    }

    #[test]
    fn client_ping() {
        let test_socket = init_server("client_ping_me");
        let mut client = client::ExtensionManagerClient::new_with_path(test_socket).unwrap();
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
        ExtensionServer::handle_connection(&server, read_chan).unwrap();
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
        let test_socket = init_server("processor");
        let (tx, rx) = std::sync::mpsc::channel();
        let mut children = Vec::new();

        const NTHREADS: u32 = 10;
        for id in 0..NTHREADS {
            let test_socket = test_socket.clone();
            // The sender endpoint can be copied
            let thread_tx = tx.clone();
            let child = std::thread::spawn(move || {
                let mut client = client::ExtensionManagerClient::new_with_path(test_socket)
                    .unwrap_or_else(|e| panic!("error connecting id: {} {}", id, e));
                for i in 0..(NTHREADS * 100) {
                    client
                        .ping()
                        .unwrap_or_else(|_| panic!("ping failed id: {} {}", id, i));
                }
                thread_tx.send(id).unwrap();
            });
            children.push(child);
        }
        for _ in 0..NTHREADS {
            rx.recv().unwrap();
        }
    }
}
