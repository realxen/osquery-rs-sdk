use std::path::Path;
use std::time::Duration;
use thrift::{
    protocol::{TBinaryInputProtocol, TBinaryOutputProtocol, TInputProtocol, TOutputProtocol},
    transport::{TBufferedReadTransport, TBufferedWriteTransport},
    Error,
};

const DEFAULT_WAIT_MILLS: u64 = 200;

// TProtocols represents the high-level thrift transport protocols
pub type TProtocols = (Box<dyn TInputProtocol>, Box<dyn TOutputProtocol>);

#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::unix::net::UnixStream;

    fn wait_for_socket(socket_path: &Path) -> Result<UnixStream, Error> {
        std::thread::sleep(Duration::from_millis(DEFAULT_WAIT_MILLS));
        UnixStream::connect(&socket_path)
            .map_err(|e| Error::from(format!("connecting to osquery socket: {}", e)))
    }

    pub fn bind<P: AsRef<Path>>(socket_path: P) -> Result<TProtocols, Error> {
        let socket = wait_for_socket(socket_path.as_ref())?;

        let transport_in = TBufferedReadTransport::new(socket.try_clone().unwrap());
        let transport_out = TBufferedWriteTransport::new(socket.try_clone().unwrap());
        let protocol_in: Box<dyn TInputProtocol> =
            Box::new(TBinaryInputProtocol::new(transport_in, false));
        let protocol_out: Box<dyn TOutputProtocol> =
            Box::new(TBinaryOutputProtocol::new(transport_out, true));

        Ok((protocol_in, protocol_out))
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use miow::pipe;
    use std::fs::File;

    fn wait_for_socket(pipe_path: &Path) -> Result<File, Error> {
        std::thread::sleep(Duration::from_millis(DEFAULT_WAIT_MILLS));
        pipe::connect(pipe_path)
            .map_err(|e| Error::from(format!("connecting to osquery pipe: {}", e)))
    }

    pub fn bind<P: AsRef<Path>>(pipe_path: P) -> Result<TProtocols, Error> {
        let socket = wait_for_socket(pipe_path.as_ref())?;
        let transport_in = TBufferedReadTransport::new(socket.try_clone().unwrap());
        let transport_out = TBufferedWriteTransport::new(socket.try_clone().unwrap());

        let protocol_in: Box<dyn TInputProtocol> =
            Box::new(TBinaryInputProtocol::new(transport_in, false));
        let protocol_out: Box<dyn TOutputProtocol> =
            Box::new(TBinaryOutputProtocol::new(transport_out, true));

        Ok((protocol_in, protocol_out))
    }
}

pub fn bind<P: AsRef<Path>>(path: P) -> Result<TProtocols, Error> {
    #[cfg(unix)]
    return unix::bind(path);
    #[cfg(windows)]
    return windows::bind(path);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    use std::os::unix::net::UnixListener;
    #[cfg(unix)]
    use std::path::Path;

    #[cfg(unix)]
    pub static _TEST_SOCKET: &str = "src/test.socket.em";
    #[cfg(windows)]
    pub static _TEST_SOCKET: &str = r"\\.\pipe\osquery.em";
    #[cfg(windows)]
    use std::io::Write;

    #[cfg(unix)]
    fn create_test_socket(socket: &Path, cleanup_mills: u64) {
        // Delete old socket if necessary
        if socket.exists() {
            std::fs::remove_file(&socket).unwrap();
        }
        // cleanup test socket
        let delete_socket = move || {
            std::thread::sleep(Duration::from_millis(cleanup_mills));
            std::fs::remove_file(&Path::new(_TEST_SOCKET)).unwrap()
        };
        if let Ok(stream) = UnixListener::bind(&socket) {
            std::thread::spawn(delete_socket);
            for _ in stream.incoming() {}
        }
    }

    #[test]
    #[cfg(unix)]
    fn test_bind() {
        // create test socket
        #[cfg(unix)]
        std::thread::spawn(move || create_test_socket(_TEST_SOCKET.as_ref(), 200));
    }

    #[test]
    #[cfg(windows)]
    fn test_bind() {
        // create test socket
        let pipe = miow::pipe::NamedPipe::new(_TEST_SOCKET);

        // Test thrift socket binding
        bind(_TEST_SOCKET).unwrap();

        // disconnect test socket
        if let Ok(mut p) = pipe {
            p.flush().unwrap();
            p.disconnect().unwrap();
        }
    }
}
