#![cfg(windows)]

use std::{
    fs::{File, OpenOptions},
    io,
    io::{Error, ErrorKind},
    ops::Add,
    os::windows::fs::OpenOptionsExt,
    path::Path,
    time::{Duration, Instant},
};
use winapi::{shared::winerror, um::winbase};

pub struct NamedPipeClient(File);

impl NamedPipeClient {
    /// Connect to a named pipe by path.
    ///
    /// Times out if the connection takes longer than a default timeout of 2 seconds.
    /// (We do not use WaitNamedPipe.)
    pub fn connect<P: AsRef<Path>>(path: P) -> io::Result<NamedPipeClient> {
        let mut rw = OpenOptions::new();
        rw.read(true).write(true).custom_flags(
            winbase::SECURITY_IDENTIFICATION
                | winbase::SECURITY_SQOS_PRESENT
                | winbase::FILE_FLAG_OVERLAPPED,
        );

        let timeout = Instant::now().add(Duration::from_secs(2));
        Ok(NamedPipeClient(loop {
            // wait for connection timeout
            match timeout.checked_duration_since(Instant::now()) {
                Some(_) => match rw.open(path.as_ref()) {
                    Ok(f) => break f,
                    Err(ref e) if e.raw_os_error() == Some(winerror::ERROR_PIPE_BUSY as i32) => {
                        // Wait 10 msec and try again. This is a rather simplistic
                        // view, as we always try each 10 milliseconds.
                        std::thread::sleep(Duration::from_millis(10))
                    }
                    Err(e) => return Err(e),
                },
                None => return Err(Error::from(ErrorKind::TimedOut)),
            }
        }))
    }

    pub fn try_clone(&self) -> io::Result<NamedPipeClient> {
        Ok(NamedPipeClient(self.0.try_clone()?))
    }
}

impl std::io::Read for NamedPipeClient {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl std::io::Write for NamedPipeClient {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}
