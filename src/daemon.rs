#![allow(dead_code)]
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

//big brain
pub const SOCKET_PATH: &str = "/run/gatekeeperd/gatekeeperd.sock";

#[derive(Debug)]
pub enum DaemonResponse {
    Ok(String),
    Timeout,
    Error(String),
}

impl DaemonResponse {
    pub fn to_wire(&self) -> String {
        match self {
            DaemonResponse::Ok(uid) => format!("OK {uid}\n"),
            DaemonResponse::Timeout => "TIMEOUT\n".to_string(),
            DaemonResponse::Error(reason) => format!("ERROR {reason}\n"),
        }
    }

    pub fn from_wire(line: &str) -> Self {
        let line = line.trim();
        if let Some(uid) = line.strip_prefix("OK ") {
            DaemonResponse::Ok(uid.to_string())
        } else if line == "TIMEOUT" {
            DaemonResponse::Timeout
        } else if let Some(reason) = line.strip_prefix("ERROR ") {
            DaemonResponse::Error(reason.to_string())
        } else {
            DaemonResponse::Error(format!("malformed response: {line:?}"))
        }
    }
}

pub fn request_wait(timeout_secs: u64) -> io::Result<DaemonResponse> {
    let mut stream = UnixStream::connect(SOCKET_PATH)?;
    stream.set_read_timeout(Some(Duration::from_secs(timeout_secs + 2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;

    writeln!(stream, "WAIT {timeout_secs}")?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;

    Ok(DaemonResponse::from_wire(&line))
}
