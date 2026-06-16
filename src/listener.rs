use crate::daemon::{self, DaemonResponse};

#[derive(Debug)]
pub enum WaitError {
    DaemonUnavailable(String),
    DaemonError(String),
}

pub fn wait_for_user(timeout_secs: u64) -> Result<Option<String>, WaitError> {
    match daemon::request_wait(timeout_secs) {
        Ok(DaemonResponse::Ok(uid)) => Ok(Some(uid)),
        Ok(DaemonResponse::Timeout) => Ok(None),
        Ok(DaemonResponse::Error(reason)) => Err(WaitError::DaemonError(reason)),
        Err(e) => Err(WaitError::DaemonUnavailable(e.to_string())),
    }
}