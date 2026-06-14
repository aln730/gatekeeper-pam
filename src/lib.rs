#![allow(non_camel_case_types)]

mod config;
mod listener;

use config::Config;
use listener::{GateKeeperMemberListener, parse_uid};
use libc::c_int;

include!(concat!(env!("OUT_DIR"), "/pam.rs"));

const PAM_SUCCESS: c_int = 0;
const PAM_AUTH_ERROR: c_int = 7;
const PAM_SERVICE_ERROR: c_int = 3;
const PAM_IGNORE: c_int = 25;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut pam_handle_t,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const libc::c_char,
) -> c_int {
    // Load config
    let config = match Config::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("pam_gatekeeper: {}", e);
            return PAM_SERVICE_ERROR;
        }
    };

    //Get PAM_USER (VERY IMPORTANT FOR EVERYTHING!!!!)
    let mut username_ptr: *const libc::c_char = std::ptr::null();
    if unsafe { pam_get_user(pamh, &mut username_ptr, std::ptr::null()) } != PAM_SUCCESS
        || username_ptr.is_null()
    {
        return PAM_AUTH_ERROR;
    }
    let pam_user = match  unsafe { std::ffi::CStr::from_ptr(username_ptr) }.to_str() {
        Ok(s) => s.to_owned(),
        Err(_) => return PAM_AUTH_ERROR,
    };

    //Chom Listener
    let mut listener = match GateKeeperMemberListener::new(&config) {
        Some(l) => l,
        None => {
            eprintln!("failed to open NFC device");
            return PAM_IGNORE;
        }
    };

    //Wait for card tap
    let key = match listener.wait_for_user(config.nfc_timeout_secs) {
        Some(k) => k,
        None => return PAM_IGNORE,
    };

    //Fetch user from gatekeeper
    let value = match listener.fetch_user(key) {
        Ok(v) => v,
        Err(_) => {
            eprintln!("fetch failed");
            return PAM_IGNORE;
        }
    };

    //Compare uid to PAM_USER
    match parse_uid(&value) {
        Some(uid) if uid == pam_user => PAM_SUCCESS,
        Some(uid) => {
            eprintln!("id mismatch: '{}' != '{}'", uid, pam_user);
            PAM_AUTH_ERROR
        }
        None => {
            eprintln!("could not parse uid from response");
            PAM_IGNORE
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_setcred(
    _pamh: *mut pam_handle_t,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const libc::c_char,
) -> c_int {
    PAM_SUCCESS
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_open_session(
    _pamh: *mut pam_handle_t,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const libc::c_char,
) -> c_int {
    PAM_SUCCESS
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_close_session(
    _pamh: *mut pam_handle_t,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const libc::c_char,
) -> c_int {
    PAM_SUCCESS
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_acct_mgmt(
    _pamh: *mut pam_handle_t,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const libc::c_char,
) -> c_int {
    PAM_SUCCESS
}
