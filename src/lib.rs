#![allow(non_camel_case_types)]

mod config;
mod listener;
mod daemon;
use config::Config;
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
    let pamh_addr = pamh as usize;
    std::panic::catch_unwind(|| authenticate_inner(pamh_addr as *mut pam_handle_t)).unwrap_or_else(|_| {
            eprintln!("pam_gatekeeper: panic during authentication");
            PAM_SERVICE_ERROR
        })
}

fn authenticate_inner(pamh: *mut pam_handle_t) -> c_int {
    let config = match Config::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("pam_gatekeeper: {e}");
            return PAM_SERVICE_ERROR;
        }
    };

    // (VERY IMPORTANT FOR EVERYTHING!!!!)
    let mut username_ptr: *const libc::c_char = std::ptr::null();
    if unsafe { pam_get_user(pamh, &mut username_ptr, std::ptr::null()) } != PAM_SUCCESS || username_ptr.is_null()
    {
        return PAM_AUTH_ERROR;
    }
    let pam_user = match unsafe { std::ffi::CStr::from_ptr(username_ptr) }.to_str() {
        Ok(s) => s.to_owned(),
        Err(_) => return PAM_AUTH_ERROR,
    };

    loop {
        match listener::wait_for_user(config.nfc_poll_chunk_secs) {
            Ok(Some(uid)) if uid == pam_user => {
                eprintln!("gatekeeperd: tap resolved uid '{uid}'");
                return PAM_SUCCESS
            }
            Ok(Some(uid)) => {
                eprintln!("gatekeeperd: id mismatch: '{uid}' != '{pam_user}', retrying");
                continue;
            }
            Ok(None) => {
                // chunk timed out
                continue;
            }
            Err(e) => {
                eprintln!("gatekeeperd: daemon error: {e:?}");
                return PAM_IGNORE;
            }
        }
    }
}

//pam stuff
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
//trust me
