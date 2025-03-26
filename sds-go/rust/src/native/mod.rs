use core::panic::UnwindSafe;
use dd_sds::{RootRuleConfig, RuleConfig};
use serde::de::DeserializeOwned;
use std::ffi::{c_char, CStr, CString};
use std::sync::{Arc, Mutex};

pub mod create_scanner;
pub mod delete_scanner;
pub mod rule;
pub mod scan;

const ERR_UNKNOWN: i64 = -1;
pub const ERR_PANIC: i64 = -5;

pub type RulePtr = RootRuleConfig<Arc<dyn RuleConfig>>;
pub type RuleDoublePtr = Arc<RulePtr>;
pub type RuleList = Arc<Mutex<Vec<RulePtr>>>;

/// Safety: The pointer passed in must be a valid cstr pointer.
pub unsafe fn read_json<T: DeserializeOwned>(
    raw_value: *const c_char,
) -> Result<T, serde_json::Error> {
    let c_str = unsafe { CStr::from_ptr(raw_value) };
    let val = c_str.to_string_lossy();
    serde_json::from_str(&val)
}

///
/// err: The error to handle
/// error_out: An optional pointer to store the error message (if one exists)
pub fn handle_go_error(err: GoError, error_out: Option<*mut *const c_char>) {
    // This code MUST NOT panic, since it is handling a panic.

    let c_str = CString::new(err.message).unwrap_or(
        // The error message contained null bytes, which shouldn't really happen,
        // but just in case.
        CString::new("Rust panicked. No more information is available.").unwrap(),
    );
    if let Some(error_out) = error_out {
        let raw = c_str.into_raw();
        unsafe {
            *error_out = raw;
        }
    }
}

#[derive(Debug)]
pub struct GoError {
    pub message: String,
}

pub fn handle_panic_ptr_return(
    error_out: Option<*mut *const c_char>,
    f: impl FnOnce() -> i64 + UnwindSafe,
) -> i64 {
    match convert_panic_to_go_error(f) {
        Ok(ptr) => ptr,
        Err(err) => {
            handle_go_error(err, error_out);
            ERR_PANIC
        }
    }
}

pub fn convert_panic_to_go_error<R>(f: impl FnOnce() -> R + UnwindSafe) -> Result<R, GoError> {
    match std::panic::catch_unwind(f) {
        Ok(result) => Ok(result),
        Err(err) => {
            let message = if let Some(string) = err.downcast_ref::<&str>() {
                string.to_string()
            } else if let Some(string) = err.downcast_ref::<String>() {
                string.to_string()
            } else {
                "Rust panicked. No more information is available.".to_string()
            };
            Err(GoError { message })
        }
    }
}
