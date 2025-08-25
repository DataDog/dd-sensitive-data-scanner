use crate::handle_panic_ptr_return;
use dd_sds::validate_regex as validate_regex_impl;
use std::ffi::{CStr, CString, c_char};

/// # Safety
///
/// This function dereferences `regex` and `error_out` which are pointers to c_char.
/// The caller must ensure that the pointers are valid.
///
/// Thread Safety: This is safe to call simultaneously from multiple threads.
/// Return value: `null` if the regex is valid, otherwise a string describing the error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn validate_regex(
    regex: *const c_char,
    error_out: *mut *const c_char,
) -> *const c_char {
    handle_panic_ptr_return(Some(error_out), || {
        let pattern = unsafe { CStr::from_ptr(regex).to_string_lossy().into_owned() };

        match validate_regex_impl(&pattern) {
            Ok(_) => 0i64, // Return null pointer as i64
            Err(err) => {
                // Convert error to CString and return as pointer
                let error_msg = format!("{err}");
                let c_string = CString::new(error_msg).unwrap_or_else(|_| {
                    CString::new("Invalid regex (error details unavailable)").unwrap()
                });
                let ptr = c_string.into_raw();
                ptr as i64
            }
        }
    }) as *const c_char
}
