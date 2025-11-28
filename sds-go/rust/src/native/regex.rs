use crate::handle_panic_ptr_return;
use dd_sds::explain_regex as explain_regex_impl;
use dd_sds::validate_regex as validate_regex_impl;
use serde::{Deserialize, Serialize};
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

#[derive(Debug, Serialize, Deserialize)]
struct RegexExplanation {
    is_valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tree: Option<dd_sds::AstNode>,
}

impl From<Result<dd_sds::AstNode, String>> for RegexExplanation {
    fn from(result: Result<dd_sds::AstNode, String>) -> Self {
        match result {
            Ok(tree) => RegexExplanation {
                is_valid: true,
                error: None,
                tree: Some(tree),
            },
            Err(err) => RegexExplanation {
                is_valid: false,
                error: Some(err),
                tree: None,
            },
        }
    }
}

/// # Safety
///
/// This function dereferences `regex` which is a pointer to c_char.
/// The caller must ensure that the pointer is valid.
///
/// Thread Safety: This is safe to call simultaneously from multiple threads.
/// Return value: A JSON string containing the regex explanation if valid or the error message if invalid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn explain_regex(
    regex: *const c_char,
    error_out: *mut *const c_char,
) -> *const c_char {
    handle_panic_ptr_return(Some(error_out), || {
        let pattern = unsafe { CStr::from_ptr(regex).to_string_lossy().into_owned() };

        let result = explain_regex_impl(&pattern);
        let explanation: RegexExplanation = result.into();

        match serde_json::to_string(&explanation) {
            Ok(json_str) => {
                let c_string = CString::new(json_str).unwrap_or_else(|_| {
                    CString::new(
                        "{\"is_valid\":false,\"error\":\"Failed to serialize explanation\"}",
                    )
                    .unwrap()
                });
                let ptr = c_string.into_raw();
                ptr as i64
            }
            Err(_) => {
                let error_msg =
                    "{\"is_valid\":false,\"error\":\"Failed to serialize explanation\"}";
                let c_string = CString::new(error_msg).unwrap();
                let ptr = c_string.into_raw();
                ptr as i64
            }
        }
    }) as *const c_char
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_explain_regex_valid() {
        let pattern = CString::new("a+").unwrap();
        let mut error_out: *const c_char = std::ptr::null();

        unsafe {
            let result = explain_regex(pattern.as_ptr(), &mut error_out);
            assert!(!result.is_null());

            let json_str = CStr::from_ptr(result).to_string_lossy();
            assert!(json_str.contains("is_valid"));
            assert!(json_str.contains("true"));

            // Free the allocated string
            let _ = CString::from_raw(result as *mut c_char);
        }
    }

    #[test]
    fn test_explain_regex_invalid() {
        let pattern = CString::new("[").unwrap();
        let mut error_out: *const c_char = std::ptr::null();

        unsafe {
            let result = explain_regex(pattern.as_ptr(), &mut error_out);
            assert!(!result.is_null());

            let json_str = CStr::from_ptr(result).to_string_lossy();
            assert!(json_str.contains("is_valid"));
            assert!(json_str.contains("false"));

            // Free the allocated string
            let _ = CString::from_raw(result as *mut c_char);
        }
    }
}
