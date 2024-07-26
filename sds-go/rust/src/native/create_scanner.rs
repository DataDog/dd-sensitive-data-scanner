use std::ffi::{c_char, CStr, CString};
use std::mem::ManuallyDrop;
use std::sync::Arc;

use crate::RuleList;
use dd_sds::{RegexRuleConfig, RuleConfig, Scanner};

use super::convert_panic_to_error;

const ERR_UNKNOWN: i64 = -1;
const ERR_PANIC: i64 = -5;

#[no_mangle]
pub extern "C" fn create_scanner(
    rules: i64,
    error_out: *mut *const c_char,
    should_keywords_match_event_paths: bool,
) -> i64 {
    match convert_panic_to_error(|| {
        // // json bytes parameter
        // let c_str = unsafe { CStr::from_ptr(rules_as_json) };
        // let val = c_str.to_string_lossy();
        // 
        // // parse the json
        // let rules: Vec<RegexRuleConfig> = serde_json::from_str(&val).unwrap();
        let rules_mutex = ManuallyDrop::new(unsafe {RuleList::from_raw(rules as usize as *const _)});
        
        let rules = rules_mutex.lock().unwrap();

        // create the scanner
        let scanner = match Scanner::builder(&rules)
        .with_keywords_should_match_event_paths(should_keywords_match_event_paths)
        .build()
        {
            Ok(s) => s,
            Err(err) => match err.try_into() {
                Ok(i) => return i,
                Err(_) => return ERR_UNKNOWN,
            },
        };

        // return a scanner id using the object address
        let scanner_address = Arc::into_raw(Arc::new(scanner));
        scanner_address as usize as i64
    }) {
        Ok(scanner_address) => scanner_address,
        Err(error) => {
            let c_str = CString::new(error.message).unwrap_or(
                // The error message contained null bytes, which shouldn't really happen,
                // but just in case.
                CString::new("Rust panicked. No more information is available.").unwrap(),
            );
            unsafe {
                let raw = c_str.into_raw();
                *error_out = raw;
            }
            ERR_PANIC
        }
    }
}
