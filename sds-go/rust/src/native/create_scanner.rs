use std::ffi::c_char;
use std::mem::ManuallyDrop;
use std::sync::Arc;

use crate::{handle_panic_ptr_return, RuleList};
use dd_sds::Scanner;

#[no_mangle]
pub extern "C" fn create_scanner(rules: i64, error_out: *mut *const c_char) -> i64 {
    handle_panic_ptr_return(Some(error_out), || {
        let rules_mutex =
            ManuallyDrop::new(unsafe { RuleList::from_raw(rules as usize as *const _) });
        let rules = rules_mutex.lock().unwrap();

        // create the scanner
        let scanner = match Scanner::builder(&rules).build() {
            Ok(s) => s,
            Err(err) => return err.into(),
        };

        // return a scanner id using the object address
        let scanner_address = Arc::into_raw(Arc::new(scanner));
        scanner_address as usize as i64
    })
}
