use crate::convert_panic_to_go_error;
use dd_sds::Scanner;
use std::sync::Arc;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn delete_scanner(scanner_id: i64) {
    let _ = convert_panic_to_go_error(|| {
        let scanner = unsafe { Arc::from_raw(scanner_id as *mut Scanner) };
        drop(scanner);
    });
}
