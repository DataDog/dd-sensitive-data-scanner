use std::ffi::{c_char, CStr, CString};
use std::mem::ManuallyDrop;
use std::sync::{Arc, Mutex};

use crate::native::{convert_panic_to_go_error, ERR_PANIC, GoError, handle_panic_ptr_return};
use crate::{RuleDoublePtr, RuleList};


#[no_mangle]
pub extern "C" fn free_any_rule(
    rule_ptr: i64
) {
    let _ = convert_panic_to_go_error(|| {
        let double_pointer = unsafe {RuleDoublePtr::from_raw(rule_ptr as usize as *const _)};
        drop(double_pointer);
    });
}

// Infallible
#[no_mangle]
pub extern "C" fn create_rule_list() -> i64 {
    handle_panic_ptr_return(None, || {
        // Wrapping with `Arc<Mutex>>` so there is a single pointer than can be shared over FFI, and
        // to make it thread-safe.
        let list = RuleList::new(Mutex::new(Vec::new()));
        Arc::into_raw(list) as usize as i64
    })
}

// Infallible
#[no_mangle]
pub extern "C" fn append_rule_to_list(rule: i64, list: i64) {
    let _ = convert_panic_to_go_error(|| {
        let list = ManuallyDrop::new(unsafe {RuleList::from_raw(list as usize as *const _)});
        let rule_double_ptr = ManuallyDrop::new(unsafe {RuleDoublePtr::from_raw(rule as usize as *const _)});

        let rule_ptr = rule_double_ptr.as_ref().clone();
        list.lock().unwrap().push(rule_ptr);
    });
}

// Infallible
#[no_mangle]
pub extern "C" fn free_rule_list(list: i64) {
    let _ = convert_panic_to_go_error(|| {
        let list = unsafe {RuleList::from_raw(list as usize as *const _)};
        drop(list);
    });
}


