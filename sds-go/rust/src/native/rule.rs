use std::ffi::{c_char};
use std::mem::ManuallyDrop;
use std::sync::{Arc, Mutex};
use dd_sds::RegexRuleConfig;

use crate::native::{convert_panic_to_go_error, handle_panic_ptr_return, read_json};
use crate::{RuleDoublePtr, RuleList, RulePtr};


#[no_mangle]
pub extern "C" fn create_regex_rule(
    json_config: *const c_char,
) -> i64 {
    handle_panic_ptr_return(None, || {
        // parse the json
        let config: RegexRuleConfig = unsafe {read_json(json_config).unwrap()};
        
        let rule: RulePtr = Arc::new(config);
        // A trait object in Rust is a fat-pointer (1 data + 1 vtable pointer). This is boxed again
        // to get a single (normal) pointer to the fat pointer so only 1 value needs to be sent over FFI
        let double_pointer = RuleDoublePtr::new(rule);

        Arc::into_raw(double_pointer) as usize as i64
    })
}

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


