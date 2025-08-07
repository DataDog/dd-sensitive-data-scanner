use std::ffi::c_char;
use std::ffi::c_void;
use std::slice;
use std::sync::Arc;

use crate::convert_panic_to_go_error;
use dd_sds::{Scanner, Utf8Encoding};
use sds_bindings_utils::{encode_response, BinaryEvent};

/// # Safety
///
/// This function makes use of `slice::from_raw_parts` which is unsafe as it dereferences a pointer to a c_void.
/// It also dereferences `retsize` and `retcapacity` which are pointers to i64.
/// The caller must ensure that the pointers are valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn scan(
    scanner_id: i64,
    event: *const c_void,
    event_size: i64,
    retsize: *mut i64,
    retcapacity: *mut i64,
    error_out: *mut *const c_char,
) -> *const c_char {
    match convert_panic_to_go_error(|| {
        let scanner =
            std::mem::ManuallyDrop::new(unsafe { Arc::from_raw(scanner_id as *mut Scanner) });

        // event to process
        let data = unsafe { slice::from_raw_parts(event.cast(), event_size as usize) }.to_vec();

        let mut event = BinaryEvent::<Utf8Encoding>::new(data, false);

        // TODO: we might want to forward the error to go in the future
        let matches = scanner.scan(&mut event);

        if let Some(encoded_response) = encode_response(&event.storage, matches.as_deref(), false) {
            let mut str = std::mem::ManuallyDrop::new(encoded_response);
            let len = str.len() as i64;
            let cap = str.capacity() as i64;

            unsafe {
                *retsize = len;
                *retcapacity = cap;
            };

            str.as_mut_ptr() as *const c_char
        } else {
            // The Go binding will immediately test for `retsize`, if retsize == 0
            // it will know that nothing has matched and that the Scan call
            // has not returned anything.
            unsafe {
                *retsize = 0;
                *retcapacity = 0;
            }
            std::ptr::null::<c_char>()
        }
    }) {
        Ok(ptr) => ptr,
        Err(error) => {
            let c_str = std::ffi::CString::new(error.message).unwrap_or(
                // The error message contained null bytes, which shouldn't really happen,
                // but just in case.
                std::ffi::CString::new("Rust panicked. No more information is available.").unwrap(),
            );
            unsafe {
                let raw = c_str.into_raw();
                *error_out = raw;
                *retsize = 0;
                *retcapacity = 0;
            }
            std::ptr::null::<c_char>()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn free_vec(ptr: *const c_char, len: i64, cap: i64) {
    unsafe {
        // rust "owns" it again and will drop it leaving the scope
        drop(Vec::from_raw_parts(
            ptr as *mut c_char,
            len as usize,
            cap as usize,
        ));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn free_string(ptr: *const c_char) {
    unsafe {
        drop(std::ffi::CString::from_raw(ptr as *mut c_char));
    }
}
