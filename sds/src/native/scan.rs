use std::ffi::c_char;
use std::ffi::c_void;
use std::slice;
use std::sync::Arc;

use ahash::AHashMap;

use crate::bindings_utils::{BinaryEvent, encode_response};
use crate::{ScanOptionBuilder, Scanner, Utf8Encoding};

use super::convert_panic_to_go_error;

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
    with_validate_matching: i32,
) -> *const c_char {
    match convert_panic_to_go_error(|| {
        let scanner =
            std::mem::ManuallyDrop::new(unsafe { Arc::from_raw(scanner_id as *mut Scanner) });

        // event to process
        let data = unsafe { slice::from_raw_parts(event.cast(), event_size as usize) }.to_vec();

        let mut event = BinaryEvent::<Utf8Encoding>::new(data, false, None);

        // TODO: we might want to forward the error to go in the future
        let scan_options = ScanOptionBuilder::new()
            .with_validate_matching(with_validate_matching != 0)
            .build();
        let matches = scanner.scan_with_options(&mut event, scan_options);

        if let Some(encoded_response) =
            encode_response(&event.storage, matches.as_deref(), false, false)
        {
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

/// Like `scan`, but accepts an additional null-terminated JSON string of key-value scan metadata
/// (e.g. `{"org_id":"123"}`). The metadata is forwarded to each rule via
/// `StringMatchesCtx::scan_metadata`. Pass an empty JSON object (`{}`) when no metadata is needed.
///
/// # Safety
///
/// Same requirements as `scan`. Additionally, `scan_metadata_json` must be a valid null-terminated
/// UTF-8 string containing a JSON object.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn scan_v2(
    scanner_id: i64,
    event: *const c_void,
    event_size: i64,
    retsize: *mut i64,
    retcapacity: *mut i64,
    error_out: *mut *const c_char,
    with_validate_matching: i32,
    scan_metadata_json: *const c_char,
) -> *const c_char {
    match convert_panic_to_go_error(|| {
        let scanner =
            std::mem::ManuallyDrop::new(unsafe { Arc::from_raw(scanner_id as *mut Scanner) });

        let data = unsafe { slice::from_raw_parts(event.cast(), event_size as usize) }.to_vec();

        let mut event = BinaryEvent::<Utf8Encoding>::new(data, false, None);

        let scan_metadata: AHashMap<String, String> = if scan_metadata_json.is_null() {
            AHashMap::new()
        } else {
            let cstr = unsafe { std::ffi::CStr::from_ptr(scan_metadata_json) };
            serde_json::from_str(cstr.to_str().unwrap_or("{}")).unwrap_or_default()
        };

        let scan_options = ScanOptionBuilder::new()
            .with_validate_matching(with_validate_matching != 0)
            .with_scan_metadata(scan_metadata)
            .build();
        let matches = scanner.scan_with_options(&mut event, scan_options);

        if let Some(encoded_response) =
            encode_response(&event.storage, matches.as_deref(), false, false)
        {
            let mut str = std::mem::ManuallyDrop::new(encoded_response);
            let len = str.len() as i64;
            let cap = str.capacity() as i64;

            unsafe {
                *retsize = len;
                *retcapacity = cap;
            };

            str.as_mut_ptr() as *const c_char
        } else {
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
pub unsafe extern "C" fn free_vec(ptr: *const c_char, len: i64, cap: i64) {
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
pub unsafe extern "C" fn free_string(ptr: *const c_char) {
    unsafe {
        drop(std::ffi::CString::from_raw(ptr as *mut c_char));
    }
}
