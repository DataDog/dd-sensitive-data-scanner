// This blocks accidental use of `println`. If one is actually needed, you can
// override with `#[allow(clippy::print_stdout)]`.
#![deny(clippy::print_stdout)]

mod binary_encoding;

pub use binary_encoding::{
    BinaryEvent, encode_async_response, encode_response, encode_response_in_place,
};
