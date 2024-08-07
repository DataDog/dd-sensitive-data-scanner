// This blocks accidental use of `println`. If one is actually needed, you can
// override with `#[allow(clippy::print_stdout)]`.
#![deny(clippy::print_stdout)]

mod native;

pub use native::*;

