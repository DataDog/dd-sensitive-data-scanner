pub mod compiled;
pub mod config;
mod regex_store;
mod regex_cache_store;

pub use regex_cache_store::{access_regex_caches, RegexCaches};
pub use regex_store::{SharedRegex2, get_memoized_regex};