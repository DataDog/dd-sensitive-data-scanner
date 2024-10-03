pub mod compiled;
pub mod config;
mod regex_cache_store;
mod regex_store;

pub use regex_cache_store::{access_regex_caches, RegexCaches};
pub use regex_store::{get_memoized_regex, SharedRegex};
