use std::sync::LazyLock;
use tokio::runtime::Runtime;

// A globally shared Tokio runtime for SDS
pub static TOKIO_RUNTIME: LazyLock<Runtime> =
    LazyLock::new(|| Runtime::new().expect("Failed to create Tokio runtime"));
