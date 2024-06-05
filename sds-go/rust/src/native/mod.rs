use core::panic::UnwindSafe;

mod create_scanner;
mod delete_scanner;
mod scan;

#[derive(Debug)]
pub struct Error {
    pub message: String,
}

pub fn convert_panic_to_error<R>(f: impl FnOnce() -> R + UnwindSafe) -> Result<R, Error> {
    match std::panic::catch_unwind(f) {
        Ok(result) => Ok(result),
        Err(err) => {
            let message = if let Some(string) = err.downcast_ref::<&str>() {
                string.to_string()
            } else if let Some(string) = err.downcast_ref::<String>() {
                string.to_string()
            } else {
                "Rust panicked. No more information is available.".to_string()
            };

            Err(Error { message })
        }
    }
}
