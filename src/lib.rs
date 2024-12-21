use std::ffi;

#[cfg(target_os = "macos")]
pub use macos::Dtrace;

#[cfg(target_os = "macos")]
mod macos;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("dtrace: {0}")]
    DTrace(ffi::c_int),
}
