//! Hardware Key Provider - macOS/iOS Secure Enclave backed keys

#[cfg(all(
    any(target_os = "macos", target_os = "ios"),
    feature = "secure-enclave"
))]
mod secure_enclave;

#[cfg(all(
    any(target_os = "macos", target_os = "ios"),
    feature = "secure-enclave"
))]
mod provider;

#[cfg(all(
    any(target_os = "macos", target_os = "ios"),
    feature = "secure-enclave"
))]
pub use provider::HardwareKeyProvider;

#[cfg(all(
    any(target_os = "macos", target_os = "ios"),
    feature = "secure-enclave"
))]
pub use secure_enclave::{SecureEnclaveKeyHandle, SecureEnclaveOperations};
