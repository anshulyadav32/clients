use anyhow::Result;

#[allow(clippy::module_inception)]
#[cfg_attr(target_os = "linux", path = "linux.rs")]
#[cfg_attr(target_os = "macos", path = "unimplemented.rs")]
#[cfg_attr(target_os = "windows", path = "windows.rs")]
mod biometric;

#[cfg(target_os = "windows")]
pub mod windows_focus;

pub use biometric::BiometricLockSystem;

#[allow(async_fn_in_trait)]
pub trait BiometricTrait {
    /// Authenticate the user
    async fn authenticate(&self, hwnd: Vec<u8>, message: String) -> Result<bool>;
    /// Check if biometric authentication is available
    async fn authenticate_available(&self) -> Result<bool>;
    /// Enroll a key for persistent unlock
    async fn enroll_persistent(&self, user_id: &str, key: &[u8]) -> Result<()>;
    /// Clear the persistent and ephemeral keys
    async fn unenroll(&self, user_id: &str) -> Result<()>;
    async fn has_persistent(&self, user_id: &str) -> Result<bool>;
    /// On every unlock, the client provides a key to be held for subsequent biometric unlock
    async fn provide_key(&self, user_id: &str, key: &[u8]);
    /// Perform biometric unlock and return the key
    async fn unlock(&self, user_id: &str, hwnd: Vec<u8>) -> Result<Vec<u8>>;
    /// Check if biometric unlock is available based on whether a key is present and whether authentication is possible
    async fn unlock_available(&self, user_id: &str) -> Result<bool>;
}
