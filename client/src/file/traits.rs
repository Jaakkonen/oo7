//! Traits for keyring abstraction.
//!
//! These traits define the interface for locked and unlocked keyrings,
//! allowing different encryption implementations (password-based, GPG, etc.)
//! to be used interchangeably.

use std::{path::Path, sync::Arc, time::Duration};

use async_trait::async_trait;
#[cfg(feature = "tokio")]
use tokio::sync::oneshot;

use super::{Error, InvalidItemError, Item};
use crate::{AsAttributes, Secret};

/// Result of beginning an unlock operation.
///
/// This enum allows keyrings to return either an immediately unlocked keyring
/// (for GPG keyrings that use gpg-agent) or indicate that user input is needed
/// (for password-based keyrings that need a D-Bus prompt).
#[cfg(feature = "tokio")]
pub enum BeginUnlockResult {
    /// Keyring was unlocked immediately (e.g., GPG keyrings via gpg-agent).
    Unlocked(Box<dyn UnlockedKeyring>),

    /// User input is required to complete the unlock.
    ///
    /// The keyring has been consumed and a background task is waiting to complete
    /// the unlock once the user provides input via the prompt.
    NeedsInput {
        /// A prompt identifier/path that the D-Bus layer can use.
        /// For D-Bus servers, this is typically an object path like "/org/freedesktop/secrets/prompt/p0".
        prompt_path: String,
        /// Receiver that completes when the unlock finishes.
        /// The background task sends the unlocked keyring (or error) through this channel.
        completion: oneshot::Receiver<Result<Box<dyn UnlockedKeyring>, Error>>,
    },
}

/// Trait for locked keyrings.
///
/// A locked keyring can list items (in encrypted form) but cannot access
/// their secrets. The encryption type determines how unlocking is performed.
#[async_trait]
pub trait LockedKeyring: Send + Sync {
    /// Read-only access to encrypted items.
    async fn items(&self) -> Result<Vec<Result<Item, InvalidItemError>>, Error>;

    /// File path if backed by file.
    fn path(&self) -> Option<&Path>;

    /// Modification time.
    async fn modified_time(&self) -> Duration;

    /// Validate if a secret would work for unlocking.
    ///
    /// For password-based keyrings, this checks if the password is correct.
    /// For GPG keyrings, this may return `Ok(true)` or attempt validation.
    async fn validate_secret(&self, secret: &Secret) -> Result<bool, Error>;

    /// Returns true if this keyring requires a password to unlock.
    ///
    /// - **Password keyrings**: Return `true` - need user input.
    /// - **GPG keyrings**: Return `false` - can unlock via gpg-agent without input.
    ///
    /// This is used by the D-Bus layer to determine if a prompt is needed
    /// before attempting to unlock.
    fn requires_password(&self) -> bool;

    /// Begin the unlock process.
    ///
    /// This method initiates unlocking and returns immediately:
    /// - **GPG keyrings**: Unlocks via gpg-agent and returns `Unlocked` with the keyring.
    /// - **Password keyrings**: Creates a D-Bus prompt, spawns a background task to
    ///   wait for user input, and returns `NeedsInput` with the prompt path.
    ///
    /// The caller (Collection) matches on the result without needing to know the
    /// encryption type. This eliminates all type-specific branching.
    ///
    /// # Returns
    /// - `BeginUnlockResult::Unlocked` - Keyring unlocked immediately
    /// - `BeginUnlockResult::NeedsInput` - User input required, prompt created
    ///
    /// This method consumes self because unlocking transitions to a new state.
    #[cfg(feature = "tokio")]
    async fn begin_unlock(self: Box<Self>) -> Result<BeginUnlockResult, Error>;

    /// Unlock the keyring (blocking version).
    ///
    /// This method blocks until the keyring is unlocked:
    /// - **Password keyrings**: Calls `SecretProvider::get_secret()` which may block
    ///   waiting for user input.
    /// - **GPG keyrings**: Calls gpg-agent directly.
    ///
    /// For D-Bus servers, prefer `begin_unlock()` which returns immediately.
    ///
    /// This method consumes self because unlocking transitions to a new state.
    async fn unlock(self: Box<Self>) -> Result<Box<dyn UnlockedKeyring>, Error>;

    /// Unlock the keyring with a known secret.
    ///
    /// This is used when the caller already has a valid secret (e.g., from PAM).
    /// - **Password keyrings**: Unlocks directly with the provided secret.
    /// - **GPG keyrings**: Ignores the secret and unlocks via gpg-agent.
    ///
    /// This avoids triggering a D-Bus prompt when the secret is already known.
    async fn unlock_with_secret(
        self: Box<Self>,
        secret: &Secret,
    ) -> Result<Box<dyn UnlockedKeyring>, Error>;
}

/// Trait for unlocked keyrings - full CRUD access to items.
#[async_trait]
pub trait UnlockedKeyring: Send + Sync {
    /// Retrieve all items in decrypted form.
    async fn items(&self) -> Result<Vec<Result<Item, InvalidItemError>>, Error>;

    /// Search items matching the given attributes.
    async fn search_items(
        &self,
        attrs: &(dyn AsAttributes + Send + Sync),
    ) -> Result<Vec<Item>, Error>;

    /// Create a new item in the keyring.
    ///
    /// # Arguments
    /// * `label` - User-visible label for the item
    /// * `attrs` - Searchable attributes
    /// * `secret` - The secret to store
    /// * `replace` - If true, replace existing items with matching attributes
    async fn create_item(
        &self,
        label: &str,
        attrs: &(dyn AsAttributes + Send + Sync),
        secret: Secret,
        replace: bool,
    ) -> Result<Item, Error>;

    /// Delete items matching the given attributes.
    async fn delete(&self, attrs: &(dyn AsAttributes + Send + Sync)) -> Result<(), Error>;

    /// Write changes to persistent storage.
    async fn write(&self) -> Result<(), Error>;

    /// File path if backed by file.
    fn path(&self) -> Option<&Path>;

    /// Modification time.
    async fn modified_time(&self) -> Duration;

    /// Lock the keyring, returning to the locked state.
    ///
    /// This consumes self and returns a locked keyring.
    fn lock(self: Box<Self>) -> Box<dyn LockedKeyring>;

    /// Get the encryption key for operations that need it.
    ///
    /// This is needed for attribute matching on locked items.
    async fn key(&self) -> Result<Arc<crate::Key>, crate::crypto::Error>;

    /// Validate if a secret matches the keyring's password.
    ///
    /// For password-based keyrings, checks if the password is correct.
    /// For GPG keyrings, returns `Ok(false)` as they don't use passwords.
    async fn validate_secret(&self, secret: &Secret) -> Result<bool, Error>;

    /// Change the keyring's password.
    ///
    /// For password-based keyrings, re-encrypts all items with a new password.
    /// For GPG keyrings, returns an error (password change not supported).
    async fn change_secret(&self, secret: Secret) -> Result<(), Error>;
}

/// Provider for obtaining secrets from the user.
///
/// This trait is implemented by the server to provide password prompts.
/// Password-based keyrings call this to obtain the unlock secret.
///
/// The trait has two modes of operation:
/// 1. **Blocking mode**: Call `get_secret()` which creates a prompt and blocks until complete.
/// 2. **Non-blocking mode**: Call `create_prompt()` to get a prompt path immediately,
///    then `await_prompt()` later to wait for the user's response.
#[async_trait]
pub trait SecretProvider: Send + Sync {
    /// Create a D-Bus prompt and return its path without blocking.
    ///
    /// The prompt is created and exposed on D-Bus, ready for the client to interact with.
    /// Use `await_prompt()` to wait for the user to complete the prompt.
    ///
    /// # Arguments
    /// * `label` - The keyring label (shown in the prompt UI)
    ///
    /// # Returns
    /// A string path/identifier for the prompt (e.g., "/org/freedesktop/secrets/prompt/p0")
    async fn create_prompt(&self, label: &str) -> Result<String, Error>;

    /// Wait for a prompt to be completed and return the secret.
    ///
    /// This blocks until the user completes or dismisses the prompt.
    ///
    /// # Arguments
    /// * `prompt_path` - The path returned by `create_prompt()`
    async fn await_prompt(&self, prompt_path: &str) -> Result<Secret, Error>;

    /// Get a secret for the given keyring label (blocking convenience method).
    ///
    /// This is equivalent to calling `create_prompt()` then `await_prompt()`.
    /// The implementation may show UI, block for user input, etc.
    async fn get_secret(&self, label: &str) -> Result<Secret, Error> {
        let path = self.create_prompt(label).await?;
        self.await_prompt(&path).await
    }

    /// Called when a provided secret was rejected (wrong password).
    ///
    /// The implementation may show an error message and prompt again,
    /// or return an error to abort the unlock attempt.
    async fn secret_rejected(&self, label: &str, error: &Error) -> Result<Secret, Error>;
}

/// Optional callback for unlock notifications.
///
/// This can be used to show UI feedback during unlock operations,
/// for example "Touch your Yubikey" notifications for GPG keyrings.
#[async_trait]
pub trait UnlockNotifier: Send + Sync {
    /// Called when an unlock operation is starting.
    ///
    /// # Arguments
    /// * `label` - The keyring label being unlocked
    /// * `method` - Description of the unlock method (e.g., "Yubikey GPG")
    async fn unlock_starting(&self, label: &str, method: &str);
}
