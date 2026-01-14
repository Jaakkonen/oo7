//! Keyring loader that detects encryption type and returns appropriate implementation.

#[cfg(feature = "async-std")]
use std::io;
use std::{path::Path, sync::Arc};

#[cfg(feature = "async-std")]
use async_fs as fs;
#[cfg(feature = "async-std")]
use futures_lite::AsyncReadExt;
#[cfg(feature = "tokio")]
use tokio::{
    fs,
    io::{self, AsyncReadExt},
};

use super::{
    api, Error, GpgLockedKeyring, PasswordLockedKeyring,
    traits::{LockedKeyring, SecretProvider, UnlockNotifier},
};

/// Load a keyring from file, returning appropriate implementation based on encryption type.
///
/// This function reads the keyring file, detects whether it uses GPG or password-based
/// encryption, and returns the appropriate `LockedKeyring` implementation.
///
/// # Arguments
/// * `path` - The file path to load from
/// * `label` - Human-readable label for this keyring (used in prompts)
/// * `secret_provider` - Provider for obtaining unlock passwords (used for password keyrings)
/// * `notifier` - Optional notifier for unlock events (e.g., Yubikey touch)
///
/// # Returns
/// A boxed `LockedKeyring` trait object, either `PasswordLockedKeyring` or `GpgLockedKeyring`.
pub async fn load_keyring(
    path: impl AsRef<Path>,
    label: &str,
    secret_provider: Arc<dyn SecretProvider>,
    notifier: Option<Arc<dyn UnlockNotifier>>,
) -> Result<Box<dyn LockedKeyring>, Error> {
    let path = path.as_ref();

    // Read the file to detect encryption type
    let keyring = match fs::File::open(&path).await {
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            // New keyring - default to password-based
            #[cfg(feature = "tracing")]
            tracing::debug!("Keyring file not found at {:?}, creating new password-based keyring", path);
            return Ok(Box::new(
                PasswordLockedKeyring::load(path, label, secret_provider).await?,
            ));
        }
        Err(err) => return Err(err.into()),
        Ok(mut file) => {
            let mut content = Vec::new();
            file.read_to_end(&mut content).await?;
            api::Keyring::try_from(content.as_slice())?
        }
    };

    // Detect encryption type and return appropriate implementation
    if keyring.gpg_config.is_some() {
        #[cfg(feature = "tracing")]
        tracing::debug!("Detected GPG-encrypted keyring at {:?}", path);
        Ok(Box::new(GpgLockedKeyring::load(path, label, notifier).await?))
    } else {
        #[cfg(feature = "tracing")]
        tracing::debug!("Detected password-based keyring at {:?}", path);
        Ok(Box::new(
            PasswordLockedKeyring::load(path, label, secret_provider).await?,
        ))
    }
}

/// Check if a keyring file uses GPG encryption without fully loading it.
///
/// This is useful for determining the encryption type before deciding
/// how to handle the keyring.
pub async fn is_gpg_encrypted(path: impl AsRef<Path>) -> Result<bool, Error> {
    let path = path.as_ref();

    let mut file = fs::File::open(&path).await?;
    let mut content = Vec::new();
    file.read_to_end(&mut content).await?;

    let keyring = api::Keyring::try_from(content.as_slice())?;
    Ok(keyring.gpg_config.is_some())
}
