#[cfg(feature = "async-std")]
use std::io;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

#[cfg(feature = "async-std")]
use async_fs as fs;
#[cfg(feature = "async-std")]
use async_lock::{Mutex, RwLock};
#[cfg(feature = "async-std")]
use futures_lite::AsyncReadExt;
#[cfg(feature = "tokio")]
use tokio::{
    fs,
    io::{self, AsyncReadExt},
    sync::{Mutex, RwLock},
};

use super::{Error, Item, LockedItem, UnlockedKeyring, api};
use crate::{Secret, file::InvalidItemError};

/// A locked keyring that requires a secret to unlock.
#[derive(Debug)]
pub struct LockedKeyring {
    pub(super) keyring: Arc<RwLock<api::Keyring>>,
    pub(super) path: Option<PathBuf>,
    pub(super) mtime: Mutex<Option<std::time::SystemTime>>,
}

impl LockedKeyring {
    /// Validate that a secret can decrypt the items in this keyring.
    ///
    /// For empty keyrings, this always returns `true` since there are no items
    /// to validate against.
    ///
    /// # Arguments
    ///
    /// * `secret` - The secret to validate.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self, secret)))]
    pub async fn validate_secret(&self, secret: &Secret) -> Result<bool, Error> {
        let keyring = self.keyring.read().await;
        Ok(keyring.validate_secret(secret)?)
    }

    /// Return the associated file if any.
    pub fn path(&self) -> Option<&std::path::Path> {
        self.path.as_deref()
    }

    /// Get the modification timestamp
    pub async fn modified_time(&self) -> std::time::Duration {
        self.keyring.read().await.modified_time()
    }

    /// Check if this keyring uses GPG encryption.
    ///
    /// Returns `true` if the keyring is encrypted with GPG, `false` if it uses
    /// password-based encryption.
    pub async fn is_gpg_encrypted(&self) -> bool {
        let keyring = self.keyring.read().await;
        keyring.gpg_config.is_some()
    }

    /// Retrieve the list of available [`LockedItem`]s without decrypting them.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self)))]
    pub async fn items(&self) -> Result<Vec<Result<Item, InvalidItemError>>, Error> {
        let keyring = self.keyring.read().await;

        Ok(keyring
            .items
            .iter()
            .map(|encrypted_item| {
                Ok(Item::Locked(LockedItem {
                    inner: encrypted_item.clone(),
                }))
            })
            .collect())
    }

    /// Unlocks a keyring and validates it
    pub async fn unlock(self, secret: Secret) -> Result<UnlockedKeyring, Error> {
        self.unlock_inner(secret, true).await
    }

    /// Unlocks a keyring without validating it
    ///
    /// # Safety
    ///
    /// The method doesn't validate that the secret can decrypt all the items in
    /// the keyring.
    pub async unsafe fn unlock_unchecked(self, secret: Secret) -> Result<UnlockedKeyring, Error> {
        self.unlock_inner(secret, false).await
    }

    /// Unlocks a GPG-encrypted keyring and validates it.
    ///
    /// This method requires the keyring to use GPG encryption and will prompt
    /// for Yubikey touch/PIN via gpg-agent.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self)))]
    pub async fn unlock_with_gpg(self) -> Result<UnlockedKeyring, Error> {
        self.unlock_with_gpg_inner(true).await
    }

    /// Unlocks a GPG-encrypted keyring without validating it.
    ///
    /// # Safety
    ///
    /// The method doesn't validate that the decrypted master key can decrypt
    /// all the items in the keyring.
    pub async unsafe fn unlock_with_gpg_unchecked(self) -> Result<UnlockedKeyring, Error> {
        self.unlock_with_gpg_inner(false).await
    }

    async fn unlock_with_gpg_inner(
        self,
        validate_items: bool,
    ) -> Result<UnlockedKeyring, Error> {
        use crate::crypto::gpg;

        let key = if validate_items {
            let inner_keyring = self.keyring.read().await;

            // Check if the keyring uses GPG encryption
            let config = inner_keyring.gpg_config.as_ref()
                .ok_or(Error::NotGpgEncrypted)?;

            #[cfg(feature = "tracing")]
            tracing::debug!("Decrypting master key with GPG key: {}", config.gpg_key_id);

            let encrypted_master_key = config.encrypted_master_key.clone();

            // Decrypt the master key using GPG (this will trigger Yubikey interaction)
            // Run on a blocking thread to avoid runtime issues
            let master_key_bytes = tokio::task::spawn_blocking(move || {
                gpg::decrypt_session_key(&encrypted_master_key)
            })
            .await
            .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))??;

            // Convert to Key type
            let key = crate::Key::new(master_key_bytes.to_vec());

            // Validate items can be decrypted with this key
            inner_keyring.validate_key(&key)?;
            drop(inner_keyring);

            Some(Arc::new(key))
        } else {
            None
        };

        // For GPG-encrypted keyrings, we don't have a traditional "secret" (password)
        // So we use an empty secret as a placeholder
        let placeholder_secret = Secret::text("");

        Ok(UnlockedKeyring {
            keyring: self.keyring,
            path: self.path,
            mtime: self.mtime,
            key: Mutex::new(key),
            secret: Mutex::new(Arc::new(placeholder_secret)),
        })
    }

    async fn unlock_inner(
        self,
        secret: Secret,
        validate_items: bool,
    ) -> Result<UnlockedKeyring, Error> {
        let key = if validate_items {
            let inner_keyring = self.keyring.read().await;

            let key = inner_keyring.derive_key(&secret)?;

            // Validate items can be decrypted with this key
            inner_keyring.validate_key(&key)?;
            drop(inner_keyring);
            Some(Arc::new(key))
        } else {
            None
        };

        Ok(UnlockedKeyring {
            keyring: self.keyring,
            path: self.path,
            mtime: self.mtime,
            key: Mutex::new(key),
            secret: Mutex::new(Arc::new(secret)),
        })
    }

    /// Load a keyring from a file path.
    pub async fn load(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref();
        let (mtime, keyring) = match fs::File::open(&path).await {
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                #[cfg(feature = "tracing")]
                tracing::debug!("Keyring file not found, creating a new one");
                (None, api::Keyring::new())
            }
            Err(err) => return Err(err.into()),
            Ok(mut file) => {
                #[cfg(feature = "tracing")]
                tracing::debug!("Keyring file found, loading its content");
                let mtime = file.metadata().await?.modified().ok();

                let mut content = Vec::new();
                file.read_to_end(&mut content).await?;

                let keyring = api::Keyring::try_from(content.as_slice())?;

                (mtime, keyring)
            }
        };

        Ok(Self {
            keyring: Arc::new(RwLock::new(keyring)),
            path: Some(path.to_path_buf()),
            mtime: Mutex::new(mtime),
        })
    }

    /// Open a named keyring.
    pub async fn open(name: &str) -> Result<Self, Error> {
        let v1_path = api::Keyring::path(name, api::MAJOR_VERSION)?;
        Self::load(v1_path).await
    }
}
