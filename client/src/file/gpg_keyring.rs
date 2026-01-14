//! GPG-based keyring implementation.
//!
//! This module provides keyring implementations that use GPG encryption
//! with hardware tokens like Yubikey.

#[cfg(feature = "async-std")]
use std::io;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

#[cfg(feature = "async-std")]
use async_fs as fs;
#[cfg(feature = "async-std")]
use async_lock::{Mutex, RwLock};
#[cfg(feature = "async-std")]
use futures_lite::AsyncReadExt;
use async_trait::async_trait;
#[cfg(feature = "tokio")]
use tokio::{
    fs,
    io::{self, AsyncReadExt},
    sync::{Mutex, RwLock},
};

use super::{
    api, Error, InvalidItemError, Item, LockedItem,
    traits::{LockedKeyring, UnlockNotifier, UnlockedKeyring},
};
#[cfg(feature = "tokio")]
use super::traits::BeginUnlockResult;
use crate::{AsAttributes, Key, Secret};

/// A GPG-based locked keyring.
///
/// This keyring uses GPG encryption with a hardware token (e.g., Yubikey).
/// When unlocking, it calls gpg-agent directly to decrypt the master key.
pub struct GpgLockedKeyring {
    pub(super) inner: Arc<RwLock<api::Keyring>>,
    pub(super) path: Option<PathBuf>,
    pub(super) mtime: Mutex<Option<std::time::SystemTime>>,
    pub(super) label: String,
    pub(super) notifier: Option<Arc<dyn UnlockNotifier>>,
}

impl std::fmt::Debug for GpgLockedKeyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GpgLockedKeyring")
            .field("path", &self.path)
            .field("label", &self.label)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl LockedKeyring for GpgLockedKeyring {
    async fn items(&self) -> Result<Vec<Result<Item, InvalidItemError>>, Error> {
        let keyring = self.inner.read().await;
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

    fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    async fn modified_time(&self) -> Duration {
        self.inner.read().await.modified_time()
    }

    async fn validate_secret(&self, _secret: &Secret) -> Result<bool, Error> {
        // GPG keyrings don't use password-based validation
        // The GPG agent handles authentication
        Ok(true)
    }

    fn requires_password(&self) -> bool {
        false // GPG keyrings use gpg-agent, no user password needed
    }

    #[cfg(feature = "tokio")]
    async fn begin_unlock(self: Box<Self>) -> Result<BeginUnlockResult, Error> {
        // GPG keyrings unlock immediately via gpg-agent
        let unlocked = self.unlock().await?;
        Ok(BeginUnlockResult::Unlocked(unlocked))
    }

    async fn unlock(self: Box<Self>) -> Result<Box<dyn UnlockedKeyring>, Error> {
        use crate::crypto::gpg;

        // Notify that unlock is starting (e.g., "Touch your Yubikey")
        if let Some(notifier) = &self.notifier {
            notifier.unlock_starting(&self.label, "GPG/Yubikey").await;
        }

        let inner_keyring = self.inner.read().await;

        // Check if the keyring uses GPG encryption
        let config = inner_keyring
            .gpg_config
            .as_ref()
            .ok_or(Error::NotGpgEncrypted)?;

        #[cfg(feature = "tracing")]
        tracing::debug!("Decrypting master key with GPG key: {}", config.gpg_key_id);

        let encrypted_master_key = config.encrypted_master_key.clone();
        let gpg_key_id = config.gpg_key_id.clone();

        // Decrypt the master key using GPG (this will trigger Yubikey interaction)
        // Run on a blocking thread to avoid runtime issues
        #[cfg(feature = "tokio")]
        let master_key_bytes = tokio::task::spawn_blocking(move || {
            gpg::decrypt_session_key(&encrypted_master_key)
        })
        .await
        .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))??;

        #[cfg(feature = "async-std")]
        let master_key_bytes = blocking::unblock(move || {
            gpg::decrypt_session_key(&encrypted_master_key)
        })
        .await?;

        // Convert to Key type
        let key = Key::new(master_key_bytes.to_vec());

        // Validate items can be decrypted with this key
        inner_keyring.validate_key(&key)?;
        drop(inner_keyring);

        Ok(Box::new(GpgUnlockedKeyring {
            inner: self.inner,
            path: self.path,
            mtime: self.mtime,
            key: Mutex::new(Some(Arc::new(key))),
            label: self.label,
            gpg_key_id,
            notifier: self.notifier,
        }))
    }

    async fn unlock_with_secret(
        self: Box<Self>,
        _secret: &Secret,
    ) -> Result<Box<dyn UnlockedKeyring>, Error> {
        // GPG keyrings don't use password secrets - unlock via gpg-agent
        self.unlock().await
    }
}

impl GpgLockedKeyring {
    /// Load a GPG-based keyring from a file path.
    ///
    /// # Arguments
    /// * `path` - The file path to load from
    /// * `label` - Human-readable label for this keyring
    /// * `notifier` - Optional notifier for unlock events (e.g., Yubikey touch)
    pub async fn load(
        path: impl AsRef<Path>,
        label: &str,
        notifier: Option<Arc<dyn UnlockNotifier>>,
    ) -> Result<Self, Error> {
        let path = path.as_ref();
        let (mtime, keyring) = match fs::File::open(&path).await {
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Err(Error::Io(err));
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

        // Verify this is a GPG-encrypted keyring
        if keyring.gpg_config.is_none() {
            return Err(Error::NotGpgEncrypted);
        }

        Ok(Self {
            inner: Arc::new(RwLock::new(keyring)),
            path: Some(path.to_path_buf()),
            mtime: Mutex::new(mtime),
            label: label.to_string(),
            notifier,
        })
    }
}

/// A GPG-based unlocked keyring with full CRUD access.
pub struct GpgUnlockedKeyring {
    pub(super) inner: Arc<RwLock<api::Keyring>>,
    pub(super) path: Option<PathBuf>,
    pub(super) mtime: Mutex<Option<std::time::SystemTime>>,
    pub(super) key: Mutex<Option<Arc<Key>>>,
    pub(super) label: String,
    pub(super) gpg_key_id: String,
    pub(super) notifier: Option<Arc<dyn UnlockNotifier>>,
}

impl std::fmt::Debug for GpgUnlockedKeyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GpgUnlockedKeyring")
            .field("path", &self.path)
            .field("label", &self.label)
            .field("gpg_key_id", &self.gpg_key_id)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl UnlockedKeyring for GpgUnlockedKeyring {
    async fn items(&self) -> Result<Vec<Result<Item, InvalidItemError>>, Error> {
        let key = self.get_key().await?;
        let keyring = self.inner.read().await;

        Ok(keyring
            .items
            .iter()
            .map(|e| {
                (*e).clone()
                    .decrypt(&key)
                    .map_err(|err| {
                        InvalidItemError::new(
                            err,
                            e.hashed_attributes.keys().map(|x| x.to_string()).collect(),
                        )
                    })
                    .map(Item::Unlocked)
            })
            .collect())
    }

    async fn search_items(
        &self,
        attrs: &(dyn AsAttributes + Send + Sync),
    ) -> Result<Vec<Item>, Error> {
        let key = self.get_key().await?;
        let keyring = self.inner.read().await;
        let results = keyring
            .search_items(attrs, &key)?
            .into_iter()
            .map(Item::Unlocked)
            .collect::<Vec<Item>>();

        #[cfg(feature = "tracing")]
        tracing::debug!("Found {} matching items", results.len());

        Ok(results)
    }

    async fn create_item(
        &self,
        label: &str,
        attrs: &(dyn AsAttributes + Send + Sync),
        secret: Secret,
        replace: bool,
    ) -> Result<Item, Error> {
        use super::UnlockedItem;

        let item = {
            let key = self.get_key().await?;
            let mut keyring = self.inner.write().await;
            if replace {
                keyring.remove_items(attrs, &key)?;
            }
            let item = UnlockedItem::new(label, attrs, secret);
            let encrypted_item = item.encrypt(&key)?;
            keyring.items.push(encrypted_item);
            item
        };

        self.write().await?;

        #[cfg(feature = "tracing")]
        tracing::info!("Successfully created item");

        Ok(Item::Unlocked(item))
    }

    async fn delete(&self, attrs: &(dyn AsAttributes + Send + Sync)) -> Result<(), Error> {
        {
            let key = self.get_key().await?;
            let mut keyring = self.inner.write().await;
            keyring.remove_items(attrs, &key)?;
        }
        self.write().await
    }

    async fn write(&self) -> Result<(), Error> {
        let mut mtime = self.mtime.lock().await;

        // For GPG-encrypted keyrings, rotate the key before writing
        #[cfg(feature = "tracing")]
        tracing::debug!("Auto-rotating GPG master key before save");
        self.rotate_key().await?;

        // Write keyring to disk
        {
            let mut keyring = self.inner.write().await;

            if let Some(ref path) = self.path {
                keyring.dump(path, *mtime).await?;
            }
        }

        let Some(ref path) = self.path else {
            return Ok(());
        };

        #[cfg(feature = "tokio")]
        if let Ok(modified) = fs::metadata(path).await?.modified() {
            *mtime = Some(modified);
        }
        #[cfg(feature = "async-std")]
        if let Ok(modified) = fs::metadata(path).await?.modified() {
            *mtime = Some(modified);
        }

        Ok(())
    }

    fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    async fn modified_time(&self) -> Duration {
        self.inner.read().await.modified_time()
    }

    fn lock(self: Box<Self>) -> Box<dyn LockedKeyring> {
        Box::new(GpgLockedKeyring {
            inner: self.inner,
            path: self.path,
            mtime: self.mtime,
            label: self.label,
            notifier: self.notifier,
        })
    }

    async fn key(&self) -> Result<Arc<Key>, crate::crypto::Error> {
        self.get_key().await
    }

    async fn validate_secret(&self, _secret: &Secret) -> Result<bool, Error> {
        // GPG keyrings don't use password-based secrets
        // They use the GPG agent for authentication
        Ok(false)
    }

    async fn change_secret(&self, _secret: Secret) -> Result<(), Error> {
        // GPG keyrings cannot change password via this API
        // The GPG key's passphrase is managed by gpg-agent
        Err(Error::NotPasswordBased)
    }
}

impl GpgUnlockedKeyring {
    /// Get the cached key.
    async fn get_key(&self) -> Result<Arc<Key>, crate::crypto::Error> {
        let key_lock = self.key.lock().await;
        key_lock
            .as_ref()
            .cloned()
            .ok_or(crate::crypto::Error::NoKey)
    }

    /// Rotate the master key for forward secrecy.
    async fn rotate_key(&self) -> Result<(), Error> {
        use crate::crypto::gpg;

        #[cfg(feature = "tracing")]
        tracing::debug!("Rotating master key for GPG keyring");

        // Get the current key
        let old_key = self.get_key().await?;

        // Generate a new random master key (16 bytes for AES-128)
        let master_key = gpg::generate_session_key(16)?;

        #[cfg(feature = "tracing")]
        tracing::debug!("Generated new master key, encrypting with GPG");

        // Encrypt the master key with the GPG public key
        let encrypted_master_key = gpg::encrypt_session_key(&master_key, &self.gpg_key_id)?;

        // Convert master key to Key type
        let new_key = Arc::new(Key::new_with_strength(master_key.to_vec(), Ok(())));

        // Decrypt all items with old key and re-encrypt with new key
        {
            let keyring = self.inner.read().await;
            let mut items = Vec::with_capacity(keyring.items.len());

            for item in &keyring.items {
                items.push(item.clone().decrypt(&old_key)?);
            }
            drop(keyring);

            let mut keyring = self.inner.write().await;
            keyring.items.clear();

            for item in items {
                let encrypted_item = item.encrypt(&new_key)?;
                keyring.items.push(encrypted_item);
            }

            // Update the GPG configuration
            keyring.gpg_config = Some(api::GpgConfig {
                gpg_key_id: self.gpg_key_id.clone(),
                encrypted_master_key,
            });
        }

        // Update the cached key
        let mut key_lock = self.key.lock().await;
        *key_lock = Some(new_key);

        #[cfg(feature = "tracing")]
        tracing::debug!("Key rotation complete");

        Ok(())
    }
}
