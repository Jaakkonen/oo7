//! Password-based keyring implementation.
//!
//! This module provides keyring implementations that use password-based
//! encryption (PBKDF2 key derivation).

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
    traits::{LockedKeyring, SecretProvider, UnlockedKeyring},
};
#[cfg(feature = "tokio")]
use super::traits::BeginUnlockResult;
use crate::{AsAttributes, Key, Secret};

/// A password-based locked keyring.
///
/// This keyring uses PBKDF2 key derivation from a user-provided password.
/// When unlocking, it calls the injected `SecretProvider` to obtain the password.
pub struct PasswordLockedKeyring {
    pub(super) inner: Arc<RwLock<api::Keyring>>,
    pub(super) path: Option<PathBuf>,
    pub(super) mtime: Mutex<Option<std::time::SystemTime>>,
    pub(super) label: String,
    pub(super) secret_provider: Arc<dyn SecretProvider>,
}

impl std::fmt::Debug for PasswordLockedKeyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordLockedKeyring")
            .field("path", &self.path)
            .field("label", &self.label)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl LockedKeyring for PasswordLockedKeyring {
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

    async fn validate_secret(&self, secret: &Secret) -> Result<bool, Error> {
        let keyring = self.inner.read().await;
        Ok(keyring.validate_secret(secret)?)
    }

    fn requires_password(&self) -> bool {
        true // Password keyrings require a password from the user
    }

    #[cfg(feature = "tokio")]
    async fn begin_unlock(self: Box<Self>) -> Result<BeginUnlockResult, Error> {
        // Create prompt and get path immediately
        let prompt_path = self.secret_provider.create_prompt(&self.label).await?;

        // Create channel for completion notification
        let (tx, rx) = tokio::sync::oneshot::channel();

        // Clone the data we need for the background task
        let secret_provider = Arc::clone(&self.secret_provider);
        let label = self.label.clone();
        let prompt_path_clone = prompt_path.clone();

        // Spawn background task to wait for prompt completion and unlock
        tokio::spawn(async move {
            let result = async {
                // Wait for prompt to complete
                let mut secret = secret_provider.await_prompt(&prompt_path_clone).await?;

                // Try to unlock with the secret, retrying on wrong password
                loop {
                    match self.try_unlock(&secret).await {
                        Ok(unlocked) => {
                            return Ok(Box::new(unlocked) as Box<dyn UnlockedKeyring>);
                        }
                        Err(Error::IncorrectSecret) => {
                            // Password was wrong, ask for another
                            secret = secret_provider
                                .secret_rejected(&label, &Error::IncorrectSecret)
                                .await?;
                        }
                        Err(e) => return Err(e),
                    }
                }
            }
            .await;

            // Send result through channel (ignore errors if receiver dropped)
            let _ = tx.send(result);
        });

        Ok(BeginUnlockResult::NeedsInput {
            prompt_path,
            completion: rx,
        })
    }

    async fn unlock(self: Box<Self>) -> Result<Box<dyn UnlockedKeyring>, Error> {
        // Get the secret from the provider
        let mut secret = self.secret_provider.get_secret(&self.label).await?;

        loop {
            match self.try_unlock(&secret).await {
                Ok(unlocked) => return Ok(Box::new(unlocked)),
                Err(Error::IncorrectSecret) => {
                    // Password was wrong, ask for another
                    secret = self
                        .secret_provider
                        .secret_rejected(&self.label, &Error::IncorrectSecret)
                        .await?;
                }
                Err(e) => return Err(e),
            }
        }
    }

    async fn unlock_with_secret(
        self: Box<Self>,
        secret: &Secret,
    ) -> Result<Box<dyn UnlockedKeyring>, Error> {
        // Directly unlock with the provided secret
        let unlocked = self.try_unlock(secret).await?;
        Ok(Box::new(unlocked))
    }
}

impl PasswordLockedKeyring {
    /// Try to unlock with the given secret.
    async fn try_unlock(&self, secret: &Secret) -> Result<PasswordUnlockedKeyring, Error> {
        let inner_keyring = self.inner.read().await;

        let key = inner_keyring.derive_key(secret)?;

        // Validate items can be decrypted with this key
        inner_keyring.validate_key(&key)?;
        drop(inner_keyring);

        Ok(PasswordUnlockedKeyring {
            inner: Arc::clone(&self.inner),
            path: self.path.clone(),
            mtime: Mutex::new(*self.mtime.lock().await),
            key: Mutex::new(Some(Arc::new(key))),
            secret: Mutex::new(Arc::new(secret.clone())),
            label: self.label.clone(),
            secret_provider: Arc::clone(&self.secret_provider),
        })
    }

    /// Unlock the keyring with a known secret.
    ///
    /// This bypasses the `SecretProvider` and unlocks directly with the given secret.
    /// Use this when the secret is already known (e.g., from PAM authentication).
    ///
    /// # Arguments
    /// * `secret` - The secret to unlock with
    ///
    /// # Errors
    /// Returns an error if the secret is invalid or if decryption fails.
    pub async fn unlock_with_secret(
        self,
        secret: &Secret,
    ) -> Result<PasswordUnlockedKeyring, Error> {
        self.try_unlock(secret).await
    }

    /// Load a password-based keyring from a file path.
    ///
    /// # Arguments
    /// * `path` - The file path to load from
    /// * `label` - Human-readable label for this keyring
    /// * `secret_provider` - Provider for obtaining the unlock password
    pub async fn load(
        path: impl AsRef<Path>,
        label: &str,
        secret_provider: Arc<dyn SecretProvider>,
    ) -> Result<Self, Error> {
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

        // Verify this is not a GPG-encrypted keyring
        if keyring.gpg_config.is_some() {
            return Err(Error::NotGpgEncrypted); // TODO: Add a better error variant
        }

        Ok(Self {
            inner: Arc::new(RwLock::new(keyring)),
            path: Some(path.to_path_buf()),
            mtime: Mutex::new(mtime),
            label: label.to_string(),
            secret_provider,
        })
    }
}

/// A password-based unlocked keyring with full CRUD access.
pub struct PasswordUnlockedKeyring {
    pub(super) inner: Arc<RwLock<api::Keyring>>,
    pub(super) path: Option<PathBuf>,
    pub(super) mtime: Mutex<Option<std::time::SystemTime>>,
    pub(super) key: Mutex<Option<Arc<Key>>>,
    pub(super) secret: Mutex<Arc<Secret>>,
    pub(super) label: String,
    pub(super) secret_provider: Arc<dyn SecretProvider>,
}

impl std::fmt::Debug for PasswordUnlockedKeyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordUnlockedKeyring")
            .field("path", &self.path)
            .field("label", &self.label)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl UnlockedKeyring for PasswordUnlockedKeyring {
    async fn items(&self) -> Result<Vec<Result<Item, InvalidItemError>>, Error> {
        let key = self.derive_key().await?;
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
        let key = self.derive_key().await?;
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
            let key = self.derive_key().await?;
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
            let key = self.derive_key().await?;
            let mut keyring = self.inner.write().await;
            keyring.remove_items(attrs, &key)?;
        }
        self.write().await
    }

    async fn write(&self) -> Result<(), Error> {
        let mut mtime = self.mtime.lock().await;
        let mut keyring = self.inner.write().await;

        if let Some(ref path) = self.path {
            keyring.dump(path, *mtime).await?;
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
        Box::new(PasswordLockedKeyring {
            inner: self.inner,
            path: self.path,
            mtime: self.mtime,
            label: self.label,
            secret_provider: self.secret_provider,
        })
    }

    async fn key(&self) -> Result<Arc<Key>, crate::crypto::Error> {
        self.derive_key().await
    }

    async fn validate_secret(&self, secret: &Secret) -> Result<bool, Error> {
        let keyring = self.inner.read().await;
        Ok(keyring.validate_secret(secret)?)
    }

    async fn change_secret(&self, secret: Secret) -> Result<(), Error> {
        let key = self.derive_key().await?;

        // Decrypt all items with old key
        let mut items = Vec::new();
        {
            let keyring = self.inner.read().await;
            items.reserve(keyring.items.len());
            for item in &keyring.items {
                items.push(item.clone().decrypt(&key)?);
            }
        }

        // Update stored secret and clear cached key
        {
            let mut secret_lock = self.secret.lock().await;
            *secret_lock = Arc::new(secret);
        }
        {
            let mut key_lock = self.key.lock().await;
            *key_lock = None;
        }

        // Reset keyring (generates new salt, clears items)
        {
            let mut keyring = self.inner.write().await;
            keyring.reset();
        }

        // Derive new key with new secret and salt
        let new_key = self.derive_key().await?;

        // Re-encrypt all items with the new key
        {
            let mut keyring = self.inner.write().await;
            for item in items {
                let encrypted_item = item.encrypt(&new_key)?;
                keyring.items.push(encrypted_item);
            }
        }

        self.write().await
    }
}

/// A no-op secret provider for temporary/session keyrings.
///
/// This provider returns an error if called, since temporary keyrings
/// are always unlocked and should never need to prompt for a password.
struct NoOpSecretProvider;

impl std::fmt::Debug for NoOpSecretProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoOpSecretProvider").finish()
    }
}

#[async_trait]
impl SecretProvider for NoOpSecretProvider {
    async fn create_prompt(&self, _label: &str) -> Result<String, Error> {
        Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Temporary keyrings do not support prompts",
        )))
    }

    async fn await_prompt(&self, _prompt_path: &str) -> Result<crate::Secret, Error> {
        Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Temporary keyrings do not support prompts",
        )))
    }

    async fn secret_rejected(&self, _label: &str, _error: &Error) -> Result<crate::Secret, Error> {
        Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Temporary keyrings do not support prompts",
        )))
    }
}

impl PasswordUnlockedKeyring {
    /// Creates a temporary in-memory keyring that is never stored on disk.
    ///
    /// This is useful for session collections that exist only in memory.
    /// The keyring will not persist after the process exits.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(secret)))]
    pub async fn temporary(secret: crate::Secret) -> Result<Self, Error> {
        let keyring = api::Keyring::new();
        Ok(Self {
            inner: Arc::new(RwLock::new(keyring)),
            path: None,
            mtime: Mutex::new(None),
            key: Mutex::new(None),
            secret: Mutex::new(Arc::new(secret)),
            label: "session".to_string(),
            secret_provider: Arc::new(NoOpSecretProvider),
        })
    }

    /// Create a temporary keyring with a custom secret provider.
    ///
    /// This is useful for tests that need prompt support when the keyring is locked.
    pub async fn temporary_with_provider(
        secret: crate::Secret,
        secret_provider: Arc<dyn SecretProvider>,
    ) -> Result<Self, Error> {
        let keyring = api::Keyring::new();
        Ok(Self {
            inner: Arc::new(RwLock::new(keyring)),
            path: None,
            mtime: Mutex::new(None),
            key: Mutex::new(None),
            secret: Mutex::new(Arc::new(secret)),
            label: "session".to_string(),
            secret_provider,
        })
    }

    /// Open or create a named keyring with the given secret.
    ///
    /// If the keyring file exists, it will be loaded and unlocked with the secret.
    /// If it doesn't exist, a new empty keyring will be created.
    ///
    /// This is a convenience method for scenarios where the secret is already known
    /// (e.g., provided by user through a prompt).
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(secret)))]
    pub async fn open(name: &str, secret: crate::Secret) -> Result<Self, Error> {
        let path = api::Keyring::path(name, api::MAJOR_VERSION)?;

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

        // Verify this is not a GPG-encrypted keyring
        if keyring.gpg_config.is_some() {
            return Err(Error::NotGpgEncrypted);
        }

        let keyring = Arc::new(RwLock::new(keyring));

        // Derive key to validate secret
        let key = {
            let inner = keyring.read().await;
            inner.derive_key(&secret)?
        };

        // Use name as label (capitalized)
        let label = {
            let mut chars = name.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
            }
        };

        Ok(Self {
            inner: keyring,
            path: Some(path),
            mtime: Mutex::new(mtime),
            key: Mutex::new(Some(Arc::new(key))),
            secret: Mutex::new(Arc::new(secret)),
            label,
            secret_provider: Arc::new(NoOpSecretProvider),
        })
    }

    /// Return key, derive and store it first if not initialized.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self)))]
    async fn derive_key(&self) -> Result<Arc<Key>, crate::crypto::Error> {
        let keyring = Arc::clone(&self.inner);
        let secret_lock = self.secret.lock().await;
        let secret = Arc::clone(&secret_lock);
        drop(secret_lock);

        let mut key_lock = self.key.lock().await;
        if key_lock.is_none() {
            #[cfg(feature = "async-std")]
            let key = blocking::unblock(move || {
                async_io::block_on(async { keyring.read().await.derive_key(&secret) })
            })
            .await?;
            #[cfg(feature = "tokio")]
            let key = {
                tokio::task::spawn_blocking(move || keyring.blocking_read().derive_key(&secret))
                    .await
                    .unwrap()?
            };

            *key_lock = Some(Arc::new(key));
        }

        Ok(Arc::clone(key_lock.as_ref().unwrap()))
    }
}
