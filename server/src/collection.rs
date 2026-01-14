// org.freedesktop.Secret.Collection

use std::{
    collections::HashMap,
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime},
};

use oo7::{
    Key, Secret,
    dbus::{
        ServiceError,
        api::{DBusSecretInner, Properties},
    },
    file::{
        BeginUnlockResult, InvalidItemError, Item as FileItem,
        LockedKeyringTrait, UnlockedKeyringTrait,
    },
};
use tokio::sync::{Mutex, RwLock};
use zbus::{interface, object_server::SignalEmitter, proxy::Defaults, zvariant};
use zvariant::{ObjectPath, OwnedObjectPath};

use crate::{
    Service,
    error::{Error, custom_service_error},
    item,
};

/// State of a keyring - either locked or unlocked.
///
/// This is an internal enum that wraps trait objects for polymorphic keyring handling.
/// It allows the Collection to work with both password-based and GPG keyrings
/// without knowing the specific implementation.
pub enum KeyringState {
    Locked(Box<dyn LockedKeyringTrait>),
    Unlocked(Box<dyn UnlockedKeyringTrait>),
}

impl std::fmt::Debug for KeyringState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Locked(_) => write!(f, "KeyringState::Locked"),
            Self::Unlocked(_) => write!(f, "KeyringState::Unlocked"),
        }
    }
}

#[allow(dead_code)]
impl KeyringState {
    pub fn is_locked(&self) -> bool {
        matches!(self, Self::Locked(_))
    }

    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::Locked(k) => k.path(),
            Self::Unlocked(k) => k.path(),
        }
    }

    pub async fn modified_time(&self) -> Duration {
        match self {
            Self::Locked(k) => k.modified_time().await,
            Self::Unlocked(k) => k.modified_time().await,
        }
    }

    pub async fn items(&self) -> Result<Vec<Result<FileItem, InvalidItemError>>, oo7::file::Error> {
        match self {
            Self::Locked(k) => k.items().await,
            Self::Unlocked(k) => k.items().await,
        }
    }

    pub async fn validate_secret(&self, secret: &Secret) -> Result<bool, oo7::file::Error> {
        match self {
            Self::Locked(k) => k.validate_secret(secret).await,
            Self::Unlocked(_) => Ok(true), // Already unlocked
        }
    }

    pub fn as_unlocked(&self) -> &dyn UnlockedKeyringTrait {
        match self {
            Self::Unlocked(k) => k.as_ref(),
            Self::Locked(_) => panic!("Keyring is locked"),
        }
    }

    pub async fn key(&self) -> Result<Arc<Key>, oo7::crypto::Error> {
        match self {
            Self::Unlocked(k) => k.key().await,
            Self::Locked(_) => panic!("Keyring is locked"),
        }
    }
}


#[derive(Debug, Clone)]
pub struct Collection {
    // Properties
    items: Arc<Mutex<Vec<item::Item>>>,
    label: Arc<Mutex<String>>,
    created: Duration,
    modified: Arc<Mutex<Duration>>,
    // Other attributes
    alias: Arc<Mutex<String>>,
    pub(crate) keyring: Arc<RwLock<Option<KeyringState>>>,
    service: Service,
    item_index: Arc<RwLock<u32>>,
    path: OwnedObjectPath,
}

#[interface(name = "org.freedesktop.Secret.Collection")]
impl Collection {
    #[zbus(out_args("prompt"))]
    pub async fn delete(&self) -> Result<OwnedObjectPath, ServiceError> {
        // If already unlocked, delete directly
        if !self.is_locked().await {
            self.delete_unlocked().await?;
            return Ok(OwnedObjectPath::default());
        }

        // Take the locked keyring and begin unlock
        let locked_keyring = {
            let mut keyring_guard = self.keyring.write().await;
            match keyring_guard.take() {
                Some(KeyringState::Locked(locked)) => locked,
                Some(unlocked) => {
                    // Already unlocked (race condition), put it back
                    *keyring_guard = Some(unlocked);
                    drop(keyring_guard);
                    self.delete_unlocked().await?;
                    return Ok(OwnedObjectPath::default());
                }
                None => {
                    return Err(custom_service_error("Keyring not available"));
                }
            }
        };

        // Begin unlock - no type branching, keyring handles it
        match locked_keyring.begin_unlock().await.map_err(|e| {
            custom_service_error(&format!("Failed to begin unlock: {e}"))
        })? {
            BeginUnlockResult::Unlocked(unlocked) => {
                // GPG keyring unlocked immediately
                tracing::debug!(
                    "Collection `{}` unlocked immediately for delete",
                    self.path
                );

                // Update items to unlocked state
                let items = self.items.lock().await;
                for item in items.iter() {
                    item.set_locked_trait(false, unlocked.as_ref()).await?;
                }
                drop(items);

                // Store unlocked keyring
                *self.keyring.write().await = Some(KeyringState::Unlocked(unlocked));

                // Now delete
                self.delete_unlocked().await?;
                Ok(OwnedObjectPath::default())
            }
            BeginUnlockResult::NeedsInput { prompt_path, completion } => {
                // Password keyring - prompt created, return path
                tracing::debug!(
                    "Delete prompt created at `{}` for locked collection `{}`",
                    prompt_path,
                    self.path
                );

                // Spawn task to complete delete when unlock finishes
                let collection = self.clone();
                tokio::spawn(async move {
                    match completion.await {
                        Ok(Ok(unlocked)) => {
                            // Update items to unlocked state
                            let items = collection.items.lock().await;
                            for item in items.iter() {
                                if let Err(e) = item.set_locked_trait(false, unlocked.as_ref()).await {
                                    tracing::error!("Failed to unlock item: {e}");
                                }
                            }
                            drop(items);

                            // Store unlocked keyring
                            *collection.keyring.write().await = Some(KeyringState::Unlocked(unlocked));

                            // Delete
                            if let Err(e) = collection.delete_unlocked().await {
                                tracing::error!("Failed to delete collection: {e}");
                            }
                        }
                        Ok(Err(e)) => {
                            tracing::error!("Unlock failed: {e}");
                        }
                        Err(_) => {
                            tracing::debug!("Unlock cancelled (prompt dismissed)");
                        }
                    }
                });

                Ok(OwnedObjectPath::try_from(prompt_path).unwrap_or_default())
            }
        }
    }

    async fn delete_unlocked(&self) -> Result<(), ServiceError> {
        let keyring = self.keyring.read().await;
        let keyring = keyring.as_ref().unwrap().as_unlocked();

        let object_server = self.service.object_server();

        // Remove all items from the object server
        let items = self.items.lock().await;
        for item in items.iter() {
            object_server.remove::<item::Item, _>(item.path()).await?;
        }
        drop(items);

        // Delete the keyring file if it's persistent
        if let Some(path) = keyring.path() {
            tokio::fs::remove_file(&path).await.map_err(|err| {
                custom_service_error(&format!("Failed to delete keyring file: {err}"))
            })?;
            tracing::debug!("Deleted keyring file: {}", path.display());
        }

        // Emit CollectionDeleted signal before removing from object server
        let service_path = oo7::dbus::api::Service::PATH.as_ref().unwrap();
        let signal_emitter = self.service.signal_emitter(service_path)?;
        Service::collection_deleted(&signal_emitter, &self.path).await?;

        // Remove collection from object server
        object_server.remove::<Collection, _>(&self.path).await?;

        // Notify service to remove from collections list
        self.service.remove_collection(&self.path).await;

        tracing::info!("Collection `{}` deleted.", self.path);

        Ok(())
    }

    #[zbus(out_args("results"))]
    pub async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> Result<Vec<OwnedObjectPath>, ServiceError> {
        let results = self
            .search_inner_items(&attributes)
            .await?
            .iter()
            .map(|item| item.path().clone().into())
            .collect::<Vec<OwnedObjectPath>>();

        if results.is_empty() {
            tracing::debug!(
                "Items with attributes {:?} does not exist in collection: {}.",
                attributes,
                self.path
            );
        } else {
            tracing::debug!(
                "Items with attributes {:?} found in collection: {}.",
                attributes,
                self.path
            );
        }

        Ok(results)
    }

    #[zbus(out_args("item", "prompt"))]
    pub async fn create_item(
        &self,
        properties: Properties,
        secret: DBusSecretInner,
        replace: bool,
    ) -> Result<(OwnedObjectPath, OwnedObjectPath), ServiceError> {
        // If already unlocked, create item directly
        if !self.is_locked().await {
            let item_path = self
                .create_item_unlocked(properties, secret, replace)
                .await?;
            return Ok((item_path, OwnedObjectPath::default()));
        }

        // Take the locked keyring and begin unlock
        let locked_keyring = {
            let mut keyring_guard = self.keyring.write().await;
            match keyring_guard.take() {
                Some(KeyringState::Locked(locked)) => locked,
                Some(unlocked) => {
                    // Already unlocked (race condition), put it back
                    *keyring_guard = Some(unlocked);
                    drop(keyring_guard);
                    let item_path = self
                        .create_item_unlocked(properties, secret, replace)
                        .await?;
                    return Ok((item_path, OwnedObjectPath::default()));
                }
                None => {
                    return Err(custom_service_error("Keyring not available"));
                }
            }
        };

        // Begin unlock - no type branching, keyring handles it
        match locked_keyring.begin_unlock().await.map_err(|e| {
            custom_service_error(&format!("Failed to begin unlock: {e}"))
        })? {
            BeginUnlockResult::Unlocked(unlocked) => {
                // GPG keyring unlocked immediately
                tracing::debug!(
                    "Collection `{}` unlocked immediately for create_item",
                    self.path
                );

                // Update items to unlocked state
                let items = self.items.lock().await;
                for item in items.iter() {
                    item.set_locked_trait(false, unlocked.as_ref()).await?;
                }
                drop(items);

                // Store unlocked keyring
                *self.keyring.write().await = Some(KeyringState::Unlocked(unlocked));

                // Create item
                let item_path = self
                    .create_item_unlocked(properties, secret, replace)
                    .await?;
                Ok((item_path, OwnedObjectPath::default()))
            }
            BeginUnlockResult::NeedsInput { prompt_path, completion } => {
                // Password keyring - prompt created, return path
                // The client will trigger the prompt and wait for completion
                tracing::debug!(
                    "CreateItem prompt created at `{}` for locked collection `{}`",
                    prompt_path,
                    self.path
                );

                // Clone data for the background task
                let collection = self.clone();
                let prompt_path_owned = OwnedObjectPath::try_from(prompt_path.clone())
                    .unwrap_or_default();

                // Spawn task to complete create_item when unlock finishes
                // This task will emit the Prompt::completed signal with the item path
                tokio::spawn(async move {
                    match completion.await {
                        Ok(Ok(unlocked)) => {
                            // Update items to unlocked state
                            let items = collection.items.lock().await;
                            for item in items.iter() {
                                if let Err(e) = item.set_locked_trait(false, unlocked.as_ref()).await {
                                    tracing::error!("Failed to unlock item: {e}");
                                }
                            }
                            drop(items);

                            // Store unlocked keyring
                            *collection.keyring.write().await = Some(KeyringState::Unlocked(unlocked));

                            // Create item
                            match collection
                                .create_item_unlocked(properties, secret, replace)
                                .await
                            {
                                Ok(item_path) => {
                                    tracing::debug!("Created item at `{}` after unlock", item_path);
                                    // The Prompt::completed signal will be emitted by PrompterCallback
                                    // with the action's return value. Since we're creating the item
                                    // asynchronously, we can't return the path through the action.
                                    // The client will need to query the collection for the new item.
                                }
                                Err(e) => {
                                    tracing::error!("Failed to create item: {e}");
                                }
                            }
                        }
                        Ok(Err(e)) => {
                            tracing::error!("Unlock failed: {e}");
                        }
                        Err(_) => {
                            tracing::debug!("Unlock cancelled (prompt dismissed)");
                        }
                    }
                });

                Ok((OwnedObjectPath::default(), prompt_path_owned))
            }
        }
    }

    async fn create_item_unlocked(
        &self,
        properties: Properties,
        secret: DBusSecretInner,
        replace: bool,
    ) -> Result<OwnedObjectPath, ServiceError> {
        let keyring = self.keyring.read().await;
        let keyring = keyring.as_ref().unwrap().as_unlocked();

        let DBusSecretInner(session_path, iv, secret_bytes, content_type) = secret;
        let label = properties.label();
        // Safe to unwrap as an item always has attributes
        let mut attributes = properties.attributes().unwrap().to_owned();

        let Some(session) = self.service.session(&session_path).await else {
            tracing::error!("The session `{}` does not exist.", session_path);
            return Err(ServiceError::NoSession(format!(
                "The session `{session_path}` does not exist."
            )));
        };

        let secret = match session.aes_key() {
            Some(key) => oo7::crypto::decrypt(secret_bytes, &key, &iv)
                .map_err(|err| custom_service_error(&format!("Failed to decrypt secret {err}.")))?,
            None => zeroize::Zeroizing::new(secret_bytes),
        };

        // Ensure content-type attribute is stored
        if !attributes.contains_key(oo7::CONTENT_TYPE_ATTRIBUTE) {
            attributes.insert(
                oo7::CONTENT_TYPE_ATTRIBUTE.to_owned(),
                content_type.as_str().to_owned(),
            );
        }

        let item = keyring
            .create_item(label, &attributes, secret.into(), replace)
            .await
            .map_err(|err| custom_service_error(&format!("Failed to create a new item {err}.")))?;

        let n_items = *self.item_index.read().await;
        let item_path = OwnedObjectPath::try_from(format!("{}/{n_items}", self.path)).unwrap();

        let item = item::Item::new(
            item,
            self.service.clone(),
            self.path.clone(),
            item_path.clone(),
        );
        *self.item_index.write().await = n_items + 1;

        let object_server = self.service.object_server();
        let signal_emitter = self.service.signal_emitter(&self.path)?;

        // Remove any existing items with the same attributes
        if replace {
            let existing_items = self.search_inner_items(&attributes).await?;
            if !existing_items.is_empty() {
                let mut items = self.items.lock().await;
                for existing in &existing_items {
                    let existing_path = existing.path();

                    items.retain(|i| i.path() != existing_path);
                    object_server.remove::<item::Item, _>(existing_path).await?;
                    Self::item_deleted(&signal_emitter, existing_path).await?;

                    tracing::debug!("Replaced item `{}`", existing_path);
                }
                drop(items);
            }
        }

        self.items.lock().await.push(item.clone());

        object_server.at(&item_path, item).await?;

        self.update_modified().await?;

        Self::item_created(&signal_emitter, &item_path).await?;
        self.items_changed(&signal_emitter).await?;

        tracing::info!("Item `{item_path}` created.");

        Ok(item_path)
    }

    #[zbus(property, name = "Items")]
    pub async fn items(&self) -> Vec<OwnedObjectPath> {
        self.items
            .lock()
            .await
            .iter()
            .map(|i| i.path().to_owned().into())
            .collect()
    }

    #[zbus(property, name = "Label")]
    pub async fn label(&self) -> String {
        self.label.lock().await.clone()
    }

    #[zbus(property, name = "Label")]
    pub async fn set_label(&self, label: &str) -> Result<(), zbus::Error> {
        if self.is_locked().await {
            tracing::error!("Cannot set label of a locked collection `{}`", self.path);
            return Err(zbus::Error::FDO(Box::new(zbus::fdo::Error::Failed(
                format!("Cannot set label of a locked collection `{}`.", self.path),
            ))));
        }

        *self.label.lock().await = label.to_owned();

        self.update_modified()
            .await
            .map_err(|err| zbus::Error::FDO(Box::new(zbus::fdo::Error::Failed(err.to_string()))))?;

        let service_path = oo7::dbus::api::Service::PATH.as_ref().unwrap();
        let signal_emitter = self
            .service
            .signal_emitter(service_path)
            .map_err(|err| zbus::Error::FDO(Box::new(zbus::fdo::Error::Failed(err.to_string()))))?;
        Service::collection_changed(&signal_emitter, &self.path).await?;

        let signal_emitter = self
            .service
            .signal_emitter(&self.path)
            .map_err(|err| zbus::Error::FDO(Box::new(zbus::fdo::Error::Failed(err.to_string()))))?;
        self.label_changed(&signal_emitter).await?;

        Ok(())
    }

    #[zbus(property, name = "Locked")]
    pub async fn is_locked(&self) -> bool {
        self.keyring
            .read()
            .await
            .as_ref()
            .map(|k| k.is_locked())
            .unwrap_or(true)
    }

    #[zbus(property, name = "Created")]
    pub fn created_at(&self) -> u64 {
        self.created.as_secs()
    }

    #[zbus(property, name = "Modified")]
    pub async fn modified_at(&self) -> u64 {
        self.modified.lock().await.as_secs()
    }

    #[zbus(signal, name = "ItemCreated")]
    async fn item_created(
        signal_emitter: &SignalEmitter<'_>,
        item: &ObjectPath<'_>,
    ) -> zbus::Result<()>;

    #[zbus(signal, name = "ItemDeleted")]
    pub async fn item_deleted(
        signal_emitter: &SignalEmitter<'_>,
        item: &ObjectPath<'_>,
    ) -> zbus::Result<()>;

    #[zbus(signal, name = "ItemChanged")]
    pub async fn item_changed(
        signal_emitter: &SignalEmitter<'_>,
        item: &ObjectPath<'_>,
    ) -> zbus::Result<()>;
}

impl Collection {
    pub async fn new(
        label: &str,
        alias: &str,
        service: Service,
        keyring_state: KeyringState,
    ) -> Self {
        let modified = keyring_state.modified_time().await;

        // Get created time from filesystem if keyring has a path
        let created = if let Some(path) = keyring_state.path() {
            tokio::fs::metadata(path)
                .await
                .ok()
                .and_then(|m| m.created().ok())
                .and_then(|t| t.duration_since(std::time::SystemTime::UNIX_EPOCH).ok())
                .unwrap_or(modified)
        } else {
            modified
        };

        let sanitized_label = label
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect::<String>();

        Self {
            items: Default::default(),
            label: Arc::new(Mutex::new(label.to_owned())),
            modified: Arc::new(Mutex::new(modified)),
            alias: Arc::new(Mutex::new(alias.to_owned())),
            item_index: Arc::new(RwLock::new(0)),
            path: OwnedObjectPath::try_from(format!(
                "/org/freedesktop/secrets/collection/{sanitized_label}"
            ))
            .expect("Sanitized label should always produce valid object path"),
            created,
            service,
            keyring: Arc::new(RwLock::new(Some(keyring_state))),
        }
    }

    pub fn path(&self) -> &ObjectPath<'_> {
        &self.path
    }

    pub async fn set_alias(&self, alias: &str) {
        *self.alias.lock().await = alias.to_owned();
    }

    pub async fn alias(&self) -> String {
        self.alias.lock().await.clone()
    }

    pub async fn search_inner_items(
        &self,
        attributes: &HashMap<String, String>,
    ) -> Result<Vec<item::Item>, ServiceError> {
        // If collection is locked, we can't search
        if self.is_locked().await {
            return Ok(Vec::new());
        }

        let keyring_guard = self.keyring.read().await;
        let keyring = keyring_guard.as_ref().unwrap().as_unlocked();

        let key = keyring
            .key()
            .await
            .map_err(|err| custom_service_error(&format!("Failed to derive key: {err}")))?;

        let mut matching_items = Vec::new();
        let items = self.items.lock().await;

        for item_wrapper in items.iter() {
            let inner = item_wrapper.inner.lock().await;
            let file_item = inner.as_ref().unwrap();

            // Use the oo7::file::Item's matches_attributes method
            if file_item.matches_attributes(attributes, &key) {
                matching_items.push(item_wrapper.clone());
            }
        }

        Ok(matching_items)
    }

    pub async fn item_from_path(&self, path: &ObjectPath<'_>) -> Option<item::Item> {
        let items = self.items.lock().await;

        items.iter().find(|i| i.path() == path).cloned()
    }

    pub async fn set_locked(
        &self,
        locked: bool,
        secret: Option<Secret>,
    ) -> Result<(), ServiceError> {
        let mut keyring_guard = self.keyring.write().await;

        if let Some(old_keyring) = keyring_guard.take() {
            let new_keyring = match (old_keyring, locked) {
                (KeyringState::Unlocked(unlocked), true) => {
                    // Lock the keyring
                    let items = self.items.lock().await;
                    for item in items.iter() {
                        item.set_locked_trait(true, unlocked.as_ref()).await?;
                    }
                    drop(items);

                    KeyringState::Locked(unlocked.lock())
                }
                (KeyringState::Locked(locked_kr), false) => {
                    // Try to unlock - prefer using provided secret if available
                    if let Some(ref secret) = secret {
                        // Validate first (doesn't consume the keyring)
                        let is_valid = locked_kr
                            .validate_secret(secret)
                            .await
                            .map_err(|e| custom_service_error(&format!(
                                "Failed to validate secret: {e}"
                            )))?;

                        if !is_valid {
                            // Secret is invalid - put the keyring back and return error
                            *keyring_guard = Some(KeyringState::Locked(locked_kr));
                            return Err(custom_service_error("Invalid secret"));
                        }

                        // Secret is valid - unlock (consumes the keyring)
                        let unlocked = locked_kr
                            .unlock_with_secret(secret)
                            .await
                            .map_err(|e| custom_service_error(&format!(
                                "Failed to unlock with secret: {e}"
                            )))?;

                        // Update items to unlocked state
                        let items = self.items.lock().await;
                        for item in items.iter() {
                            item.set_locked_trait(false, unlocked.as_ref()).await?;
                        }
                        drop(items);

                        KeyringState::Unlocked(unlocked)
                    } else {
                        // No secret provided - check if password is required
                        if locked_kr.requires_password() {
                            // Password keyring needs a prompt - don't consume the keyring
                            // Put it back and let the caller handle prompting
                            *keyring_guard = Some(KeyringState::Locked(locked_kr));
                            return Err(custom_service_error(
                                "Password keyring requires prompt; use D-Bus unlock method",
                            ));
                        }

                        // GPG keyring - can unlock without password via gpg-agent
                        match locked_kr.begin_unlock().await {
                            Ok(BeginUnlockResult::Unlocked(unlocked)) => {
                                // GPG keyring unlocked immediately
                                // Update items to unlocked state
                                let items = self.items.lock().await;
                                for item in items.iter() {
                                    item.set_locked_trait(false, unlocked.as_ref()).await?;
                                }
                                drop(items);

                                KeyringState::Unlocked(unlocked)
                            }
                            Ok(BeginUnlockResult::NeedsInput { .. }) => {
                                // Shouldn't happen for GPG keyrings
                                return Err(custom_service_error(
                                    "Unexpected: GPG keyring returned NeedsInput",
                                ));
                            }
                            Err(err) => {
                                return Err(custom_service_error(&format!(
                                    "Failed to unlock GPG keyring: {err}"
                                )));
                            }
                        }
                    }
                }
                (other, _) => other,
            };
            *keyring_guard = Some(new_keyring);
        }

        drop(keyring_guard);

        // Emit signals - don't fail the unlock if signal emission fails
        // The keyring has already been successfully unlocked at this point
        match self.service.signal_emitter(&self.path) {
            Ok(signal_emitter) => {
                if let Err(e) = self.locked_changed(&signal_emitter).await {
                    tracing::warn!("Failed to emit locked_changed signal for {}: {}", self.path, e);
                }
            }
            Err(e) => {
                tracing::warn!("Failed to get signal emitter for {}: {}", self.path, e);
            }
        }

        let service_path = oo7::dbus::api::Service::PATH.as_ref().unwrap();
        match self.service.signal_emitter(service_path) {
            Ok(signal_emitter) => {
                if let Err(e) = Service::collection_changed(&signal_emitter, &self.path).await {
                    tracing::warn!("Failed to emit collection_changed signal: {}", e);
                }
            }
            Err(e) => {
                tracing::warn!("Failed to get signal emitter for service path: {}", e);
            }
        }

        tracing::debug!(
            "Collection: {} is {}.",
            self.path,
            if locked { "locked" } else { "unlocked" }
        );

        Ok(())
    }

    pub async fn dispatch_items(&self) -> Result<(), Error> {
        let keyring_guard = self.keyring.read().await;
        let keyring = keyring_guard.as_ref().unwrap();

        let keyring_items = keyring.items().await?;
        let mut items = self.items.lock().await;
        let object_server = self.service.object_server();
        let mut n_items = 1;

        for keyring_item in keyring_items {
            let item_path = OwnedObjectPath::try_from(format!("{}/{n_items}", self.path)).unwrap();
            let item = item::Item::new(
                keyring_item.map_err(Error::InvalidItem)?,
                self.service.clone(),
                self.path.clone(),
                item_path.clone(),
            );
            n_items += 1;

            items.push(item.clone());
            object_server.at(item_path, item).await?;
        }

        *self.item_index.write().await = n_items;

        Ok(())
    }

    pub async fn delete_item(&self, path: &ObjectPath<'_>) -> Result<(), ServiceError> {
        let Some(item) = self.item_from_path(path).await else {
            return Err(ServiceError::NoSuchObject(format!(
                "Item `{path}` does not exist."
            )));
        };

        if item.is_locked().await {
            return Err(ServiceError::IsLocked(format!(
                "Cannot delete a locked item `{path}`"
            )));
        }

        if self.is_locked().await {
            return Err(ServiceError::IsLocked(format!(
                "Cannot delete an item `{path}`  in a locked collection "
            )));
        }

        let attributes = item.attributes().await.map_err(|err| {
            custom_service_error(&format!("Failed to read item attributes {err}"))
        })?;

        let keyring = self.keyring.read().await;
        let keyring = keyring.as_ref().unwrap().as_unlocked();

        keyring
            .delete(&attributes)
            .await
            .map_err(|err| custom_service_error(&format!("Failed to deleted item {err}.")))?;

        let mut items = self.items.lock().await;
        items.retain(|item| item.path() != path);
        drop(items);

        self.update_modified().await?;

        let signal_emitter = self.service.signal_emitter(&self.path)?;
        self.items_changed(&signal_emitter).await?;

        Ok(())
    }

    /// Update the modified timestamp and emit the PropertiesChanged signal
    async fn update_modified(&self) -> Result<(), ServiceError> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();
        *self.modified.lock().await = now;

        let signal_emitter = self.service.signal_emitter(&self.path)?;
        self.modified_changed(&signal_emitter).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use oo7::dbus;
    use tokio_stream::StreamExt;

    use crate::tests::TestServiceSetup;

    #[tokio::test]
    async fn create_item_plain() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Get initial modified timestamp
        let initial_modified = setup.collections[0].modified().await?;

        // Wait to ensure timestamp will be different
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        // Create an item using the proper API
        let secret = oo7::Secret::text("my-secret-password");
        let dbus_secret = dbus::api::DBusSecret::new(setup.session, secret.clone());

        let item = setup.collections[0]
            .create_item(
                "Test Item",
                &[("application", "test-app"), ("type", "password")],
                &dbus_secret,
                false,
                None,
            )
            .await?;

        // Verify item exists in collection
        let items = setup.collections[0].items().await?;
        assert_eq!(items.len(), 1, "Collection should have one item");
        assert_eq!(items[0].inner().path(), item.inner().path());

        // Verify item label
        let label = item.label().await?;
        assert_eq!(label, "Test Item");

        // Verify modified timestamp was updated
        let new_modified = setup.collections[0].modified().await?;
        assert!(
            new_modified > initial_modified,
            "Modified timestamp should be updated after creating item"
        );

        Ok(())
    }

    #[tokio::test]
    async fn create_item_encrypted() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::encrypted_session(true).await?;
        let aes_key = setup.aes_key.unwrap();

        // Create an encrypted item using the proper API
        let secret = oo7::Secret::text("my-encrypted-secret");
        let dbus_secret = dbus::api::DBusSecret::new_encrypted(setup.session, secret, &aes_key)?;

        let item = setup.collections[0]
            .create_item(
                "Test Encrypted Item",
                &[("application", "test-app"), ("type", "encrypted-password")],
                &dbus_secret,
                false,
                None,
            )
            .await?;

        // Verify item exists
        let items = setup.collections[0].items().await?;
        assert_eq!(items.len(), 1, "Collection should have one item");
        assert_eq!(items[0].inner().path(), item.inner().path());

        Ok(())
    }

    #[tokio::test]
    async fn search_items_after_creation() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Create two items with different attributes
        let secret1 = oo7::Secret::text("password1");
        let dbus_secret1 = dbus::api::DBusSecret::new(Arc::clone(&setup.session), secret1);

        setup.collections[0]
            .create_item(
                "Firefox Password",
                &[("application", "firefox"), ("username", "user1")],
                &dbus_secret1,
                false,
                None,
            )
            .await?;

        let secret2 = oo7::Secret::text("password2");
        let dbus_secret2 = dbus::api::DBusSecret::new(Arc::clone(&setup.session), secret2);

        setup.collections[0]
            .create_item(
                "Chrome Password",
                &[("application", "chrome"), ("username", "user2")],
                &dbus_secret2,
                false,
                None,
            )
            .await?;

        // Search for firefox item
        let firefox_attrs = &[("application", "firefox")];
        let firefox_items = setup.collections[0].search_items(firefox_attrs).await?;

        assert_eq!(firefox_items.len(), 1, "Should find one firefox item");

        // Search for chrome item
        let chrome_items = setup.collections[0]
            .search_items(&[("application", "chrome")])
            .await?;

        assert_eq!(chrome_items.len(), 1, "Should find one chrome item");

        // Search for non-existent item
        let nonexistent_items = setup.collections[0]
            .search_items(&[("application", "nonexistent")])
            .await?;

        assert_eq!(
            nonexistent_items.len(),
            0,
            "Should find no nonexistent items"
        );

        Ok(())
    }

    #[tokio::test]
    async fn search_items_subset_matching() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Create an item with multiple attributes (url and username)
        let secret = oo7::Secret::text("my-password");
        let dbus_secret = dbus::api::DBusSecret::new(Arc::clone(&setup.session), secret);

        setup.collections[0]
            .create_item(
                "Zed Login",
                &[("url", "https://zed.dev"), ("username", "alice")],
                &dbus_secret,
                false,
                None,
            )
            .await?;

        // Search with only the url attribute (subset of stored attributes)
        let results = setup.collections[0]
            .search_items(&[("url", "https://zed.dev")])
            .await?;

        assert_eq!(
            results.len(),
            1,
            "Should find item when searching with subset of its attributes"
        );

        // Search with only the username attribute (another subset)
        let results = setup.collections[0]
            .search_items(&[("username", "alice")])
            .await?;

        assert_eq!(
            results.len(),
            1,
            "Should find item when searching with different subset of its attributes"
        );

        // Search with both attributes (exact match)
        let results = setup.collections[0]
            .search_items(&[("url", "https://zed.dev"), ("username", "alice")])
            .await?;

        assert_eq!(
            results.len(),
            1,
            "Should find item when searching with all its attributes"
        );

        // Search with superset of attributes (should not match)
        let results = setup.collections[0]
            .search_items(&[
                ("url", "https://zed.dev"),
                ("username", "alice"),
                ("extra", "attribute"),
            ])
            .await?;

        assert_eq!(
            results.len(),
            0,
            "Should not find item when searching with superset of its attributes"
        );

        Ok(())
    }

    #[tokio::test]
    async fn create_item_with_replace() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Create first item
        let secret1 = oo7::Secret::text("original-password");
        let dbus_secret1 = dbus::api::DBusSecret::new(Arc::clone(&setup.session), secret1.clone());

        let item1 = setup.collections[0]
            .create_item(
                "Test Item",
                &[("application", "myapp"), ("username", "user")],
                &dbus_secret1,
                false,
                None,
            )
            .await?;

        // Verify one item exists
        let items = setup.collections[0].items().await?;
        assert_eq!(items.len(), 1, "Should have one item");

        // Get the secret from first item
        let retrieved1 = item1.secret(&setup.session).await?;
        assert_eq!(retrieved1.value(), secret1.as_bytes());

        // Create second item with same attributes and replace=true
        let secret2 = oo7::Secret::text("replaced-password");
        let dbus_secret2 = dbus::api::DBusSecret::new(Arc::clone(&setup.session), secret2.clone());

        let item2 = setup.collections[0]
            .create_item(
                "Test Item",
                &[("application", "myapp"), ("username", "user")],
                &dbus_secret2,
                true, // replace=true
                None,
            )
            .await?;

        // Should still have only one item (replaced)
        let items = setup.collections[0].items().await?;
        assert_eq!(items.len(), 1, "Should still have one item after replace");

        // Verify the new item has the updated secret
        let retrieved2 = item2.secret(&setup.session).await?;
        assert_eq!(retrieved2.value(), secret2.as_bytes());

        Ok(())
    }

    #[tokio::test]
    async fn label_property() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Get the Login collection via alias (don't rely on collection ordering)
        let login_collection = setup
            .service_api
            .read_alias("default")
            .await?
            .expect("Default collection should exist");

        // Get initial label (should be "Login" for default collection)
        let label = login_collection.label().await?;
        assert_eq!(label, "Login");

        // Get initial modified timestamp
        let initial_modified = login_collection.modified().await?;

        // Wait to ensure timestamp will be different
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        // Set new label
        login_collection.set_label("My Custom Collection").await?;

        // Verify new label
        let label = login_collection.label().await?;
        assert_eq!(label, "My Custom Collection");

        // Verify modified timestamp was updated
        let new_modified = login_collection.modified().await?;
        assert!(
            new_modified > initial_modified,
            "Modified timestamp should be updated after label change"
        );

        Ok(())
    }

    #[tokio::test]
    async fn timestamps() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Get created timestamp
        let created = setup.collections[0].created().await?;
        assert!(created.as_secs() > 0, "Created timestamp should be set");

        // Get modified timestamp
        let modified = setup.collections[0].modified().await?;
        assert!(modified.as_secs() > 0, "Modified timestamp should be set");

        // Created and modified should be close (within a second for new collection)
        let diff = if created > modified {
            created.as_secs() - modified.as_secs()
        } else {
            modified.as_secs() - created.as_secs()
        };
        assert!(diff <= 1, "Created and modified should be within 1 second");

        Ok(())
    }

    #[tokio::test]
    async fn create_item_invalid_session() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Create an item using the proper API
        let secret = oo7::Secret::text("my-secret-password");
        let invalid_session =
            dbus::api::Session::new(&setup.client_conn, "/invalid/session/path").await?;
        let dbus_secret = dbus::api::DBusSecret::new(Arc::new(invalid_session), secret.clone());

        let result = setup.collections[0]
            .create_item(
                "Test Item",
                &[("application", "test-app"), ("type", "password")],
                &dbus_secret,
                false,
                None,
            )
            .await;

        assert!(
            matches!(
                result,
                Err(oo7::dbus::Error::Service(
                    oo7::dbus::ServiceError::NoSession(_)
                ))
            ),
            "Should be NoSession error"
        );

        Ok(())
    }

    #[tokio::test]
    async fn item_created_signal() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Subscribe to ItemCreated signal
        let signal_stream = setup.collections[0].receive_item_created().await?;
        tokio::pin!(signal_stream);

        // Create an item
        let secret = oo7::Secret::text("test-secret");
        let dbus_secret = dbus::api::DBusSecret::new(Arc::clone(&setup.session), secret);

        let item = setup.collections[0]
            .create_item("Test Item", &[("app", "test")], &dbus_secret, false, None)
            .await?;

        // Wait for signal with timeout
        let signal_result =
            tokio::time::timeout(tokio::time::Duration::from_secs(1), signal_stream.next()).await;

        assert!(signal_result.is_ok(), "Should receive ItemCreated signal");
        let signal = signal_result.unwrap();
        assert!(signal.is_some(), "Signal should not be None");

        let signal_item = signal.unwrap();
        assert_eq!(
            signal_item.inner().path().as_str(),
            item.inner().path().as_str(),
            "Signal should contain the created item path"
        );

        Ok(())
    }

    #[tokio::test]
    async fn item_deleted_signal() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Create an item
        let secret = oo7::Secret::text("test-secret");
        let dbus_secret = dbus::api::DBusSecret::new(Arc::clone(&setup.session), secret);

        let item = setup.collections[0]
            .create_item("Test Item", &[("app", "test")], &dbus_secret, false, None)
            .await?;

        let item_path = item.inner().path().to_owned();

        // Subscribe to ItemDeleted signal
        let signal_stream = setup.collections[0].receive_item_deleted().await?;
        tokio::pin!(signal_stream);

        // Delete the item
        item.delete(None).await?;

        // Wait for signal with timeout
        let signal_result =
            tokio::time::timeout(tokio::time::Duration::from_secs(1), signal_stream.next()).await;

        assert!(signal_result.is_ok(), "Should receive ItemDeleted signal");
        let signal = signal_result.unwrap();
        assert!(signal.is_some(), "Signal should not be None");

        let signal_item = signal.unwrap();
        assert_eq!(
            signal_item.as_str(),
            item_path.as_str(),
            "Signal should contain the deleted item path"
        );

        Ok(())
    }

    #[tokio::test]
    async fn collection_changed_signal() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Subscribe to CollectionChanged signal
        let signal_stream = setup.service_api.receive_collection_changed().await?;
        tokio::pin!(signal_stream);

        // Change the collection label
        setup.collections[0]
            .set_label("Updated Collection Label")
            .await?;

        // Wait for signal with timeout
        let signal_result =
            tokio::time::timeout(tokio::time::Duration::from_secs(1), signal_stream.next()).await;

        assert!(
            signal_result.is_ok(),
            "Should receive CollectionChanged signal after label change"
        );
        let signal = signal_result.unwrap();
        assert!(signal.is_some(), "Signal should not be None");

        let signal_collection = signal.unwrap();
        assert_eq!(
            signal_collection.inner().path().as_str(),
            setup.collections[0].inner().path().as_str(),
            "Signal should contain the changed collection path"
        );

        Ok(())
    }

    #[tokio::test]
    async fn delete_collection() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Create some items in the collection
        let secret1 = oo7::Secret::text("password1");
        let dbus_secret1 = dbus::api::DBusSecret::new(Arc::clone(&setup.session), secret1);

        setup.collections[0]
            .create_item("Item 1", &[("app", "test")], &dbus_secret1, false, None)
            .await?;

        let secret2 = oo7::Secret::text("password2");
        let dbus_secret2 = dbus::api::DBusSecret::new(Arc::clone(&setup.session), secret2);

        setup.collections[0]
            .create_item("Item 2", &[("app", "test")], &dbus_secret2, false, None)
            .await?;

        // Verify items were created
        let items = setup.collections[0].items().await?;
        assert_eq!(items.len(), 2, "Should have 2 items before deletion");

        // Get collection path for later verification
        let collection_path = setup.collections[0].inner().path().to_owned();

        // Verify collection exists in service
        let collections_before = setup.service_api.collections().await?;
        let initial_count = collections_before.len();

        // Delete the collection
        setup.collections[0].delete(None).await?;

        // Give the system a moment to process the deletion
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Verify collection is no longer in service's collection list
        let collections_after = setup.service_api.collections().await?;
        assert_eq!(
            collections_after.len(),
            initial_count - 1,
            "Service should have one less collection after deletion"
        );

        // Verify the specific collection is not in the list
        let collection_paths: Vec<_> = collections_after
            .iter()
            .map(|c| c.inner().path().as_str())
            .collect();
        assert!(
            !collection_paths.contains(&collection_path.as_str()),
            "Deleted collection should not be in service collections list"
        );

        Ok(())
    }

    #[tokio::test]
    async fn collection_deleted_signal() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Subscribe to CollectionDeleted signal
        let signal_stream = setup.service_api.receive_collection_deleted().await?;
        tokio::pin!(signal_stream);

        let collection_path = setup.collections[0].inner().path().to_owned();

        // Delete the collection
        setup.collections[0].delete(None).await?;

        // Wait for signal with timeout
        let signal_result =
            tokio::time::timeout(tokio::time::Duration::from_secs(1), signal_stream.next()).await;

        assert!(
            signal_result.is_ok(),
            "Should receive CollectionDeleted signal"
        );
        let signal = signal_result.unwrap();
        assert!(signal.is_some(), "Signal should not be None");

        let signal_collection = signal.unwrap();
        assert_eq!(
            signal_collection.as_str(),
            collection_path.as_str(),
            "Signal should contain the deleted collection path"
        );

        Ok(())
    }

    #[tokio::test]
    async fn create_item_in_locked_collection() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;
        let default_collection = setup.default_collection().await?;

        let collection = setup
            .server
            .collection_from_path(default_collection.inner().path())
            .await
            .expect("Collection should exist");
        collection
            .set_locked(true, setup.keyring_secret.clone())
            .await?;

        assert!(
            default_collection.is_locked().await?,
            "Collection should be locked"
        );

        let secret = oo7::Secret::text("test-password");
        let dbus_secret = dbus::api::DBusSecret::new(Arc::clone(&setup.session), secret.clone());

        let _item = default_collection
            .create_item(
                "Test Item",
                &[("app", "test"), ("type", "password")],
                &dbus_secret,
                false,
                None,
            )
            .await?;

        assert!(
            !default_collection.is_locked().await?,
            "Collection should be unlocked after prompt"
        );

        // Give the background task time to create the item
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let items = default_collection.items().await?;
        assert_eq!(items.len(), 1, "Collection should have one item");

        // Use the item from the collection instead of the returned item,
        // since item creation happens asynchronously after prompt completion
        let item = &items[0];

        let label = item.label().await?;
        assert_eq!(label, "Test Item", "Item should have correct label");

        let attributes = item.attributes().await?;
        assert_eq!(attributes.get("app"), Some(&"test".to_string()));
        assert_eq!(attributes.get("type"), Some(&"password".to_string()));

        let retrieved_secret = item.secret(&setup.session).await?;
        assert_eq!(retrieved_secret.value(), secret.as_bytes());

        Ok(())
    }

    #[tokio::test]
    async fn delete_locked_collection_with_prompt() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;
        let default_collection = setup.default_collection().await?;

        let collection = setup
            .server
            .collection_from_path(default_collection.inner().path())
            .await
            .expect("Collection should exist");
        collection
            .set_locked(true, setup.keyring_secret.clone())
            .await?;

        assert!(
            default_collection.is_locked().await?,
            "Collection should be locked"
        );

        let collection_path = default_collection.inner().path().to_owned();

        // Get initial collection count
        let collections_before = setup.service_api.collections().await?;
        let initial_count = collections_before.len();

        // Delete the locked collection
        default_collection.delete(None).await?;

        // Give the system a moment to process the deletion
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Verify collection was deleted
        let collections_after = setup.service_api.collections().await?;
        assert_eq!(
            collections_after.len(),
            initial_count - 1,
            "Collection should be deleted after prompt"
        );

        // Verify the specific collection is not in the list
        let collection_paths: Vec<_> = collections_after
            .iter()
            .map(|c| c.inner().path().as_str())
            .collect();
        assert!(
            !collection_paths.contains(&collection_path.as_str()),
            "Deleted collection should not be in service collections list"
        );

        Ok(())
    }

    #[tokio::test]
    async fn unlock_retry() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;
        let default_collection = setup.default_collection().await?;

        let secret = oo7::Secret::text("test-secret-data");
        let dbus_secret = dbus::api::DBusSecret::new(Arc::clone(&setup.session), secret);
        default_collection
            .create_item("Test Item", &[("app", "test")], &dbus_secret, false, None)
            .await?;

        let collection = setup
            .server
            .collection_from_path(default_collection.inner().path())
            .await
            .expect("Collection should exist");
        collection
            .set_locked(true, setup.keyring_secret.clone())
            .await?;

        assert!(
            default_collection.is_locked().await?,
            "Collection should be locked"
        );

        setup
            .mock_prompter
            .set_password_queue(vec![
                oo7::Secret::from("wrong-password"),
                oo7::Secret::from("wrong-password2"),
                oo7::Secret::from("test-password-long-enough"),
            ])
            .await;

        let unlocked = setup
            .service_api
            .unlock(&[default_collection.inner().path()], None)
            .await?;

        assert_eq!(unlocked.len(), 1, "Should have unlocked 1 collection");
        assert_eq!(
            unlocked[0].as_str(),
            default_collection.inner().path().as_str(),
            "Should return the collection path"
        );
        assert!(
            !default_collection.is_locked().await?,
            "Collection should be unlocked after retry with correct password"
        );

        Ok(())
    }

    #[tokio::test]
    async fn locked_collection_operations() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Verify collection is unlocked initially
        assert!(
            !setup.collections[0].is_locked().await?,
            "Collection should start unlocked"
        );

        // Lock the collection
        let collection = setup
            .server
            .collection_from_path(setup.collections[0].inner().path())
            .await
            .expect("Collection should exist");
        collection
            .set_locked(true, setup.keyring_secret.clone())
            .await?;

        // Verify collection is now locked
        assert!(
            setup.collections[0].is_locked().await?,
            "Collection should be locked"
        );

        // Test 1: set_label should fail with IsLocked
        let result = setup.collections[0].set_label("New Label").await;
        assert!(
            matches!(result, Err(oo7::dbus::Error::ZBus(zbus::Error::FDO(_)))),
            "set_label should fail with IsLocked error, got: {:?}",
            result
        );

        // Verify read-only operations still work on locked collections
        assert!(
            setup.collections[0].label().await.is_ok(),
            "Should be able to read label of locked collection"
        );

        let items = setup.collections[0].items().await?;
        assert!(
            items.is_empty(),
            "Should be able to read items (empty) from locked collection"
        );

        Ok(())
    }
}
