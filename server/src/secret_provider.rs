//! Server-side SecretProvider implementation using GNOME prompter.
//!
//! This module provides a `SecretProvider` implementation that creates
//! D-Bus prompts to obtain passwords from the user via the GNOME prompter.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use oo7::{Secret, file::SecretProvider};
use tokio::sync::{Mutex, RwLock, oneshot};
use zbus::zvariant::OwnedObjectPath;

use crate::{
    prompt::{Prompt, PromptAction, PromptRole},
    service::Service,
};

/// A SecretProvider implementation that uses GNOME's prompter system.
///
/// When `create_prompt()` is called, this creates a D-Bus prompt that triggers
/// the GNOME system prompter. The `await_prompt()` method then blocks until
/// the user provides a password or dismisses the prompt.
///
/// The collection can be set lazily after creation to handle the chicken-and-egg
/// problem where the Collection needs a keyring but the keyring needs a SecretProvider
/// that knows about the Collection.
pub struct GnomeSecretProvider {
    service: Service,
    /// Collection for prompt context. Can be set lazily via `set_collection()`.
    collection: RwLock<Option<crate::collection::Collection>>,
    /// Label to use in prompts when collection is not available
    label: String,
    /// Stores pending prompt receivers, keyed by prompt path
    pending_prompts: Arc<Mutex<HashMap<String, oneshot::Receiver<Result<Secret, oo7::file::Error>>>>>,
}

impl std::fmt::Debug for GnomeSecretProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GnomeSecretProvider")
            .field("label", &self.label)
            .finish_non_exhaustive()
    }
}

impl GnomeSecretProvider {
    /// Create a new GnomeSecretProvider with a collection.
    ///
    /// # Arguments
    /// * `service` - The D-Bus service for prompt registration
    /// * `collection` - The collection being unlocked (needed for prompt context)
    pub fn new(service: Service, collection: crate::collection::Collection) -> Self {
        let label = String::new(); // Collection provides the label
        Self {
            service,
            collection: RwLock::new(Some(collection)),
            label,
            pending_prompts: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Create a new GnomeSecretProvider without a collection.
    ///
    /// This is useful when loading keyrings before Collections are created.
    /// Call `set_collection()` later to provide the collection for prompt context.
    ///
    /// # Arguments
    /// * `service` - The D-Bus service for prompt registration
    /// * `label` - The keyring label to use in prompts
    pub fn new_deferred(service: Service, label: &str) -> Self {
        Self {
            service,
            collection: RwLock::new(None),
            label: label.to_string(),
            pending_prompts: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Set the collection for prompt context.
    ///
    /// This should be called after the Collection is created.
    pub async fn set_collection(&self, collection: crate::collection::Collection) {
        *self.collection.write().await = Some(collection);
    }
}

#[async_trait]
impl SecretProvider for GnomeSecretProvider {
    async fn create_prompt(&self, label: &str) -> Result<String, oo7::file::Error> {
        // Create a oneshot channel to receive the secret
        let (tx, rx) = oneshot::channel::<Result<Secret, oo7::file::Error>>();

        // Get the collection if available (for prompt context)
        let collection = self.collection.read().await.clone();

        // Create the prompt
        let prompt = Prompt::new(
            self.service.clone(),
            PromptRole::Unlock,
            label.to_string(),
            collection,
        )
        .await;

        let prompt_path = OwnedObjectPath::from(prompt.path().clone());
        let prompt_path_str = prompt_path.to_string();

        // Create an action that sends the secret through the channel
        let action = PromptAction::new(move |secret: Secret| async move {
            // Send the secret through the channel (ignore send errors)
            let _ = tx.send(Ok(secret));
            // Return an empty object path since the actual unlock/create happens asynchronously
            // For CreateItem prompts, the item path will be available after the background task completes
            Ok(zbus::zvariant::ObjectPath::from_static_str_unchecked("/")
                .to_owned()
                .into())
        });

        prompt.set_action(action).await;

        // Register the prompt with the service
        self.service
            .register_prompt(prompt_path.clone(), prompt.clone())
            .await;

        // Expose the prompt on D-Bus
        self.service
            .object_server()
            .at(&prompt_path, prompt)
            .await
            .map_err(|e| oo7::file::Error::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to expose prompt on D-Bus: {e}"),
            )))?;

        // Store the receiver for later retrieval
        self.pending_prompts
            .lock()
            .await
            .insert(prompt_path_str.clone(), rx);

        tracing::debug!("Created unlock prompt at `{}` for keyring `{}`", prompt_path, label);

        Ok(prompt_path_str)
    }

    async fn await_prompt(&self, prompt_path: &str) -> Result<Secret, oo7::file::Error> {
        // Retrieve the receiver for this prompt
        let rx = self
            .pending_prompts
            .lock()
            .await
            .remove(prompt_path)
            .ok_or_else(|| oo7::file::Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("No pending prompt found for path: {}", prompt_path),
            )))?;

        // Wait for the prompt to complete
        rx.await.map_err(|_| oo7::file::Error::PromptDismissed)?
    }

    async fn secret_rejected(&self, label: &str, _error: &oo7::file::Error) -> Result<Secret, oo7::file::Error> {
        // When a secret is rejected, we create another prompt and wait for it
        // The GNOME prompter will show "incorrect password" warning
        tracing::debug!("Secret rejected for keyring `{}`, prompting again", label);
        let path = self.create_prompt(label).await?;
        self.await_prompt(&path).await
    }
}
