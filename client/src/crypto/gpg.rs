//! GPG-based encryption for session keys using Yubikey via gpg-agent.
//!
//! This module provides functions to encrypt/decrypt master symmetric keys
//! using GPG public/private keys. The private key operations are handled
//! by gpg-agent, which can communicate with Yubikey hardware tokens.

use std::io::{Read, Seek};

use gpgme::{Context, Data, Protocol};
use zeroize::Zeroizing;

use super::Error;

/// Encrypts a session key (master key) using a GPG public key.
///
/// This operation does not require gpg-agent or Yubikey interaction,
/// as it only uses the public key for encryption.
///
/// # Arguments
/// * `session_key` - The master symmetric key to encrypt (16 bytes for AES-128)
/// * `gpg_key_id` - GPG key fingerprint or ID to use for encryption
///
/// # Returns
/// The encrypted session key as bytes
pub fn encrypt_session_key(
    session_key: &[u8],
    gpg_key_id: &str,
) -> Result<Vec<u8>, Error> {
    // Initialize GPGME
    gpgme::init();

    // Create a context for cryptographic operations
    let mut ctx = Context::from_protocol(Protocol::OpenPgp)
        .map_err(Error::Gpg)?;

    // Set armor to false (we want binary output)
    ctx.set_armor(false);

    // Get the key by fingerprint or ID
    let key = ctx.get_key(gpg_key_id)
        .map_err(Error::Gpg)?;

    // Prepare input data (the session key)
    let mut input = Data::from_buffer(session_key)
        .map_err(Error::Gpg)?;

    // Prepare output buffer
    let mut output = Data::new()
        .map_err(Error::Gpg)?;

    // Encrypt the session key
    ctx.encrypt(Some(&key), &mut input, &mut output)
        .map_err(Error::Gpg)?;

    // Extract the encrypted data
    output.seek(std::io::SeekFrom::Start(0))
        .map_err(Error::GpgIo)?;

    let mut encrypted = Vec::new();
    Read::read_to_end(&mut output, &mut encrypted)
        .map_err(Error::GpgIo)?;

    Ok(encrypted)
}

/// Decrypts a session key (master key) using a GPG private key via gpg-agent.
///
/// This operation requires gpg-agent and will prompt for Yubikey touch/PIN.
///
/// # Arguments
/// * `encrypted_key` - The GPG-encrypted session key
///
/// # Returns
/// The decrypted session key (zeroized on drop)
pub fn decrypt_session_key(
    encrypted_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    // Initialize GPGME
    gpgme::init();

    // Create a context for cryptographic operations
    let mut ctx = Context::from_protocol(Protocol::OpenPgp)
        .map_err(Error::Gpg)?;

    // Prepare input data (the encrypted session key)
    let mut input = Data::from_buffer(encrypted_key)
        .map_err(Error::Gpg)?;

    // Prepare output buffer
    let mut output = Data::new()
        .map_err(Error::Gpg)?;

    // Decrypt using gpg-agent (this will trigger Yubikey interaction)
    ctx.decrypt(&mut input, &mut output)
        .map_err(Error::Gpg)?;

    // Extract the decrypted data
    output.seek(std::io::SeekFrom::Start(0))
        .map_err(Error::GpgIo)?;

    let mut decrypted = Zeroizing::new(Vec::new());
    Read::read_to_end(&mut output, &mut *decrypted)
        .map_err(Error::GpgIo)?;

    Ok(decrypted)
}

/// Lists available GPG keys.
///
/// # Returns
/// A vector of tuples containing (key_id, user_id, is_on_card)
pub fn list_gpg_keys() -> Result<Vec<(String, String, bool)>, Error> {
    // Initialize GPGME
    gpgme::init();

    // Create a context
    let mut ctx = Context::from_protocol(Protocol::OpenPgp)
        .map_err(Error::Gpg)?;

    // List all secret keys (keys we can use for decryption)
    let mut keys = ctx.find_secret_keys(None::<String>)
        .map_err(Error::Gpg)?;

    let mut result = Vec::new();
    for key in keys.by_ref().filter_map(|k| k.ok()) {
        // Get fingerprint
        let fingerprint = key.fingerprint()
            .ok()
            .unwrap_or("<no fingerprint>")
            .to_string();

        // Get user ID (primary)
        let user_id = key.user_ids()
            .next()
            .and_then(|uid| uid.id().ok())
            .unwrap_or("<no user ID>")
            .to_string();

        // Check if key is on a smartcard
        // A key is on a smartcard if any of its subkeys report card status
        let is_on_card = key.subkeys()
            .any(|subkey| subkey.is_card_key());

        result.push((fingerprint, user_id, is_on_card));
    }

    Ok(result)
}

/// Generates a random session key suitable for use as a master encryption key.
///
/// # Arguments
/// * `size` - Size of the key in bytes (16 for AES-128)
///
/// # Returns
/// A cryptographically random session key
pub fn generate_session_key(size: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    use rand::RngCore;

    let mut key = Zeroizing::new(vec![0u8; size]);
    rand::rng()
        .fill_bytes(&mut *key);

    Ok(key)
}

/// Validates that a GPG key ID exists and is usable for encryption.
///
/// This checks that:
/// - The key exists in the keyring
/// - The key is not expired, revoked, or invalid
/// - The key has encryption capability
///
/// # Arguments
/// * `key_id` - GPG key fingerprint, ID, or email to validate
///
/// # Returns
/// `Ok(true)` if the key is valid and usable, `Ok(false)` if key exists but unusable,
/// `Err` if key not found or GPGME error
pub fn validate_key_id(key_id: &str) -> Result<bool, Error> {
    gpgme::init();

    let mut ctx = Context::from_protocol(Protocol::OpenPgp)
        .map_err(Error::Gpg)?;

    let key = ctx.get_key(key_id)
        .map_err(Error::Gpg)?;

    // Check key validity
    if key.is_expired() || key.is_revoked() || key.is_invalid() {
        return Ok(false);
    }

    // Verify key can be used for encryption
    if !key.can_encrypt() {
        return Ok(false);
    }

    Ok(true)
}

/// Gets the full fingerprint for a GPG key.
///
/// This normalizes various key identifiers (short ID, long ID, email)
/// to the full 40-character fingerprint.
///
/// # Arguments
/// * `key_id` - GPG key identifier (fingerprint, ID, or email)
///
/// # Returns
/// The full 40-character key fingerprint
pub fn get_key_fingerprint(key_id: &str) -> Result<String, Error> {
    gpgme::init();

    let mut ctx = Context::from_protocol(Protocol::OpenPgp)
        .map_err(Error::Gpg)?;

    let key = ctx.get_key(key_id)
        .map_err(Error::Gpg)?;

    key.fingerprint()
        .map(|s| s.to_string())
        .map_err(|_| Error::Gpg(gpgme::Error::NO_PUBKEY))
}
