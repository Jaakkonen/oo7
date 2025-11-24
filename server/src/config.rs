use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Configuration for the oo7-daemon
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct Config {
    /// Configuration for the default Login keyring
    pub login_keyring: LoginKeyringConfig,

    /// Disable support for v1 (GNOME Keyring) password-based keyrings
    ///
    /// When enabled, the daemon will only support GPG-encrypted keyrings
    /// and will not load or create v1 GNOME password-based keyrings.
    ///
    /// Use the `oo7-cli migrate` command to convert existing v1 keyrings
    /// to GPG-encrypted format before enabling this option.
    pub disable_v1_keyrings: bool,
}

/// Configuration for the Login keyring
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct LoginKeyringConfig {
    /// Enable GPG encryption for the Login keyring
    ///
    /// When enabled, the Login keyring will be encrypted with the specified
    /// GPG key instead of a password. This allows hardware tokens (like Yubikey)
    /// to be used for authentication.
    pub use_gpg: bool,

    /// GPG key ID to use for encrypting the Login keyring
    ///
    /// This should be the fingerprint or key ID of a GPG key.
    /// The key must be available in your GPG keyring.
    ///
    /// Example: "0x1234567890ABCDEF" or "your-email@example.com"
    pub gpg_key_id: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            login_keyring: LoginKeyringConfig::default(),
            disable_v1_keyrings: false,
        }
    }
}

impl Default for LoginKeyringConfig {
    fn default() -> Self {
        Self {
            use_gpg: false,
            gpg_key_id: None,
        }
    }
}

impl Config {
    /// Load configuration from a file
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path.as_ref())
            .map_err(|e| ConfigError::Io(e))?;

        toml::from_str(&content)
            .map_err(|e| ConfigError::Parse(e))
    }

    /// Try to load configuration from standard location
    ///
    /// Looks for config at $XDG_CONFIG_HOME/oo7-daemon/config.toml
    /// or $HOME/.config/oo7-daemon/config.toml
    ///
    /// If no config file is found, returns the default configuration.
    pub fn load_from_standard_locations() -> Self {
        // Get user config path
        let config_path = if let Ok(xdg_config) = std::env::var("XDG_CONFIG_HOME") {
            PathBuf::from(xdg_config).join("oo7-daemon/config.toml")
        } else if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home).join(".config/oo7-daemon/config.toml")
        } else {
            tracing::debug!("No config directory found, using defaults");
            return Self::default();
        };

        // Try to load config
        match Self::load(&config_path) {
            Ok(config) => {
                tracing::info!("Loaded configuration from {}", config_path.display());
                config
            }
            Err(_) => {
                tracing::debug!("No configuration file found at {}, using defaults", config_path.display());
                Self::default()
            }
        }
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.login_keyring.use_gpg && self.login_keyring.gpg_key_id.is_none() {
            return Err(ConfigError::Validation(
                "GPG encryption enabled but no GPG key ID specified".to_string()
            ));
        }

        Ok(())
    }
}

/// Configuration errors
#[derive(Debug)]
pub enum ConfigError {
    /// I/O error reading config file
    Io(std::io::Error),
    /// Error parsing TOML
    Parse(toml::de::Error),
    /// Configuration validation error
    Validation(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "I/O error: {}", e),
            ConfigError::Parse(e) => write!(f, "Parse error: {}", e),
            ConfigError::Validation(msg) => write!(f, "Validation error: {}", msg),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConfigError::Io(e) => Some(e),
            ConfigError::Parse(e) => Some(e),
            ConfigError::Validation(_) => None,
        }
    }
}
