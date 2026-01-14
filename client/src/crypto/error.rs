/// Cryptography specific errors.
#[derive(Debug)]
pub enum Error {
    #[cfg(feature = "openssl_crypto")]
    Openssl(openssl::error::ErrorStack),
    #[cfg(feature = "native_crypto")]
    PadError(cipher::inout::PadError),
    #[cfg(feature = "native_crypto")]
    UnpadError(cipher::block_padding::UnpadError),
    Gpg(gpgme::Error),
    GpgIo(std::io::Error),
    /// No decryption key is available.
    NoKey,
}

#[cfg(feature = "openssl_crypto")]
impl From<openssl::error::ErrorStack> for Error {
    fn from(value: openssl::error::ErrorStack) -> Self {
        Self::Openssl(value)
    }
}

#[cfg(feature = "native_crypto")]
impl From<cipher::block_padding::UnpadError> for Error {
    fn from(value: cipher::block_padding::UnpadError) -> Self {
        Self::UnpadError(value)
    }
}

#[cfg(feature = "native_crypto")]
impl From<cipher::inout::PadError> for Error {
    fn from(value: cipher::inout::PadError) -> Self {
        Self::PadError(value)
    }
}

impl From<gpgme::Error> for Error {
    fn from(value: gpgme::Error) -> Self {
        Self::Gpg(value)
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::GpgIo(value)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            #[cfg(feature = "openssl_crypto")]
            Self::Openssl(e) => Some(e),
            #[cfg(feature = "native_crypto")]
            Self::UnpadError(_) | Self::PadError(_) => None,
            Self::Gpg(e) => Some(e),
            Self::GpgIo(e) => Some(e),
            Self::NoKey => None,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(feature = "openssl_crypto")]
            Self::Openssl(e) => f.write_fmt(format_args!("Openssl error: {e}")),
            #[cfg(feature = "native_crypto")]
            Self::UnpadError(e) => f.write_fmt(format_args!("Wrong padding error: {e}")),
            #[cfg(feature = "native_crypto")]
            Self::PadError(e) => f.write_fmt(format_args!("Wrong padding error: {e}")),
            Self::Gpg(e) => f.write_fmt(format_args!("GPG error: {e}")),
            Self::GpgIo(e) => f.write_fmt(format_args!("GPG I/O error: {e}")),
            Self::NoKey => f.write_str("No decryption key available"),
        }
    }
}
