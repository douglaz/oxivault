//! Error types for IronVault core

#[cfg(not(feature = "std"))]
use alloc::string::String;

/// Core error type for IronVault operations
#[derive(Debug, Clone)]
pub enum Error {
    /// Invalid mnemonic phrase
    InvalidMnemonic,
    /// Invalid derivation path
    InvalidDerivationPath(String),
    /// Invalid network
    InvalidNetwork,
    /// Secp256k1 error
    Secp256k1Error,
    /// Bitcoin encoding error
    BitcoinError(String),
    /// PSBT error
    PsbtError(String),
    /// Insufficient entropy
    InsufficientEntropy,
    /// Invalid key
    InvalidKey,
    /// Invalid entropy input
    InvalidEntropy(String),
    /// Invalid parameter
    InvalidParameter(String),
    /// Checksum error
    ChecksumError,
    /// Taproot error
    Taproot(String),
    /// Backup error
    BackupError(String),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Error::InvalidMnemonic => write!(f, "Invalid mnemonic phrase"),
            Error::InvalidDerivationPath(path) => write!(f, "Invalid derivation path: {}", path),
            Error::InvalidNetwork => write!(f, "Invalid network"),
            Error::Secp256k1Error => write!(f, "Secp256k1 error"),
            Error::BitcoinError(msg) => write!(f, "Bitcoin error: {}", msg),
            Error::PsbtError(msg) => write!(f, "PSBT error: {}", msg),
            Error::InsufficientEntropy => write!(f, "Insufficient entropy"),
            Error::InvalidKey => write!(f, "Invalid key"),
            Error::InvalidEntropy(msg) => write!(f, "Invalid entropy: {}", msg),
            Error::InvalidParameter(msg) => write!(f, "Invalid parameter: {}", msg),
            Error::ChecksumError => write!(f, "Checksum verification failed"),
            Error::Taproot(msg) => write!(f, "Taproot error: {}", msg),
            Error::BackupError(msg) => write!(f, "Backup error: {}", msg),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Result type for IronVault operations
pub type Result<T> = core::result::Result<T, Error>;