#![cfg_attr(not(feature = "std"), no_std)]
#![allow(
    clippy::manual_try_fold,
    clippy::if_same_then_else,
    clippy::needless_range_loop,
    clippy::manual_flatten
)]

//! OxiVault Core - Bitcoin primitives for hardware wallets
//!
//! This crate provides no_std compatible Bitcoin functionality for
//! embedded hardware wallet implementations.

pub mod backup;
pub mod bip32;
pub mod bip39;
pub mod entropy;
pub mod errors;
pub mod hal;
#[cfg(feature = "serde")]
pub mod hwi;
pub mod miniscript;
pub mod multisig;
pub mod pin;
pub mod psbt;
pub mod psbt_parser;
pub mod rng;
pub mod secure;
pub mod slip39;
pub mod tamper;
pub mod taproot;
pub mod timing;
pub mod wallet;

pub use errors::{Error, Result};

// Re-export commonly used types
pub use bitcoin::{Address, Network, PrivateKey, PublicKey};
pub use secp256k1::Secp256k1;

// Required for no_std builds
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

/// Core wallet functionality
pub struct OxiVault {
    /// The secp256k1 context for cryptographic operations
    secp: Secp256k1<secp256k1::All>,
    /// Current network (mainnet/testnet)
    network: Network,
}

impl OxiVault {
    /// Create a new OxiVault instance
    pub fn new(network: Network) -> Self {
        Self {
            secp: Secp256k1::new(),
            network,
        }
    }

    /// Get the current network
    pub fn network(&self) -> Network {
        self.network
    }

    /// Get a reference to the secp256k1 context
    pub fn secp(&self) -> &Secp256k1<secp256k1::All> {
        &self.secp
    }
}
