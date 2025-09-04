#![cfg_attr(not(feature = "std"), no_std)]

//! IronVault Core - Bitcoin primitives for hardware wallets
//! 
//! This crate provides no_std compatible Bitcoin functionality for
//! embedded hardware wallet implementations.

pub mod bip32;
pub mod bip39;
pub mod psbt;
pub mod psbt_parser;
pub mod wallet;
pub mod errors;
pub mod entropy;
pub mod slip39;
pub mod rng;
pub mod secure;
pub mod timing;
pub mod tamper;
pub mod hal;
pub mod taproot;
pub mod multisig;
pub mod pin;
pub mod miniscript;
pub mod backup;
#[cfg(feature = "serde")]
pub mod hwi;

pub use errors::{Error, Result};

// Re-export commonly used types
pub use bitcoin::{Address, Network, PublicKey, PrivateKey};
pub use secp256k1::Secp256k1;

// Required for no_std builds
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec, string::{String, ToString}, format};

/// Core wallet functionality
pub struct IronVault {
    /// The secp256k1 context for cryptographic operations
    secp: Secp256k1<secp256k1::All>,
    /// Current network (mainnet/testnet)
    network: Network,
}

impl IronVault {
    /// Create a new IronVault instance
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