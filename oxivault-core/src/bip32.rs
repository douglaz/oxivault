//! BIP-32 Hierarchical Deterministic key derivation

use crate::{Error, Result};
use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv, Xpub};
use bitcoin::Network;
use secp256k1::Secp256k1;

#[cfg(not(feature = "std"))]
use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

/// HD wallet key derivation
pub struct HdWallet {
    master_key: Xpriv,
    network: Network,
}

impl HdWallet {
    /// Create HD wallet from seed
    pub fn from_seed(seed: &[u8], network: Network) -> Result<Self> {
        let master_key = Xpriv::new_master(network, seed).map_err(|_| Error::InvalidKey)?;

        Ok(Self {
            master_key,
            network,
        })
    }

    /// Derive a key at the given path
    pub fn derive(&self, path: &DerivationPath) -> Result<Xpriv> {
        let secp = Secp256k1::new();
        self.master_key
            .derive_priv(&secp, path)
            .map_err(|_| Error::InvalidDerivationPath(format!("{:?}", path)))
    }

    /// Derive a public key at the given path
    pub fn derive_pub(&self, path: &DerivationPath) -> Result<Xpub> {
        let secp = Secp256k1::new();
        let priv_key = self.derive(path)?;
        Ok(Xpub::from_priv(&secp, &priv_key))
    }

    /// Get master extended public key
    pub fn master_xpub(&self) -> Xpub {
        let secp = Secp256k1::new();
        Xpub::from_priv(&secp, &self.master_key)
    }

    /// Get account extended public key (m/purpose'/coin'/account')
    pub fn account_xpub(&self, purpose: u32, account: u32) -> Result<Xpub> {
        let coin = match self.network {
            Network::Bitcoin => 0,
            Network::Testnet | Network::Signet | Network::Regtest => 1,
            _ => return Err(Error::InvalidNetwork),
        };

        let path = DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(purpose)
                .map_err(|_| Error::InvalidDerivationPath("purpose".into()))?,
            ChildNumber::from_hardened_idx(coin)
                .map_err(|_| Error::InvalidDerivationPath("coin".into()))?,
            ChildNumber::from_hardened_idx(account)
                .map_err(|_| Error::InvalidDerivationPath("account".into()))?,
        ]);

        self.derive_pub(&path)
    }
}

/// Common derivation paths
pub struct DerivationPaths;

impl DerivationPaths {
    /// BIP-44 Legacy (P2PKH) - m/44'/coin'/account'/change/index
    pub fn bip44(coin: u32, account: u32, change: u32, index: u32) -> Result<DerivationPath> {
        Ok(DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(44)
                .map_err(|_| Error::InvalidDerivationPath("44".into()))?,
            ChildNumber::from_hardened_idx(coin)
                .map_err(|_| Error::InvalidDerivationPath("coin".into()))?,
            ChildNumber::from_hardened_idx(account)
                .map_err(|_| Error::InvalidDerivationPath("account".into()))?,
            ChildNumber::from_normal_idx(change)
                .map_err(|_| Error::InvalidDerivationPath("change".into()))?,
            ChildNumber::from_normal_idx(index)
                .map_err(|_| Error::InvalidDerivationPath("index".into()))?,
        ]))
    }

    /// BIP-49 Nested Segwit (P2SH-P2WPKH) - m/49'/coin'/account'/change/index
    pub fn bip49(coin: u32, account: u32, change: u32, index: u32) -> Result<DerivationPath> {
        Ok(DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(49)
                .map_err(|_| Error::InvalidDerivationPath("49".into()))?,
            ChildNumber::from_hardened_idx(coin)
                .map_err(|_| Error::InvalidDerivationPath("coin".into()))?,
            ChildNumber::from_hardened_idx(account)
                .map_err(|_| Error::InvalidDerivationPath("account".into()))?,
            ChildNumber::from_normal_idx(change)
                .map_err(|_| Error::InvalidDerivationPath("change".into()))?,
            ChildNumber::from_normal_idx(index)
                .map_err(|_| Error::InvalidDerivationPath("index".into()))?,
        ]))
    }

    /// BIP-84 Native Segwit (P2WPKH) - m/84'/coin'/account'/change/index
    pub fn bip84(coin: u32, account: u32, change: u32, index: u32) -> Result<DerivationPath> {
        Ok(DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(84)
                .map_err(|_| Error::InvalidDerivationPath("84".into()))?,
            ChildNumber::from_hardened_idx(coin)
                .map_err(|_| Error::InvalidDerivationPath("coin".into()))?,
            ChildNumber::from_hardened_idx(account)
                .map_err(|_| Error::InvalidDerivationPath("account".into()))?,
            ChildNumber::from_normal_idx(change)
                .map_err(|_| Error::InvalidDerivationPath("change".into()))?,
            ChildNumber::from_normal_idx(index)
                .map_err(|_| Error::InvalidDerivationPath("index".into()))?,
        ]))
    }

    /// BIP-86 Taproot (P2TR) - m/86'/coin'/account'/change/index
    pub fn bip86(coin: u32, account: u32, change: u32, index: u32) -> Result<DerivationPath> {
        Ok(DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(86)
                .map_err(|_| Error::InvalidDerivationPath("86".into()))?,
            ChildNumber::from_hardened_idx(coin)
                .map_err(|_| Error::InvalidDerivationPath("coin".into()))?,
            ChildNumber::from_hardened_idx(account)
                .map_err(|_| Error::InvalidDerivationPath("account".into()))?,
            ChildNumber::from_normal_idx(change)
                .map_err(|_| Error::InvalidDerivationPath("change".into()))?,
            ChildNumber::from_normal_idx(index)
                .map_err(|_| Error::InvalidDerivationPath("index".into()))?,
        ]))
    }

    /// Parse derivation path from string (e.g., "m/84'/0'/0'/0/0")
    pub fn from_str(path: &str) -> Result<DerivationPath> {
        path.parse()
            .map_err(|_| Error::InvalidDerivationPath(path.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derivation_paths() -> Result<()> {
        // Test BIP-84 path creation
        let path = DerivationPaths::bip84(0, 0, 0, 0)?;
        // Bitcoin crate's DerivationPath doesn't include "m/" in its Display
        assert_eq!(path.to_string(), "84'/0'/0'/0/0");

        // Test path parsing - it accepts "m/" prefix but doesn't display it
        let parsed = DerivationPaths::from_str("m/84'/0'/0'/0/0")?;
        assert_eq!(parsed.to_string(), "84'/0'/0'/0/0");

        // Test creating other BIP paths
        let bip44 = DerivationPaths::bip44(0, 0, 0, 0)?;
        assert_eq!(bip44.to_string(), "44'/0'/0'/0/0");

        let bip49 = DerivationPaths::bip49(0, 0, 0, 0)?;
        assert_eq!(bip49.to_string(), "49'/0'/0'/0/0");

        let bip86 = DerivationPaths::bip86(0, 0, 0, 0)?;
        assert_eq!(bip86.to_string(), "86'/0'/0'/0/0");

        Ok(())
    }

    #[test]
    fn test_hd_wallet() {
        let seed = [0u8; 64];
        let wallet = HdWallet::from_seed(&seed, Network::Bitcoin).unwrap();

        // Test master xpub generation
        let xpub = wallet.master_xpub();
        assert!(!xpub.to_string().is_empty());

        // Test account xpub for BIP-84
        let account_xpub = wallet.account_xpub(84, 0).unwrap();
        assert!(!account_xpub.to_string().is_empty());
    }
}
