//! Wallet functionality combining BIP-39, BIP-32, and address generation

use crate::bip32::{DerivationPaths, HdWallet};
use crate::bip39::MnemonicManager;
use crate::{Error, Result};
use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bitcoin::{Address, Network, PublicKey, ScriptBuf};
use secp256k1::Secp256k1;

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

/// Script type for address generation
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ScriptType {
    /// Legacy P2PKH (1...)
    Legacy,
    /// Nested Segwit P2SH-P2WPKH (3...)
    NestedSegwit,
    /// Native Segwit P2WPKH (bc1q...)
    NativeSegwit,
    /// Taproot P2TR (bc1p...)
    Taproot,
}

impl ScriptType {
    /// Get the BIP number for this script type
    pub fn bip_number(&self) -> u32 {
        match self {
            ScriptType::Legacy => 44,
            ScriptType::NestedSegwit => 49,
            ScriptType::NativeSegwit => 84,
            ScriptType::Taproot => 86,
        }
    }
}

/// Complete wallet with mnemonic and HD key derivation (requires std)
#[cfg(feature = "std")]
pub struct Wallet {
    mnemonic: MnemonicManager,
    hd_wallet: HdWallet,
    network: Network,
}

#[cfg(feature = "std")]
impl Wallet {
    /// Create a new wallet from mnemonic phrase
    pub fn from_mnemonic(phrase: &str, passphrase: &str, network: Network) -> Result<Self> {
        let mnemonic = MnemonicManager::from_phrase(phrase)?;
        let seed = mnemonic.to_seed_bytes(passphrase);
        let hd_wallet = HdWallet::from_seed(&seed, network)?;

        Ok(Self {
            mnemonic,
            hd_wallet,
            network,
        })
    }

    /// Create a new wallet from entropy
    pub fn from_entropy(entropy: &[u8], passphrase: &str, network: Network) -> Result<Self> {
        let mnemonic = MnemonicManager::from_entropy(entropy)?;
        let seed = mnemonic.to_seed_bytes(passphrase);
        let hd_wallet = HdWallet::from_seed(&seed, network)?;

        Ok(Self {
            mnemonic,
            hd_wallet,
            network,
        })
    }

    /// Get the mnemonic phrase
    pub fn mnemonic_phrase(&self) -> String {
        self.mnemonic.phrase()
    }

    /// Get an address for a specific script type and derivation
    pub fn get_address(
        &self,
        script_type: ScriptType,
        account: u32,
        change: u32,
        index: u32,
    ) -> Result<Address> {
        let secp = Secp256k1::new();

        let coin = match self.network {
            Network::Bitcoin => 0,
            Network::Testnet | Network::Signet | Network::Regtest => 1,
            _ => return Err(Error::InvalidNetwork),
        };

        let path = match script_type {
            ScriptType::Legacy => DerivationPaths::bip44(coin, account, change, index)?,
            ScriptType::NestedSegwit => DerivationPaths::bip49(coin, account, change, index)?,
            ScriptType::NativeSegwit => DerivationPaths::bip84(coin, account, change, index)?,
            ScriptType::Taproot => DerivationPaths::bip86(coin, account, change, index)?,
        };

        let private_key = self.hd_wallet.derive(&path)?;
        let public_key = PublicKey::from_private_key(&secp, &private_key.to_priv());
        let compressed_pk =
            bitcoin::key::CompressedPublicKey::from_private_key(&secp, &private_key.to_priv())
                .unwrap();

        let address = match script_type {
            ScriptType::Legacy => Address::p2pkh(public_key, self.network),
            ScriptType::NestedSegwit => {
                let wpkh = compressed_pk.wpubkey_hash();
                let script = ScriptBuf::new_p2wpkh(&wpkh);
                Address::p2sh(&script, self.network).unwrap()
            }
            ScriptType::NativeSegwit => Address::p2wpkh(&compressed_pk, self.network),
            ScriptType::Taproot => {
                let keypair = private_key.to_priv().inner.keypair(&secp);
                let (internal_key, _parity) = keypair.x_only_public_key();
                Address::p2tr(&secp, internal_key, None, self.network)
            }
        };

        Ok(address)
    }

    /// Get extended public key for an account
    pub fn get_account_xpub(&self, script_type: ScriptType, account: u32) -> Result<Xpub> {
        self.hd_wallet
            .account_xpub(script_type.bip_number(), account)
    }

    /// Get master fingerprint
    pub fn master_fingerprint(&self) -> bitcoin::bip32::Fingerprint {
        self.hd_wallet.master_xpub().fingerprint()
    }

    /// Derive a private key at a specific path
    pub fn derive_private_key(&self, path: &DerivationPath) -> Result<Xpriv> {
        self.hd_wallet.derive(path)
    }

    /// Derive a public key at a specific path
    pub fn derive_public_key(&self, path: &DerivationPath) -> Result<Xpub> {
        self.hd_wallet.derive_pub(path)
    }

    /// Get the network
    pub fn network(&self) -> Network {
        self.network
    }
}

/// Multisig wallet coordinator
pub struct MultisigWallet {
    threshold: usize,
    xpubs: Vec<Xpub>,
    #[allow(dead_code)]
    network: Network,
}

impl MultisigWallet {
    /// Create a new multisig wallet
    pub fn new(threshold: usize, xpubs: Vec<Xpub>, network: Network) -> Result<Self> {
        if threshold == 0 || threshold > xpubs.len() {
            return Err(Error::BitcoinError("Invalid multisig threshold".into()));
        }

        if xpubs.len() > 15 {
            return Err(Error::BitcoinError("Too many cosigners (max 15)".into()));
        }

        Ok(Self {
            threshold,
            xpubs,
            network,
        })
    }

    /// Get the multisig configuration as M-of-N
    pub fn config(&self) -> (usize, usize) {
        (self.threshold, self.xpubs.len())
    }

    /// Generate a multisig address with proper script construction
    /// Creates a P2WSH (native segwit) multisig address
    pub fn get_address(&self, change: u32, index: u32) -> Result<Address> {
        use bitcoin::bip32::ChildNumber;
        use bitcoin::key::CompressedPublicKey;
        use bitcoin::opcodes::all::{
            OP_CHECKMULTISIG, OP_PUSHNUM_1, OP_PUSHNUM_10, OP_PUSHNUM_11, OP_PUSHNUM_12,
            OP_PUSHNUM_13, OP_PUSHNUM_14, OP_PUSHNUM_15, OP_PUSHNUM_2, OP_PUSHNUM_3, OP_PUSHNUM_4,
            OP_PUSHNUM_5, OP_PUSHNUM_6, OP_PUSHNUM_7, OP_PUSHNUM_8, OP_PUSHNUM_9,
        };

        // Derive public keys for each cosigner at the given path
        let mut pubkeys = Vec::new();
        let secp = Secp256k1::new();

        for xpub in &self.xpubs {
            // Derive the specific key: m/change/index from the account xpub
            let child_path = [
                ChildNumber::from_normal_idx(change).map_err(|_| {
                    Error::InvalidDerivationPath(format!("Invalid change index: {}", change))
                })?,
                ChildNumber::from_normal_idx(index).map_err(|_| {
                    Error::InvalidDerivationPath(format!("Invalid index: {}", index))
                })?,
            ];

            let derived_xpub = xpub
                .derive_pub(&secp, &child_path)
                .map_err(|e| Error::BitcoinError(format!("Failed to derive pubkey: {:?}", e)))?;

            // Get the compressed public key directly from the xpub
            let compressed = CompressedPublicKey(derived_xpub.public_key);
            pubkeys.push(compressed);
        }

        // Sort pubkeys for deterministic script generation (BIP67)
        pubkeys.sort_by_key(|pk| pk.to_bytes());

        // Build the multisig redeem script
        let mut builder = ScriptBuf::builder();

        // Push M (threshold)
        builder = match self.threshold {
            1 => builder.push_opcode(OP_PUSHNUM_1),
            2 => builder.push_opcode(OP_PUSHNUM_2),
            3 => builder.push_opcode(OP_PUSHNUM_3),
            4 => builder.push_opcode(OP_PUSHNUM_4),
            5 => builder.push_opcode(OP_PUSHNUM_5),
            6 => builder.push_opcode(OP_PUSHNUM_6),
            7 => builder.push_opcode(OP_PUSHNUM_7),
            8 => builder.push_opcode(OP_PUSHNUM_8),
            9 => builder.push_opcode(OP_PUSHNUM_9),
            10 => builder.push_opcode(OP_PUSHNUM_10),
            11 => builder.push_opcode(OP_PUSHNUM_11),
            12 => builder.push_opcode(OP_PUSHNUM_12),
            13 => builder.push_opcode(OP_PUSHNUM_13),
            14 => builder.push_opcode(OP_PUSHNUM_14),
            15 => builder.push_opcode(OP_PUSHNUM_15),
            _ => {
                return Err(Error::BitcoinError(
                    "Invalid threshold (must be 1-15)".into(),
                ))
            }
        };

        // Push all pubkeys
        for pubkey in &pubkeys {
            builder = builder.push_slice(pubkey.to_bytes());
        }

        // Push N (total keys)
        builder = match pubkeys.len() {
            1 => builder.push_opcode(OP_PUSHNUM_1),
            2 => builder.push_opcode(OP_PUSHNUM_2),
            3 => builder.push_opcode(OP_PUSHNUM_3),
            4 => builder.push_opcode(OP_PUSHNUM_4),
            5 => builder.push_opcode(OP_PUSHNUM_5),
            6 => builder.push_opcode(OP_PUSHNUM_6),
            7 => builder.push_opcode(OP_PUSHNUM_7),
            8 => builder.push_opcode(OP_PUSHNUM_8),
            9 => builder.push_opcode(OP_PUSHNUM_9),
            10 => builder.push_opcode(OP_PUSHNUM_10),
            11 => builder.push_opcode(OP_PUSHNUM_11),
            12 => builder.push_opcode(OP_PUSHNUM_12),
            13 => builder.push_opcode(OP_PUSHNUM_13),
            14 => builder.push_opcode(OP_PUSHNUM_14),
            15 => builder.push_opcode(OP_PUSHNUM_15),
            _ => {
                return Err(Error::BitcoinError(
                    "Invalid number of pubkeys (must be 1-15)".into(),
                ))
            }
        };

        // Add OP_CHECKMULTISIG
        builder = builder.push_opcode(OP_CHECKMULTISIG);
        let witness_script = builder.into_script();

        // Create P2WSH address from the witness script
        Ok(Address::p2wsh(&witness_script, self.network))
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_creation() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet = Wallet::from_mnemonic(phrase, "", Network::Bitcoin).unwrap();

        assert_eq!(wallet.mnemonic_phrase(), phrase);
        assert_eq!(wallet.network(), Network::Bitcoin);
    }

    #[test]
    fn test_address_generation() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet = Wallet::from_mnemonic(phrase, "", Network::Bitcoin).unwrap();

        // Test native segwit address generation
        let address = wallet
            .get_address(ScriptType::NativeSegwit, 0, 0, 0)
            .unwrap();
        assert!(address.to_string().starts_with("bc1"));
    }

    #[test]
    fn test_script_types() {
        assert_eq!(ScriptType::Legacy.bip_number(), 44);
        assert_eq!(ScriptType::NestedSegwit.bip_number(), 49);
        assert_eq!(ScriptType::NativeSegwit.bip_number(), 84);
        assert_eq!(ScriptType::Taproot.bip_number(), 86);
    }

    #[test]
    fn test_multisig_wallet() -> Result<()> {
        // Create test xpubs (these are deterministic test vectors)
        let seed1 = [0x01u8; 32];
        let seed2 = [0x02u8; 32];
        let seed3 = [0x03u8; 32];

        let xpriv1 = bitcoin::bip32::Xpriv::new_master(Network::Bitcoin, &seed1).unwrap();
        let xpriv2 = bitcoin::bip32::Xpriv::new_master(Network::Bitcoin, &seed2).unwrap();
        let xpriv3 = bitcoin::bip32::Xpriv::new_master(Network::Bitcoin, &seed3).unwrap();

        let secp = Secp256k1::new();
        let xpub1 = bitcoin::bip32::Xpub::from_priv(&secp, &xpriv1);
        let xpub2 = bitcoin::bip32::Xpub::from_priv(&secp, &xpriv2);
        let xpub3 = bitcoin::bip32::Xpub::from_priv(&secp, &xpriv3);

        // Create a 2-of-3 multisig wallet
        let multisig = MultisigWallet::new(2, vec![xpub1, xpub2, xpub3], Network::Bitcoin)?;

        // Check configuration
        let (m, n) = multisig.config();
        assert_eq!(m, 2);
        assert_eq!(n, 3);

        // Generate an address
        let address = multisig.get_address(0, 0)?;

        // Verify it's a P2WSH address (starts with bc1q for segwit v0)
        assert!(address.to_string().starts_with("bc1"));

        // Verify deterministic generation (same inputs = same address)
        let address2 = multisig.get_address(0, 0)?;
        assert_eq!(address, address2);

        // Different index should give different address
        let address3 = multisig.get_address(0, 1)?;
        assert_ne!(address, address3);

        Ok(())
    }

    #[test]
    fn test_multisig_validation() {
        let seed = [0x01u8; 32];
        let xpriv = bitcoin::bip32::Xpriv::new_master(Network::Bitcoin, &seed).unwrap();
        let secp = Secp256k1::new();
        let xpub = bitcoin::bip32::Xpub::from_priv(&secp, &xpriv);

        // Invalid threshold (0)
        assert!(MultisigWallet::new(0, vec![xpub.clone()], Network::Bitcoin).is_err());

        // Invalid threshold (greater than keys)
        assert!(MultisigWallet::new(2, vec![xpub.clone()], Network::Bitcoin).is_err());

        // Too many cosigners (> 15)
        let many_xpubs = vec![xpub; 16];
        assert!(MultisigWallet::new(8, many_xpubs, Network::Bitcoin).is_err());
    }
}
