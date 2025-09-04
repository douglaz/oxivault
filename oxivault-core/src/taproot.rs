//! Taproot (BIP-340/341/342) Implementation
//! 
//! Provides comprehensive Taproot support including:
//! - Schnorr signatures (BIP-340)
//! - Taproot key path spending
//! - Tapscript and script path spending
//! - MuSig2 preparation

use bitcoin::{
    Address, Network, XOnlyPublicKey,
    ScriptBuf,
    secp256k1::{Secp256k1, Message, Keypair, SecretKey},
    taproot::{TaprootBuilder, TaprootSpendInfo, LeafVersion, TapLeafHash},
    sighash::{SighashCache, TapSighashType, Prevouts},
    Transaction, TxOut,
};
use crate::{Result, Error};

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec, string::{String, ToString}, format};

/// Taproot key manager for BIP-341 operations
pub struct TaprootKey {
    /// Internal keypair
    keypair: Keypair,
    /// Network
    network: Network,
    /// Secp256k1 context
    secp: Secp256k1<secp256k1::All>,
}

impl TaprootKey {
    /// Create new Taproot key from secret key
    pub fn new(secret_key: SecretKey, network: Network) -> Self {
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &secret_key);
        
        Self {
            keypair,
            network,
            secp,
        }
    }

    /// Get the internal public key (before tweaking)
    pub fn internal_key(&self) -> XOnlyPublicKey {
        let (xonly, _) = self.keypair.x_only_public_key();
        xonly
    }

    /// Create a simple key-path-only Taproot address
    pub fn simple_address(&self) -> Address {
        Address::p2tr(&self.secp, self.internal_key(), None, self.network)
    }

    /// Create a Taproot address with a script tree
    pub fn address_with_scripts(&self, scripts: Vec<ScriptBuf>) -> Result<(Address, TaprootSpendInfo)> {
        if scripts.is_empty() {
            return Err(Error::Taproot("No scripts provided".into()));
        }

        let internal_key = self.internal_key();
        
        // Build Taproot tree
        let mut builder = TaprootBuilder::new();
        
        // Add all scripts as leaves at the same depth (simple for now)
        for script in scripts {
            builder = builder.add_leaf(0, script)
                .map_err(|e| Error::Taproot(format!("Failed to add leaf: {:?}", e)))?;
        }

        let spend_info = builder.finalize(&self.secp, internal_key)
            .map_err(|e| Error::Taproot(format!("Failed to finalize taproot: {:?}", e)))?;
        
        let address = Address::p2tr(&self.secp, internal_key, spend_info.merkle_root(), self.network);
        
        Ok((address, spend_info))
    }

    /// Sign a Taproot key-path spend
    pub fn sign_keypath(
        &self,
        tx: &Transaction,
        input_index: usize,
        prevouts: &[TxOut],
        sighash_type: Option<TapSighashType>,
    ) -> Result<bitcoin::taproot::Signature> {
        let sighash_type = sighash_type.unwrap_or(TapSighashType::Default);
        
        // Create sighash cache
        let mut cache = SighashCache::new(tx);
        let prevouts = Prevouts::All(prevouts);
        
        // Calculate sighash
        let sighash = cache
            .taproot_key_spend_signature_hash(input_index, &prevouts, sighash_type)
            .map_err(|e| Error::Taproot(format!("Failed to calculate sighash: {:?}", e)))?;
        
        let msg = Message::from_digest_slice(&sighash[..])
            .map_err(|e| Error::Taproot(format!("Invalid message: {:?}", e)))?;
        
        // Create Schnorr signature
        let sig = self.secp.sign_schnorr_no_aux_rand(&msg, &self.keypair);
        
        Ok(bitcoin::taproot::Signature {
            signature: sig,
            sighash_type,
        })
    }

    /// Sign a Taproot script-path spend
    pub fn sign_scriptpath(
        &self,
        tx: &Transaction,
        input_index: usize,
        prevouts: &[TxOut],
        leaf_hash: TapLeafHash,
        sighash_type: Option<TapSighashType>,
    ) -> Result<bitcoin::taproot::Signature> {
        let sighash_type = sighash_type.unwrap_or(TapSighashType::Default);
        
        // Create sighash cache
        let mut cache = SighashCache::new(tx);
        let prevouts = Prevouts::All(prevouts);
        
        // Calculate script path sighash
        let sighash = cache
            .taproot_script_spend_signature_hash(input_index, &prevouts, leaf_hash, sighash_type)
            .map_err(|e| Error::Taproot(format!("Failed to calculate script sighash: {:?}", e)))?;
        
        let msg = Message::from_digest_slice(&sighash[..])
            .map_err(|e| Error::Taproot(format!("Invalid message: {:?}", e)))?;
        
        // Create Schnorr signature
        let sig = self.secp.sign_schnorr_no_aux_rand(&msg, &self.keypair);
        
        Ok(bitcoin::taproot::Signature {
            signature: sig,
            sighash_type,
        })
    }
}

/// Taproot descriptor for complex scripts
#[derive(Debug, Clone)]
pub struct TaprootDescriptor {
    /// Internal key
    internal_key: XOnlyPublicKey,
    /// Script leaves
    leaves: Vec<TapLeaf>,
    /// Taproot spend info
    spend_info: Option<TaprootSpendInfo>,
}

/// A leaf in the Taproot tree
#[derive(Debug, Clone)]
pub struct TapLeaf {
    /// Depth in the tree (0 = top)
    depth: u8,
    /// The script
    script: ScriptBuf,
    /// Leaf version
    version: LeafVersion,
}

impl TaprootDescriptor {
    /// Create a new Taproot descriptor
    pub fn new(internal_key: XOnlyPublicKey) -> Self {
        Self {
            internal_key,
            leaves: Vec::new(),
            spend_info: None,
        }
    }

    /// Add a script leaf
    pub fn add_leaf(&mut self, depth: u8, script: ScriptBuf) -> &mut Self {
        self.leaves.push(TapLeaf {
            depth,
            script,
            version: LeafVersion::TapScript,
        });
        self
    }

    /// Build the Taproot tree and get the address
    pub fn build(&mut self, secp: &Secp256k1<secp256k1::All>, network: Network) -> Result<Address> {
        if self.leaves.is_empty() {
            // Key-path only
            return Ok(Address::p2tr(secp, self.internal_key, None, network));
        }

        let mut builder = TaprootBuilder::new();
        
        for leaf in &self.leaves {
            builder = builder.add_leaf(leaf.depth, leaf.script.clone())
                .map_err(|e| Error::Taproot(format!("Failed to add leaf: {:?}", e)))?;
        }

        let spend_info = builder.finalize(secp, self.internal_key)
            .map_err(|e| Error::Taproot(format!("Failed to finalize: {:?}", e)))?;
        
        let address = Address::p2tr(secp, self.internal_key, spend_info.merkle_root(), network);
        self.spend_info = Some(spend_info);
        
        Ok(address)
    }

    /// Get the spend info
    pub fn spend_info(&self) -> Option<&TaprootSpendInfo> {
        self.spend_info.as_ref()
    }
}

/// MuSig2 coordinator for multisig Taproot
pub struct MuSig2Coordinator {
    /// Participant public keys
    pubkeys: Vec<XOnlyPublicKey>,
    /// Aggregated public key
    aggregate_pubkey: Option<XOnlyPublicKey>,
    /// Partial signatures
    partial_sigs: Vec<Option<[u8; 64]>>,
}

impl MuSig2Coordinator {
    /// Create new MuSig2 coordinator
    pub fn new(pubkeys: Vec<XOnlyPublicKey>) -> Self {
        let partial_sigs = vec![None; pubkeys.len()];
        Self {
            pubkeys,
            aggregate_pubkey: None,
            partial_sigs,
        }
    }

    /// Aggregate public keys (simplified - real MuSig2 needs more steps)
    pub fn aggregate_pubkeys(&mut self) -> Result<XOnlyPublicKey> {
        if self.pubkeys.is_empty() {
            return Err(Error::Taproot("No pubkeys to aggregate".into()));
        }

        // This is a simplified aggregation - real MuSig2 requires:
        // 1. Key sorting
        // 2. Coefficient calculation
        // 3. Point multiplication
        // For now, just return the first key as placeholder
        let aggregate = self.pubkeys[0];
        self.aggregate_pubkey = Some(aggregate);
        Ok(aggregate)
    }

    /// Add a partial signature
    pub fn add_partial_signature(&mut self, index: usize, sig: [u8; 64]) -> Result<()> {
        if index >= self.partial_sigs.len() {
            return Err(Error::Taproot("Invalid signature index".into()));
        }
        self.partial_sigs[index] = Some(sig);
        Ok(())
    }

    /// Check if we have all signatures
    pub fn is_complete(&self) -> bool {
        self.partial_sigs.iter().all(|s| s.is_some())
    }

    /// Aggregate signatures (simplified)
    pub fn aggregate_signatures(&self) -> Result<[u8; 64]> {
        if !self.is_complete() {
            return Err(Error::Taproot("Not all signatures collected".into()));
        }

        // Simplified - real MuSig2 needs proper aggregation
        // For now, return the first signature
        Ok(self.partial_sigs[0].unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::PrivateKey;

    #[test]
    fn test_taproot_simple_address() {
        let secret_key = SecretKey::from_slice(&[0x01; 32]).unwrap();
        let taproot_key = TaprootKey::new(secret_key, Network::Bitcoin);
        
        let address = taproot_key.simple_address();
        assert!(address.to_string().starts_with("bc1p"));
    }

    #[test]
    fn test_taproot_with_scripts() {
        let secret_key = SecretKey::from_slice(&[0x02; 32]).unwrap();
        let taproot_key = TaprootKey::new(secret_key, Network::Bitcoin);
        
        // Create some dummy scripts
        let script1 = ScriptBuf::from_bytes(vec![0x51]); // OP_1
        let script2 = ScriptBuf::from_bytes(vec![0x52]); // OP_2
        
        let (address, spend_info) = taproot_key.address_with_scripts(vec![script1, script2]).unwrap();
        
        assert!(address.to_string().starts_with("bc1p"));
        assert!(spend_info.merkle_root().is_some());
    }

    #[test]
    fn test_taproot_descriptor() {
        let secret_key = SecretKey::from_slice(&[0x03; 32]).unwrap();
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &secret_key);
        let (xonly, _) = keypair.x_only_public_key();
        
        let mut descriptor = TaprootDescriptor::new(xonly);
        descriptor.add_leaf(0, ScriptBuf::from_bytes(vec![0x51]));
        
        let address = descriptor.build(&secp, Network::Bitcoin).unwrap();
        assert!(address.to_string().starts_with("bc1p"));
    }

    #[test]
    fn test_musig2_coordinator() {
        let key1 = XOnlyPublicKey::from_slice(&[0x02; 32]).unwrap();
        let key2 = XOnlyPublicKey::from_slice(&[0x03; 32]).unwrap();
        
        let mut coordinator = MuSig2Coordinator::new(vec![key1, key2]);
        let aggregate = coordinator.aggregate_pubkeys().unwrap();
        
        assert_eq!(aggregate, key1); // Simplified implementation returns first key
        
        // Add signatures
        coordinator.add_partial_signature(0, [0x01; 64]).unwrap();
        assert!(!coordinator.is_complete());
        
        coordinator.add_partial_signature(1, [0x02; 64]).unwrap();
        assert!(coordinator.is_complete());
    }
}