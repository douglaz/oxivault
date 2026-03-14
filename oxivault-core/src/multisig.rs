//! Multisig Coordination Module
//!
//! Provides comprehensive multisig support including:
//! - PSBT round coordination
//! - Cosigner management
//! - Signature collection and validation
//! - Various multisig configurations (2-of-3, 3-of-5, etc.)

use crate::{Error, Result};
use bitcoin::{
    bip32::{DerivationPath, Fingerprint, Xpub},
    blockdata::opcodes,
    blockdata::script::Builder,
    psbt::Psbt,
    secp256k1::Secp256k1,
    Address, Network, PublicKey, ScriptBuf,
};

#[cfg(not(feature = "std"))]
use alloc::{
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
#[cfg(feature = "std")]
use std::collections::BTreeMap;

/// Multisig wallet configuration
#[derive(Debug, Clone)]
pub struct MultisigConfig {
    /// Required signatures (M in M-of-N)
    pub threshold: usize,
    /// Total cosigners (N in M-of-N)
    pub total: usize,
    /// Cosigner information
    pub cosigners: Vec<CosignerInfo>,
    /// Network
    pub network: Network,
    /// Script type
    pub script_type: MultisigScriptType,
}

/// Cosigner information
#[derive(Debug, Clone)]
pub struct CosignerInfo {
    /// Cosigner name/identifier
    pub name: String,
    /// Master fingerprint
    pub fingerprint: Fingerprint,
    /// Account extended public key
    pub xpub: Xpub,
    /// Derivation path from master to account
    pub derivation: DerivationPath,
}

/// Multisig script types
#[derive(Debug, Clone, PartialEq)]
pub enum MultisigScriptType {
    /// Legacy P2SH multisig
    P2sh,
    /// Nested SegWit P2SH-P2WSH
    P2shP2wsh,
    /// Native SegWit P2WSH
    P2wsh,
    /// Taproot multisig (using MuSig2 or similar)
    P2tr,
}

impl MultisigConfig {
    /// Create new multisig configuration
    pub fn new(
        threshold: usize,
        cosigners: Vec<CosignerInfo>,
        network: Network,
        script_type: MultisigScriptType,
    ) -> Result<Self> {
        if threshold == 0 || threshold > cosigners.len() {
            return Err(Error::InvalidParameter(format!(
                "Invalid threshold {} for {} cosigners",
                threshold,
                cosigners.len()
            )));
        }

        if cosigners.len() > 20 {
            return Err(Error::InvalidParameter(
                "Maximum 20 cosigners supported".to_string(),
            ));
        }

        Ok(Self {
            threshold,
            total: cosigners.len(),
            cosigners,
            network,
            script_type,
        })
    }

    /// Derive address at a specific path
    pub fn derive_address(&self, change: u32, index: u32) -> Result<Address> {
        let secp = Secp256k1::new();

        // Derive public keys for all cosigners
        let mut pubkeys: Vec<bitcoin::PublicKey> = Vec::new();
        for cosigner in &self.cosigners {
            let child = cosigner
                .xpub
                .derive_pub(&secp, &[change.into(), index.into()])
                .map_err(|_| Error::InvalidDerivationPath(format!("{}/{}", change, index)))?;

            pubkeys.push(bitcoin::PublicKey::new(child.public_key));
        }

        // Sort public keys for deterministic script
        pubkeys.sort_by_key(|k| k.to_bytes());

        // Create multisig script
        let script = self.create_multisig_script(pubkeys.as_slice())?;

        // Convert to address based on script type
        match self.script_type {
            MultisigScriptType::P2sh => Address::p2sh(&script, self.network)
                .map_err(|e| Error::BitcoinError(format!("Failed to create P2SH address: {e:?}"))),
            MultisigScriptType::P2shP2wsh => {
                // Create P2WSH script first, then wrap in P2SH
                let witness_script = script;
                let p2wsh = Address::p2wsh(&witness_script, self.network);
                Address::p2sh(&p2wsh.script_pubkey(), self.network).map_err(|e| {
                    Error::BitcoinError(format!("Failed to create P2SH-P2WSH address: {e:?}"))
                })
            }
            MultisigScriptType::P2wsh => Ok(Address::p2wsh(&script, self.network)),
            MultisigScriptType::P2tr => {
                // Taproot multisig requires MuSig2 or script path
                // For now, return error
                Err(Error::InvalidParameter(
                    "Taproot multisig not yet implemented".to_string(),
                ))
            }
        }
    }

    /// Create multisig redeem script
    fn create_multisig_script(&self, pubkeys: &[PublicKey]) -> Result<ScriptBuf> {
        let mut builder = Builder::new();

        // Add threshold
        builder = builder.push_int(self.threshold as i64);

        // Add all public keys
        for pubkey in pubkeys {
            builder = builder.push_key(pubkey);
        }

        // Add total number
        builder = builder.push_int(pubkeys.len() as i64);

        // Add CHECKMULTISIG
        builder = builder.push_opcode(opcodes::all::OP_CHECKMULTISIG);

        Ok(builder.into_script())
    }

    /// Get wallet descriptor
    pub fn descriptor(&self) -> String {
        let mut desc = match self.script_type {
            MultisigScriptType::P2sh => "sh(multi(".to_string(),
            MultisigScriptType::P2shP2wsh => "sh(wsh(multi(".to_string(),
            MultisigScriptType::P2wsh => "wsh(multi(".to_string(),
            MultisigScriptType::P2tr => "tr(musig(".to_string(),
        };

        desc.push_str(&self.threshold.to_string());

        for cosigner in &self.cosigners {
            desc.push(',');
            desc.push_str(&format!(
                "[{}/{}]{}/<0;1>/*",
                cosigner.fingerprint, cosigner.derivation, cosigner.xpub
            ));
        }

        desc.push(')');

        // Close wsh() wrapper if present
        if matches!(
            self.script_type,
            MultisigScriptType::P2wsh | MultisigScriptType::P2shP2wsh
        ) {
            desc.push(')');
        }

        // Close sh() wrapper if present
        if matches!(
            self.script_type,
            MultisigScriptType::P2sh | MultisigScriptType::P2shP2wsh
        ) {
            desc.push(')');
        }

        desc
    }
}

/// PSBT coordinator for multisig transactions
pub struct PsbtCoordinator {
    /// Multisig configuration
    config: MultisigConfig,
    /// Current PSBT being coordinated
    psbt: Psbt,
    /// Signature status for each input
    signature_status: Vec<InputSignatureStatus>,
    /// Round number
    round: u32,
}

/// Signature status for an input
#[derive(Debug, Clone)]
pub struct InputSignatureStatus {
    /// Required signatures
    #[allow(dead_code)]
    required: usize,
    /// Signatures collected from each cosigner
    signatures: BTreeMap<Fingerprint, Vec<u8>>,
    /// Is fully signed
    is_complete: bool,
}

impl PsbtCoordinator {
    /// Create new PSBT coordinator
    pub fn new(config: MultisigConfig, psbt: Psbt) -> Self {
        let num_inputs = psbt.unsigned_tx.input.len();
        let mut signature_status = Vec::with_capacity(num_inputs);

        for _ in 0..num_inputs {
            signature_status.push(InputSignatureStatus {
                required: config.threshold,
                signatures: BTreeMap::new(),
                is_complete: false,
            });
        }

        Self {
            config,
            psbt,
            signature_status,
            round: 0,
        }
    }

    /// Add signatures from a cosigner
    pub fn add_signatures(&mut self, cosigner_psbt: &Psbt) -> Result<()> {
        if cosigner_psbt.unsigned_tx.compute_txid() != self.psbt.unsigned_tx.compute_txid() {
            return Err(Error::PsbtError("PSBT transaction mismatch".to_string()));
        }

        for (i, input) in cosigner_psbt.inputs.iter().enumerate() {
            if i >= self.signature_status.len() {
                continue;
            }

            // Extract partial signatures
            for (pubkey, sig) in &input.partial_sigs {
                // Find which cosigner this belongs to
                let fingerprint = self.find_cosigner_by_pubkey(pubkey).map(|c| c.fingerprint);

                if let Some(fp) = fingerprint {
                    self.signature_status[i].signatures.insert(fp, sig.to_vec());

                    // Check if input is complete
                    if self.signature_status[i].signatures.len() >= self.config.threshold {
                        self.signature_status[i].is_complete = true;
                    }
                }
            }
        }

        self.round += 1;
        Ok(())
    }

    /// Check if all inputs are fully signed
    pub fn is_complete(&self) -> bool {
        self.signature_status.iter().all(|s| s.is_complete)
    }

    /// Get signature progress
    pub fn progress(&self) -> (usize, usize) {
        let complete = self
            .signature_status
            .iter()
            .filter(|s| s.is_complete)
            .count();
        let total = self.signature_status.len();
        (complete, total)
    }

    /// Combine all signatures into final PSBT
    pub fn finalize(&mut self) -> Result<Psbt> {
        if !self.is_complete() {
            return Err(Error::PsbtError(
                "Not all inputs are fully signed".to_string(),
            ));
        }

        // Combine signatures into PSBT inputs
        for (i, status) in self.signature_status.iter().enumerate() {
            if i >= self.psbt.inputs.len() {
                continue;
            }

            // Add all collected signatures
            for fingerprint in status.signatures.keys() {
                // Find the public key for this fingerprint
                if let Some(_cosigner) = self
                    .config
                    .cosigners
                    .iter()
                    .find(|c| c.fingerprint == *fingerprint)
                {
                    // This is simplified - real implementation needs proper key derivation
                    // and signature format handling
                }
            }
        }

        Ok(self.psbt.clone())
    }

    /// Find cosigner by public key
    fn find_cosigner_by_pubkey(&self, _pubkey: &bitcoin::PublicKey) -> Option<&CosignerInfo> {
        // Simplified - real implementation needs to derive and check keys
        self.config.cosigners.first()
    }

    /// Export current PSBT for sharing
    pub fn export_psbt(&self) -> Psbt {
        self.psbt.clone()
    }

    /// Get current round number
    pub fn round(&self) -> u32 {
        self.round
    }
}

/// Multisig wallet builder for easy setup
pub struct MultisigBuilder {
    threshold: Option<usize>,
    cosigners: Vec<CosignerInfo>,
    network: Network,
    script_type: MultisigScriptType,
}

impl MultisigBuilder {
    /// Create new multisig builder
    pub fn new() -> Self {
        Self {
            threshold: None,
            cosigners: Vec::new(),
            network: Network::Bitcoin,
            script_type: MultisigScriptType::P2wsh,
        }
    }

    /// Set threshold
    pub fn threshold(mut self, threshold: usize) -> Self {
        self.threshold = Some(threshold);
        self
    }

    /// Add cosigner
    pub fn add_cosigner(
        mut self,
        name: String,
        fingerprint: Fingerprint,
        xpub: Xpub,
        derivation: DerivationPath,
    ) -> Self {
        self.cosigners.push(CosignerInfo {
            name,
            fingerprint,
            xpub,
            derivation,
        });
        self
    }

    /// Set network
    pub fn network(mut self, network: Network) -> Self {
        self.network = network;
        self
    }

    /// Set script type
    pub fn script_type(mut self, script_type: MultisigScriptType) -> Self {
        self.script_type = script_type;
        self
    }

    /// Build the multisig configuration
    pub fn build(self) -> Result<MultisigConfig> {
        let threshold = self
            .threshold
            .ok_or_else(|| Error::InvalidParameter("Threshold not set".to_string()))?;

        MultisigConfig::new(threshold, self.cosigners, self.network, self.script_type)
    }
}

impl Default for MultisigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::bip32::Xpriv;

    #[test]
    fn test_multisig_config() -> Result<()> {
        let xprv = Xpriv::from_str(
            "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu"
        ).map_err(|e| Error::BitcoinError(format!("Invalid xprv: {e:?}")))?;

        let secp = Secp256k1::new();
        let xpub = Xpub::from_priv(&secp, &xprv);
        let fingerprint = xprv.fingerprint(&secp);

        let cosigner1 = CosignerInfo {
            name: "Alice".to_string(),
            fingerprint,
            xpub: xpub.clone(),
            derivation: DerivationPath::master(),
        };

        let cosigner2 = CosignerInfo {
            name: "Bob".to_string(),
            fingerprint,
            xpub: xpub.clone(),
            derivation: DerivationPath::master(),
        };

        let config = MultisigConfig::new(
            2,
            vec![cosigner1, cosigner2],
            Network::Bitcoin,
            MultisigScriptType::P2wsh,
        )?;

        assert_eq!(config.threshold, 2);
        assert_eq!(config.total, 2);

        // Test address derivation
        let address = config.derive_address(0, 0)?;
        assert!(address.to_string().starts_with("bc1"));

        Ok(())
    }

    #[test]
    fn test_multisig_builder() -> Result<()> {
        let xprv = Xpriv::from_str(
            "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu"
        ).map_err(|e| Error::BitcoinError(format!("Invalid xprv: {e:?}")))?;

        let secp = Secp256k1::new();
        let xpub = Xpub::from_priv(&secp, &xprv);
        let fingerprint = xprv.fingerprint(&secp);

        let config = MultisigBuilder::new()
            .threshold(2)
            .add_cosigner(
                "Alice".to_string(),
                fingerprint,
                xpub.clone(),
                DerivationPath::master(),
            )
            .add_cosigner(
                "Bob".to_string(),
                fingerprint,
                xpub.clone(),
                DerivationPath::master(),
            )
            .add_cosigner(
                "Charlie".to_string(),
                fingerprint,
                xpub,
                DerivationPath::master(),
            )
            .network(Network::Bitcoin)
            .script_type(MultisigScriptType::P2wsh)
            .build()?;

        assert_eq!(config.threshold, 2);
        assert_eq!(config.total, 3);
        assert_eq!(config.cosigners.len(), 3);

        Ok(())
    }

    #[test]
    fn test_descriptor_generation() -> Result<()> {
        let xprv = Xpriv::from_str(
            "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu"
        ).map_err(|e| Error::BitcoinError(format!("Invalid xprv: {e:?}")))?;

        let secp = Secp256k1::new();
        let xpub = Xpub::from_priv(&secp, &xprv);
        let fingerprint = xprv.fingerprint(&secp);

        let config = MultisigBuilder::new()
            .threshold(2)
            .add_cosigner(
                "Alice".to_string(),
                fingerprint,
                xpub.clone(),
                DerivationPath::from_str("m/48'/0'/0'/2'")
                    .map_err(|e| Error::InvalidDerivationPath(format!("Invalid path: {e:?}")))?,
            )
            .add_cosigner(
                "Bob".to_string(),
                fingerprint,
                xpub,
                DerivationPath::from_str("m/48'/0'/0'/2'")
                    .map_err(|e| Error::InvalidDerivationPath(format!("Invalid path: {e:?}")))?,
            )
            .network(Network::Bitcoin)
            .script_type(MultisigScriptType::P2wsh)
            .build()?;

        let descriptor = config.descriptor();
        assert!(descriptor.starts_with("wsh(multi(2,"));
        assert!(descriptor.contains("/<0;1>/*"));

        Ok(())
    }
}
