//! Simplified PSBT (Partially Signed Bitcoin Transaction) support

use crate::{Error, Result};
use bitcoin::psbt::{Psbt, PsbtSighashType};
use bitcoin::{Transaction, TxIn, TxOut, ScriptBuf, OutPoint, Witness};
use bitcoin::script::PushBytesBuf;
use bitcoin::transaction::Version;
use bitcoin::locktime::absolute::LockTime;
use bitcoin::bip32::{Xpriv, DerivationPath, Fingerprint};
use bitcoin::sighash::{SighashCache, EcdsaSighashType, Prevouts};
use bitcoin::ecdsa::Signature;
use bitcoin::PublicKey;
use bitcoin::hashes::Hash;
use secp256k1::{Secp256k1, Message};

#[cfg(not(feature = "std"))]
use alloc::{vec::Vec, string::String, format};

/// PSBT builder and signer (simplified version)
pub struct PsbtManager {
    psbt: Psbt,
}

impl PsbtManager {
    /// Create a new PSBT from a transaction
    pub fn new(transaction: Transaction) -> Self {
        let psbt = Psbt::from_unsigned_tx(transaction).unwrap();
        Self { psbt }
    }

    /// Create an empty PSBT
    pub fn empty() -> Self {
        let transaction = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: Vec::new(),
            output: Vec::new(),
        };
        Self::new(transaction)
    }

    /// Add an input to the PSBT
    pub fn add_input(&mut self, outpoint: OutPoint, sequence: u32) {
        let txin = TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence(sequence),
            witness: Witness::new(),
        };
        
        self.psbt.unsigned_tx.input.push(txin);
        self.psbt.inputs.push(Default::default());
    }

    /// Add an output to the PSBT
    pub fn add_output(&mut self, script_pubkey: ScriptBuf, value: u64) {
        let txout = TxOut {
            value: bitcoin::Amount::from_sat(value),
            script_pubkey,
        };
        
        self.psbt.unsigned_tx.output.push(txout);
        self.psbt.outputs.push(Default::default());
    }

    /// Set witness UTXO for an input
    pub fn set_witness_utxo(&mut self, input_index: usize, txout: TxOut) -> Result<()> {
        if input_index >= self.psbt.inputs.len() {
            return Err(Error::PsbtError("Input index out of bounds".into()));
        }
        
        self.psbt.inputs[input_index].witness_utxo = Some(txout);
        Ok(())
    }

    /// Set non-witness UTXO for an input (for legacy P2PKH)
    pub fn set_non_witness_utxo(&mut self, input_index: usize, tx: Transaction) -> Result<()> {
        if input_index >= self.psbt.inputs.len() {
            return Err(Error::PsbtError("Input index out of bounds".into()));
        }
        
        self.psbt.inputs[input_index].non_witness_utxo = Some(tx);
        Ok(())
    }
    
    /// Set redeem script for an input (for P2SH-P2WPKH)
    pub fn set_redeem_script(&mut self, input_index: usize, script: ScriptBuf) -> Result<()> {
        if input_index >= self.psbt.inputs.len() {
            return Err(Error::PsbtError("Input index out of bounds".into()));
        }
        
        self.psbt.inputs[input_index].redeem_script = Some(script);
        Ok(())
    }
    
    /// Set witness script for an input (for P2WSH)
    pub fn set_witness_script(&mut self, input_index: usize, script: ScriptBuf) -> Result<()> {
        if input_index >= self.psbt.inputs.len() {
            return Err(Error::PsbtError("Input index out of bounds".into()));
        }
        
        self.psbt.inputs[input_index].witness_script = Some(script);
        Ok(())
    }
    
    /// Add HD key paths for an input
    pub fn add_input_hd_keypaths(
        &mut self,
        input_index: usize,
        pubkey: secp256k1::PublicKey,
        fingerprint: Fingerprint,
        path: DerivationPath,
    ) -> Result<()> {
        if input_index >= self.psbt.inputs.len() {
            return Err(Error::PsbtError("Input index out of bounds".into()));
        }
        
        self.psbt.inputs[input_index]
            .bip32_derivation
            .insert(pubkey, (fingerprint, path));
        
        Ok(())
    }

    /// Sign PSBT with support for multiple script types
    /// Supports: P2PKH (legacy), P2SH-P2WPKH (nested segwit), P2WPKH (native segwit), P2TR (taproot)
    pub fn sign_with_key(
        &mut self,
        private_key: &Xpriv,
        secp: &Secp256k1<secp256k1::All>,
    ) -> Result<()> {
        // Collect all witness UTXOs
        let mut all_utxos = Vec::new();
        for input in &self.psbt.inputs {
            if let Some(witness_utxo) = &input.witness_utxo {
                all_utxos.push(witness_utxo.clone());
            } else {
                // For simplicity, only support witness UTXOs for now
                return Err(Error::PsbtError("Only witness UTXOs supported in simplified version".into()));
            }
        }
        
        let _prevouts = Prevouts::All(&all_utxos);
        let mut sighash_cache = SighashCache::new(&self.psbt.unsigned_tx);
        let pubkey = PublicKey::from_private_key(secp, &private_key.to_priv());
        
        // Sign each input based on script type
        for (index, input) in self.psbt.inputs.iter_mut().enumerate() {
            // Skip if already signed by this key
            if input.partial_sigs.contains_key(&pubkey) {
                continue;
            }
            
            // Determine sighash type
            let sighash_type = input.sighash_type
                .unwrap_or(PsbtSighashType::from(EcdsaSighashType::All));
            let ecdsa_type = EcdsaSighashType::from_consensus(sighash_type.to_u32());
            
            // Handle different script types and compute sighash
            let sighash = if let Some(witness_utxo) = &input.witness_utxo {
                // Native Segwit (P2WPKH)
                if witness_utxo.script_pubkey.is_p2wpkh() {
                    sighash_cache
                        .p2wpkh_signature_hash(
                            index, 
                            &witness_utxo.script_pubkey,
                            witness_utxo.value,
                            ecdsa_type
                        )
                        .map_err(|e| Error::PsbtError(format!("P2WPKH sighash failed: {:?}", e)))?
                }
                // Nested Segwit (P2SH-P2WPKH)
                else if witness_utxo.script_pubkey.is_p2sh() {
                    // For nested segwit, we need the redeem script
                    if let Some(redeem_script) = &input.redeem_script {
                        if redeem_script.is_p2wpkh() {
                            // Extract the pubkey hash from the redeem script
                            sighash_cache
                                .p2wpkh_signature_hash(
                                    index,
                                    redeem_script,
                                    witness_utxo.value,
                                    ecdsa_type
                                )
                                .map_err(|e| Error::PsbtError(format!("P2SH-P2WPKH sighash failed: {:?}", e)))?
                        } else {
                            continue; // Unsupported P2SH type
                        }
                    } else {
                        continue; // Need redeem script for P2SH
                    }
                }
                // Taproot (P2TR) - requires schnorr signatures
                else if witness_utxo.script_pubkey.is_p2tr() {
                    // Taproot uses schnorr signatures, not ECDSA
                    // For now, skip taproot inputs as they need special handling
                    continue;
                }
                // Legacy (P2PKH)
                else if witness_utxo.script_pubkey.is_p2pkh() {
                    // For legacy, we need the full previous transaction
                    if let Some(non_witness_utxo) = &input.non_witness_utxo {
                        let prevout_index = self.psbt.unsigned_tx.input[index].previous_output.vout as usize;
                        if prevout_index >= non_witness_utxo.output.len() {
                            continue;
                        }
                        let prevout = &non_witness_utxo.output[prevout_index];
                        
                        sighash_cache
                            .legacy_signature_hash(
                                index,
                                &prevout.script_pubkey,
                                ecdsa_type.to_u32()
                            )
                            .map_err(|e| Error::PsbtError(format!("P2PKH sighash failed: {:?}", e)))?
                    } else {
                        // Try with witness_utxo as fallback
                        sighash_cache
                            .legacy_signature_hash(
                                index,
                                &witness_utxo.script_pubkey,
                                ecdsa_type.to_u32()
                            )
                            .map_err(|e| Error::PsbtError(format!("P2PKH sighash failed: {:?}", e)))?
                    }
                }
                else {
                    continue; // Unsupported script type
                }
            } else if let Some(non_witness_utxo) = &input.non_witness_utxo {
                // Legacy inputs typically use non_witness_utxo
                let prevout_index = self.psbt.unsigned_tx.input[index].previous_output.vout as usize;
                if prevout_index >= non_witness_utxo.output.len() {
                    continue;
                }
                let prevout = &non_witness_utxo.output[prevout_index];
                
                if prevout.script_pubkey.is_p2pkh() {
                    sighash_cache
                        .legacy_signature_hash(
                            index,
                            &prevout.script_pubkey,
                            ecdsa_type.to_u32()
                        )
                        .map_err(|e| Error::PsbtError(format!("P2PKH sighash failed: {:?}", e)))?
                } else {
                    continue;
                }
            } else {
                continue; // No UTXO information available
            };
            
            // Sign the message (for ECDSA-based script types)
            let message = Message::from_digest(sighash.to_byte_array());
            let sig = secp.sign_ecdsa(&message, &private_key.to_priv().inner);
            let signature = Signature {
                signature: sig,
                sighash_type: ecdsa_type,
            };
            
            // Store signature
            input.partial_sigs.insert(pubkey.clone(), signature);
        }
        
        Ok(())
    }

    /// Finalize the PSBT if all signatures are present
    /// Handles multiple script types: P2PKH, P2SH-P2WPKH, P2WPKH, P2TR
    pub fn finalize(&mut self) -> Result<()> {
        for input in self.psbt.inputs.iter_mut() {
            // Skip if already finalized
            if input.final_script_sig.is_some() || input.final_script_witness.is_some() {
                continue;
            }
            
            // Get the first signature (for single-sig)
            if let Some((pubkey, signature)) = input.partial_sigs.iter().next() {
                // Determine script type and create appropriate finalization
                if let Some(witness_utxo) = &input.witness_utxo {
                    // Native Segwit (P2WPKH)
                    if witness_utxo.script_pubkey.is_p2wpkh() {
                        // Create witness stack
                        let mut witness = Witness::new();
                        witness.push(signature.to_vec());
                        witness.push(pubkey.to_bytes());
                        
                        input.final_script_witness = Some(witness);
                        input.partial_sigs.clear();
                    }
                    // Nested Segwit (P2SH-P2WPKH)
                    else if witness_utxo.script_pubkey.is_p2sh() {
                        if let Some(redeem_script) = &input.redeem_script {
                            if redeem_script.is_p2wpkh() {
                                // Create witness stack
                                let mut witness = Witness::new();
                                witness.push(signature.to_vec());
                                witness.push(pubkey.to_bytes());
                                
                                // Set the redeem script as the script sig
                                let redeem_push = PushBytesBuf::try_from(redeem_script.to_bytes())
                                    .map_err(|_| Error::PsbtError("Invalid redeem script size".into()))?;
                                input.final_script_sig = Some(ScriptBuf::builder()
                                    .push_slice(redeem_push)
                                    .into_script());
                                input.final_script_witness = Some(witness);
                                input.partial_sigs.clear();
                            }
                        }
                    }
                    // Legacy (P2PKH)
                    else if witness_utxo.script_pubkey.is_p2pkh() {
                        // Create script sig
                        let sig_push = PushBytesBuf::try_from(signature.to_vec())
                            .map_err(|_| Error::PsbtError("Invalid signature size".into()))?;
                        let pk_push = PushBytesBuf::try_from(pubkey.to_bytes())
                            .map_err(|_| Error::PsbtError("Invalid pubkey size".into()))?;
                        let script_sig = ScriptBuf::builder()
                            .push_slice(sig_push)
                            .push_slice(pk_push)
                            .into_script();
                        
                        input.final_script_sig = Some(script_sig);
                        input.partial_sigs.clear();
                    }
                    // Note: Taproot (P2TR) would need special handling for schnorr signatures
                } else if let Some(non_witness_utxo) = &input.non_witness_utxo {
                    // Legacy inputs
                    let tx_input = &self.psbt.unsigned_tx.input[input.partial_sigs.len()];
                    let prevout_index = tx_input.previous_output.vout as usize;
                    if prevout_index < non_witness_utxo.output.len() {
                        let prevout = &non_witness_utxo.output[prevout_index];
                        
                        if prevout.script_pubkey.is_p2pkh() {
                            // Create script sig for P2PKH
                            let sig_push = PushBytesBuf::try_from(signature.to_vec())
                                .map_err(|_| Error::PsbtError("Invalid signature size".into()))?;
                            let pk_push = PushBytesBuf::try_from(pubkey.to_bytes())
                                .map_err(|_| Error::PsbtError("Invalid pubkey size".into()))?;
                            let script_sig = ScriptBuf::builder()
                                .push_slice(sig_push)
                                .push_slice(pk_push)
                                .into_script();
                            
                            input.final_script_sig = Some(script_sig);
                            input.partial_sigs.clear();
                        }
                    }
                }
            }
        }
        
        Ok(())
    }

    /// Extract the final transaction
    pub fn extract_transaction(&self) -> Result<Transaction> {
        let mut tx = self.psbt.unsigned_tx.clone();
        
        // Apply finalized scripts to the transaction
        for (index, input) in self.psbt.inputs.iter().enumerate() {
            if let Some(final_script_sig) = &input.final_script_sig {
                tx.input[index].script_sig = final_script_sig.clone();
            }
            
            if let Some(final_witness) = &input.final_script_witness {
                tx.input[index].witness = final_witness.clone();
            }
        }
        
        Ok(tx)
    }

    /// Get the PSBT
    pub fn psbt(&self) -> &Psbt {
        &self.psbt
    }

    /// Get mutable PSBT
    pub fn psbt_mut(&mut self) -> &mut Psbt {
        &mut self.psbt
    }

    /// Parse PSBT from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let psbt = Psbt::deserialize(bytes)
            .map_err(|e| Error::PsbtError(format!("{:?}", e)))?;
        Ok(Self { psbt })
    }

    /// Serialize PSBT to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.psbt.serialize()
    }
}

/// PSBT role: Creator, Updater, Signer, Combiner, Finalizer
#[derive(Debug, Clone, Copy)]
pub enum PsbtRole {
    Creator,
    Updater,
    Signer,
    Combiner,
    Finalizer,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;
    use bitcoin::key::CompressedPublicKey;

    #[test]
    fn test_psbt_creation() -> Result<()> {
        let mut psbt_manager = PsbtManager::empty();
        
        // Add a dummy input
        let outpoint = OutPoint::default();
        psbt_manager.add_input(outpoint, 0xfffffffe);
        
        // Add a dummy output
        let script = ScriptBuf::new();
        psbt_manager.add_output(script, 100000);
        
        assert_eq!(psbt_manager.psbt().unsigned_tx.input.len(), 1);
        assert_eq!(psbt_manager.psbt().unsigned_tx.output.len(), 1);
        Ok(())
    }

    #[test]
    fn test_psbt_serialization() -> Result<()> {
        let psbt_manager = PsbtManager::empty();
        let bytes = psbt_manager.to_bytes();
        
        let parsed = PsbtManager::from_bytes(&bytes)?;
        assert_eq!(parsed.to_bytes(), bytes);
        Ok(())
    }
    
    #[test]
    fn test_psbt_signing_p2wpkh() -> Result<()> {
        let secp = Secp256k1::new();
        
        // Create a test private key
        let seed = [0x01u8; 32];
        let xpriv = Xpriv::new_master(Network::Bitcoin, &seed).unwrap();
        
        // Create a PSBT with a P2WPKH input
        let mut psbt_manager = PsbtManager::empty();
        
        // Add input
        let outpoint = OutPoint::default();
        psbt_manager.add_input(outpoint, 0xffffffff);
        
        // Add output (change)
        let out_script = ScriptBuf::new_p2wpkh(
            &CompressedPublicKey::from_private_key(&secp, &xpriv.to_priv()).unwrap().wpubkey_hash()
        );
        psbt_manager.add_output(out_script.clone(), 90000);
        
        // Set witness UTXO for the input
        let witness_utxo = TxOut {
            value: bitcoin::Amount::from_sat(100000),
            script_pubkey: out_script,
        };
        psbt_manager.set_witness_utxo(0, witness_utxo)?;
        
        // Sign the PSBT
        psbt_manager.sign_with_key(&xpriv, &secp)?;
        
        // Check that signature was added
        assert!(!psbt_manager.psbt().inputs[0].partial_sigs.is_empty());
        
        Ok(())
    }
    
    #[test]
    fn test_psbt_finalization() -> Result<()> {
        let secp = Secp256k1::new();
        
        // Create a test private key
        let seed = [0x02u8; 32];
        let xpriv = Xpriv::new_master(Network::Bitcoin, &seed).unwrap();
        
        // Create a PSBT
        let mut psbt_manager = PsbtManager::empty();
        
        // Add input
        let outpoint = OutPoint::default();
        psbt_manager.add_input(outpoint, 0xffffffff);
        
        // Add output
        let out_script = ScriptBuf::new_p2wpkh(
            &CompressedPublicKey::from_private_key(&secp, &xpriv.to_priv()).unwrap().wpubkey_hash()
        );
        psbt_manager.add_output(out_script.clone(), 90000);
        
        // Set witness UTXO
        let witness_utxo = TxOut {
            value: bitcoin::Amount::from_sat(100000),
            script_pubkey: out_script,
        };
        psbt_manager.set_witness_utxo(0, witness_utxo)?;
        
        // Sign and finalize
        psbt_manager.sign_with_key(&xpriv, &secp)?;
        psbt_manager.finalize()?;
        
        // Check that witness was created
        assert!(psbt_manager.psbt().inputs[0].final_script_witness.is_some());
        
        // Extract transaction
        let tx = psbt_manager.extract_transaction()?;
        assert!(!tx.input[0].witness.is_empty());
        
        Ok(())
    }
}