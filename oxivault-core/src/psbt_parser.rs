//! Real PSBT parsing and analysis
//!
//! This module provides comprehensive PSBT parsing, analysis, and manipulation
//! capabilities for hardware wallet operations.

use crate::{Error, Result};
use bitcoin::{psbt::Psbt, Address, Network, ScriptBuf};

#[cfg(not(feature = "std"))]
use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

/// Comprehensive PSBT analysis
#[derive(Debug, Clone)]
pub struct PsbtAnalysis {
    pub inputs: Vec<InputAnalysis>,
    pub outputs: Vec<OutputAnalysis>,
    pub total_input_value: Option<u64>,
    pub total_output_value: u64,
    pub fee: Option<u64>,
    pub is_complete: bool,
    pub signatures_present: usize,
    pub signatures_required: usize,
    pub network: Network,
    pub version: i32,
    pub locktime: u32,
}

/// Detailed input analysis
#[derive(Debug, Clone)]
pub struct InputAnalysis {
    pub index: usize,
    pub previous_txid: String,
    pub previous_vout: u32,
    pub value: Option<u64>,
    pub script_type: ScriptType,
    pub is_signed: bool,
    pub signatures: Vec<SignatureInfo>,
    pub derivation_path: Option<String>,
    pub is_mine: bool,
}

/// Detailed output analysis
#[derive(Debug, Clone)]
pub struct OutputAnalysis {
    pub index: usize,
    pub address: String,
    pub value: u64,
    pub script_type: ScriptType,
    pub is_change: bool,
    pub derivation_path: Option<String>,
    pub is_mine: bool,
}

/// Signature information
#[derive(Debug, Clone)]
pub struct SignatureInfo {
    pub pubkey: String,
    pub signature: String,
    pub sighash_type: String,
}

/// Script type classification
#[derive(Debug, Clone, PartialEq)]
pub enum ScriptType {
    P2PKH,
    P2SH,
    P2WPKH,
    P2WSH,
    P2TR,
    Unknown,
}

impl ScriptType {
    /// Identify script type from a script
    pub fn from_script(script: &ScriptBuf) -> Self {
        if script.is_p2pkh() {
            ScriptType::P2PKH
        } else if script.is_p2sh() {
            ScriptType::P2SH
        } else if script.is_p2wpkh() {
            ScriptType::P2WPKH
        } else if script.is_p2wsh() {
            ScriptType::P2WSH
        } else if script.is_p2tr() {
            ScriptType::P2TR
        } else {
            ScriptType::Unknown
        }
    }

    /// Get human-readable name
    pub fn name(&self) -> &str {
        match self {
            ScriptType::P2PKH => "Legacy (P2PKH)",
            ScriptType::P2SH => "Nested Segwit (P2SH)",
            ScriptType::P2WPKH => "Native Segwit (P2WPKH)",
            ScriptType::P2WSH => "Native Segwit Script (P2WSH)",
            ScriptType::P2TR => "Taproot (P2TR)",
            ScriptType::Unknown => "Unknown",
        }
    }
}

/// PSBT parser and analyzer
pub struct PsbtParser {
    network: Network,
}

impl PsbtParser {
    /// Create a new PSBT parser
    pub fn new(network: Network) -> Self {
        Self { network }
    }

    /// Parse PSBT from base64
    pub fn parse_base64(&self, base64_data: &str) -> Result<Psbt> {
        use base64::{engine::general_purpose::STANDARD, Engine as _};

        let bytes = STANDARD
            .decode(base64_data)
            .map_err(|e| Error::InvalidParameter(format!("Invalid base64: {}", e)))?;

        self.parse_bytes(&bytes)
    }

    /// Parse PSBT from bytes
    pub fn parse_bytes(&self, data: &[u8]) -> Result<Psbt> {
        // Try to deserialize directly - PSBT has its own format
        // The bitcoin crate should handle this internally
        let psbt = bitcoin::psbt::Psbt::deserialize(data)
            .map_err(|e| Error::PsbtError(format!("Failed to parse PSBT: {:?}", e)))?;

        Ok(psbt)
    }

    /// Analyze a PSBT
    pub fn analyze(&self, psbt: &Psbt) -> Result<PsbtAnalysis> {
        let unsigned_tx = &psbt.unsigned_tx;

        // Analyze inputs
        let mut inputs = Vec::new();
        let mut total_input_value = 0u64;
        let mut all_inputs_have_value = true;
        let mut signatures_present = 0;
        let mut signatures_required = 0;

        for (index, (tx_input, psbt_input)) in
            unsigned_tx.input.iter().zip(psbt.inputs.iter()).enumerate()
        {
            let previous_txid = tx_input.previous_output.txid.to_string();
            let previous_vout = tx_input.previous_output.vout;

            // Get input value from witness_utxo or non_witness_utxo
            let value = if let Some(witness_utxo) = &psbt_input.witness_utxo {
                Some(witness_utxo.value.to_sat())
            } else if let Some(non_witness_utxo) = &psbt_input.non_witness_utxo {
                let vout = tx_input.previous_output.vout as usize;
                if vout < non_witness_utxo.output.len() {
                    Some(non_witness_utxo.output[vout].value.to_sat())
                } else {
                    None
                }
            } else {
                all_inputs_have_value = false;
                None
            };

            if let Some(val) = value {
                total_input_value += val;
            }

            // Determine script type
            let script_type = if let Some(witness_utxo) = &psbt_input.witness_utxo {
                ScriptType::from_script(&witness_utxo.script_pubkey)
            } else if let Some(redeem_script) = &psbt_input.redeem_script {
                if redeem_script.is_p2wpkh() || redeem_script.is_p2wsh() {
                    ScriptType::P2SH
                } else {
                    ScriptType::Unknown
                }
            } else {
                ScriptType::Unknown
            };

            // Check if signed
            let is_signed = !psbt_input.partial_sigs.is_empty()
                || psbt_input.final_script_sig.is_some()
                || psbt_input.final_script_witness.is_some();

            if is_signed {
                signatures_present += 1;
            }
            signatures_required += 1; // Simplified - would need to parse multisig

            // Extract signatures
            let mut signatures = Vec::new();
            for (pubkey, sig) in &psbt_input.partial_sigs {
                use hex::ToHex;
                signatures.push(SignatureInfo {
                    pubkey: pubkey.to_bytes().encode_hex::<String>(),
                    signature: sig.to_vec().encode_hex::<String>(),
                    sighash_type: format!("{:?}", sig.sighash_type),
                });
            }

            // Extract derivation path if available
            let derivation_path = if !psbt_input.bip32_derivation.is_empty() {
                // Get first derivation path
                psbt_input
                    .bip32_derivation
                    .values()
                    .next()
                    .map(|(_, path)| path.to_string())
            } else {
                None
            };

            inputs.push(InputAnalysis {
                index,
                previous_txid,
                previous_vout,
                value,
                script_type,
                is_signed,
                signatures,
                derivation_path,
                is_mine: false, // Would need wallet context to determine
            });
        }

        // Analyze outputs
        let mut outputs = Vec::new();
        let mut total_output_value = 0u64;

        for (index, (tx_output, psbt_output)) in unsigned_tx
            .output
            .iter()
            .zip(psbt.outputs.iter())
            .enumerate()
        {
            total_output_value += tx_output.value.to_sat();

            // Try to get address
            let address = Address::from_script(&tx_output.script_pubkey, self.network)
                .map(|a| a.to_string())
                .unwrap_or_else(|_| "Unknown".to_string());

            let script_type = ScriptType::from_script(&tx_output.script_pubkey);

            // Extract derivation path if available
            let derivation_path = if !psbt_output.bip32_derivation.is_empty() {
                psbt_output
                    .bip32_derivation
                    .values()
                    .next()
                    .map(|(_, path)| path.to_string())
            } else {
                None
            };

            // Simple heuristic for change detection
            let is_change = derivation_path
                .as_ref()
                .map(|p| p.contains("/1/"))
                .unwrap_or(false);

            outputs.push(OutputAnalysis {
                index,
                address,
                value: tx_output.value.to_sat(),
                script_type,
                is_change,
                derivation_path,
                is_mine: false, // Would need wallet context
            });
        }

        // Calculate fee if possible
        let fee = if all_inputs_have_value {
            Some(total_input_value.saturating_sub(total_output_value))
        } else {
            None
        };

        // Check if transaction is fully signed
        let is_complete = signatures_present == signatures_required && signatures_required > 0;

        Ok(PsbtAnalysis {
            inputs,
            outputs,
            total_input_value: if all_inputs_have_value {
                Some(total_input_value)
            } else {
                None
            },
            total_output_value,
            fee,
            is_complete,
            signatures_present,
            signatures_required,
            network: self.network,
            version: unsigned_tx.version.0,
            locktime: unsigned_tx.lock_time.to_consensus_u32(),
        })
    }

    /// Create a summary of the PSBT
    pub fn summarize(&self, analysis: &PsbtAnalysis) -> String {
        let mut summary = String::new();

        summary.push_str(&"PSBT Analysis:\n".to_string());
        summary.push_str(&format!("  Network: {:?}\n", analysis.network));
        summary.push_str(&format!("  Version: {}\n", analysis.version));
        summary.push_str(&format!("  Locktime: {}\n", analysis.locktime));
        summary.push_str(&format!("\nInputs: {}\n", analysis.inputs.len()));

        for input in &analysis.inputs {
            summary.push_str(&format!(
                "  #{}: {}:{}\n",
                input.index,
                &input.previous_txid[..8],
                input.previous_vout
            ));
            if let Some(value) = input.value {
                summary.push_str(&format!("    Value: {} sats\n", value));
            }
            summary.push_str(&format!("    Type: {}\n", input.script_type.name()));
            summary.push_str(&format!("    Signed: {}\n", input.is_signed));
        }

        summary.push_str(&format!("\nOutputs: {}\n", analysis.outputs.len()));
        for output in &analysis.outputs {
            summary.push_str(&format!("  #{}: {}\n", output.index, output.address));
            summary.push_str(&format!("    Value: {} sats\n", output.value));
            summary.push_str(&format!("    Type: {}\n", output.script_type.name()));
            if output.is_change {
                summary.push_str("    (Change output)\n");
            }
        }

        if let Some(total_in) = analysis.total_input_value {
            summary.push_str(&format!("\nTotal Input: {} sats\n", total_in));
        }
        summary.push_str(&format!(
            "Total Output: {} sats\n",
            analysis.total_output_value
        ));

        if let Some(fee) = analysis.fee {
            summary.push_str(&format!("Fee: {} sats\n", fee));

            // Calculate fee rate if we have transaction size estimate
            let estimated_vsize = 150 * analysis.inputs.len() + 34 * analysis.outputs.len() + 10;
            let fee_rate = fee as f64 / estimated_vsize as f64;
            summary.push_str(&format!("Est. Fee Rate: {:.1} sat/vB\n", fee_rate));
        }

        summary.push_str(&format!(
            "\nSignatures: {}/{}\n",
            analysis.signatures_present, analysis.signatures_required
        ));
        summary.push_str(&format!("Complete: {}\n", analysis.is_complete));

        summary
    }
}

/// Validate a PSBT for signing
pub fn validate_psbt_for_signing(psbt: &Psbt) -> Result<()> {
    // Check that we have UTXOs for all inputs
    for (i, input) in psbt.inputs.iter().enumerate() {
        if input.witness_utxo.is_none() && input.non_witness_utxo.is_none() {
            return Err(Error::PsbtError(format!(
                "Missing UTXO information for input {}",
                i
            )));
        }
    }

    // Check that the transaction has inputs and outputs
    if psbt.unsigned_tx.input.is_empty() {
        return Err(Error::PsbtError("PSBT has no inputs".into()));
    }

    if psbt.unsigned_tx.output.is_empty() {
        return Err(Error::PsbtError("PSBT has no outputs".into()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_script_type_detection() {
        // Test script type detection
        assert_eq!(ScriptType::P2PKH.name(), "Legacy (P2PKH)");
        assert_eq!(ScriptType::P2WPKH.name(), "Native Segwit (P2WPKH)");
        assert_eq!(ScriptType::P2TR.name(), "Taproot (P2TR)");
    }

    #[test]
    fn test_psbt_parser_creation() {
        let parser = PsbtParser::new(Network::Bitcoin);
        assert!(matches!(parser.network, Network::Bitcoin));

        let parser_testnet = PsbtParser::new(Network::Testnet);
        assert!(matches!(parser_testnet.network, Network::Testnet));
    }
}
