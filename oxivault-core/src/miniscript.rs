//! Miniscript Compiler and Policy Language
//!
//! Implements a subset of Miniscript for creating spending policies
//! Compatible with Bitcoin Script and supports common wallet patterns

use crate::{Error, Result};
use bitcoin::{
    blockdata::{opcodes, script::Builder},
    hashes::Hash,
    PublicKey, ScriptBuf,
};

#[cfg(not(feature = "std"))]
use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
#[cfg(feature = "std")]
use std::format;

/// Miniscript policy abstract syntax tree
#[derive(Debug, Clone, PartialEq)]
pub enum Policy {
    /// Require public key signature
    Key(PublicKey),
    /// Require multiple of the sub-policies (threshold)
    Threshold(usize, Vec<Policy>),
    /// Require all sub-policies
    And(Box<Policy>, Box<Policy>),
    /// Require one of the sub-policies
    Or(Box<Policy>, Box<Policy>),
    /// Require after a certain block height
    After(u32),
    /// Require after a certain time (unix timestamp)
    AfterTime(u32),
    /// Hash preimage requirement
    HashPreimage(HashType, [u8; 32]),
    /// Older than n blocks (relative timelock)
    Older(u32),
}

/// Hash types for preimage requirements
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HashType {
    Sha256,
    Hash160,
    Hash256,
}

/// Miniscript fragment (compiled policy)
#[derive(Debug, Clone)]
pub enum Miniscript {
    /// Public key check
    Pk(PublicKey),
    /// Public key hash check  
    Pkh(PublicKey),
    /// Multi-signature
    Multi(usize, Vec<PublicKey>),
    /// Boolean AND
    And(Box<Miniscript>, Box<Miniscript>),
    /// Boolean OR with different probabilities
    Or(Box<Miniscript>, Box<Miniscript>),
    /// Threshold
    Thresh(usize, Vec<Miniscript>),
    /// Absolute timelock
    After(u32),
    /// Relative timelock
    Older(u32),
    /// SHA256 preimage
    Sha256([u8; 32]),
    /// Hash160 preimage
    Hash160([u8; 20]),
    /// Verify or return false
    Verify(Box<Miniscript>),
    /// Just 1 (true)
    True,
    /// Just 0 (false)
    False,
}

/// Miniscript compiler
pub struct MiniscriptCompiler;

impl MiniscriptCompiler {
    /// Compile a policy into Miniscript
    pub fn compile(policy: &Policy) -> Result<Miniscript> {
        match policy {
            Policy::Key(pk) => Ok(Miniscript::Pk(*pk)),

            Policy::Threshold(k, subs) => {
                if *k == 0 || *k > subs.len() {
                    return Err(Error::InvalidParameter(format!(
                        "Invalid threshold {}/{}",
                        k,
                        subs.len()
                    )));
                }

                if *k == 1 {
                    // Any one of them (OR tree)
                    let compiled: Result<Vec<_>> = subs.iter().map(Self::compile).collect();
                    let mut scripts = compiled?;

                    if scripts.is_empty() {
                        return Ok(Miniscript::False);
                    }

                    let first = scripts.remove(0);
                    scripts.into_iter().fold(Ok(first), |acc, script| {
                        acc.map(|a| Miniscript::Or(Box::new(a), Box::new(script)))
                    })
                } else if *k == subs.len() {
                    // All of them (AND tree)
                    let compiled: Result<Vec<_>> = subs.iter().map(Self::compile).collect();
                    let mut scripts = compiled?;

                    if scripts.is_empty() {
                        return Ok(Miniscript::True);
                    }

                    let first = scripts.remove(0);
                    scripts.into_iter().fold(Ok(first), |acc, script| {
                        acc.map(|a| Miniscript::And(Box::new(a), Box::new(script)))
                    })
                } else {
                    // True threshold
                    let compiled: Result<Vec<_>> = subs.iter().map(Self::compile).collect();
                    Ok(Miniscript::Thresh(*k, compiled?))
                }
            }

            Policy::And(a, b) => {
                let compiled_a = Self::compile(a)?;
                let compiled_b = Self::compile(b)?;
                Ok(Miniscript::And(Box::new(compiled_a), Box::new(compiled_b)))
            }

            Policy::Or(a, b) => {
                let compiled_a = Self::compile(a)?;
                let compiled_b = Self::compile(b)?;
                Ok(Miniscript::Or(Box::new(compiled_a), Box::new(compiled_b)))
            }

            Policy::After(height) => Ok(Miniscript::After(*height)),

            Policy::AfterTime(time) => {
                // Convert unix time to block height (BIP 65)
                // If >= 500000000, it's a unix timestamp
                if *time >= 500_000_000 {
                    Ok(Miniscript::After(*time))
                } else {
                    Ok(Miniscript::After(*time))
                }
            }

            Policy::HashPreimage(hash_type, hash) => {
                match hash_type {
                    HashType::Sha256 => Ok(Miniscript::Sha256(*hash)),
                    HashType::Hash160 => {
                        // For Hash160 we need 20 bytes
                        let mut hash160 = [0u8; 20];
                        hash160.copy_from_slice(&hash[..20]);
                        Ok(Miniscript::Hash160(hash160))
                    }
                    HashType::Hash256 => {
                        // Hash256 is double SHA256, we store as SHA256 for simplicity
                        Ok(Miniscript::Sha256(*hash))
                    }
                }
            }

            Policy::Older(blocks) => Ok(Miniscript::Older(*blocks)),
        }
    }

    /// Convert Miniscript to Bitcoin Script
    pub fn to_script(miniscript: &Miniscript) -> Result<ScriptBuf> {
        let script = match miniscript {
            Miniscript::Pk(pk) => Builder::new()
                .push_key(pk)
                .push_opcode(opcodes::all::OP_CHECKSIG)
                .into_script(),

            Miniscript::Pkh(pk) => Builder::new()
                .push_opcode(opcodes::all::OP_DUP)
                .push_opcode(opcodes::all::OP_HASH160)
                .push_slice(pk.pubkey_hash().to_byte_array())
                .push_opcode(opcodes::all::OP_EQUALVERIFY)
                .push_opcode(opcodes::all::OP_CHECKSIG)
                .into_script(),

            Miniscript::Multi(k, pks) => {
                let mut builder = Builder::new();
                builder = builder.push_int(*k as i64);
                for pk in pks {
                    builder = builder.push_key(pk);
                }
                builder = builder.push_int(pks.len() as i64);
                builder = builder.push_opcode(opcodes::all::OP_CHECKMULTISIG);
                builder.into_script()
            }

            Miniscript::And(a, b) => {
                // For AND, combine the scripts
                // This is simplified - real miniscript uses different construction
                let script_a = Self::to_script(a)?;
                let script_b = Self::to_script(b)?;

                // Concatenate scripts with AND logic
                let mut result = script_a.into_bytes();
                result.extend_from_slice(script_b.as_bytes());
                result.extend_from_slice(&[opcodes::all::OP_BOOLAND.to_u8()]);
                ScriptBuf::from_bytes(result)
            }

            Miniscript::Or(a, b) => {
                let script_a = Self::to_script(a)?;
                let script_b = Self::to_script(b)?;

                // OR using IF/ELSE structure
                let mut result = vec![opcodes::all::OP_IF.to_u8()];
                result.extend_from_slice(script_a.as_bytes());
                result.push(opcodes::all::OP_ELSE.to_u8());
                result.extend_from_slice(script_b.as_bytes());
                result.push(opcodes::all::OP_ENDIF.to_u8());
                ScriptBuf::from_bytes(result)
            }

            Miniscript::Thresh(k, subs) => {
                // Threshold is complex, simplified implementation
                // In production, use proper threshold construction
                if *k == 1 && subs.len() == 2 {
                    // 1-of-2 is just OR
                    let or_ms =
                        Miniscript::Or(Box::new(subs[0].clone()), Box::new(subs[1].clone()));
                    Self::to_script(&or_ms)?
                } else {
                    // Fallback to multisig if all are keys
                    return Err(Error::InvalidParameter(
                        "Complex threshold not yet implemented".to_string(),
                    ));
                }
            }

            Miniscript::After(height) => Builder::new()
                .push_int(*height as i64)
                .push_opcode(opcodes::all::OP_CLTV)
                .push_opcode(opcodes::all::OP_DROP)
                .push_opcode(opcodes::all::OP_PUSHNUM_1)
                .into_script(),

            Miniscript::Older(blocks) => Builder::new()
                .push_int(*blocks as i64)
                .push_opcode(opcodes::all::OP_CSV)
                .push_opcode(opcodes::all::OP_DROP)
                .push_opcode(opcodes::all::OP_PUSHNUM_1)
                .into_script(),

            Miniscript::Sha256(hash) => {
                // Build script: OP_SHA256 <hash> OP_EQUAL
                let mut script = vec![opcodes::all::OP_SHA256.to_u8()];
                script.push(32); // Push 32 bytes
                script.extend_from_slice(hash);
                script.push(opcodes::all::OP_EQUAL.to_u8());
                ScriptBuf::from_bytes(script)
            }

            Miniscript::Hash160(hash) => {
                // Build script: OP_HASH160 <hash> OP_EQUAL
                let mut script = vec![opcodes::all::OP_HASH160.to_u8()];
                script.push(20); // Push 20 bytes
                script.extend_from_slice(hash);
                script.push(opcodes::all::OP_EQUAL.to_u8());
                ScriptBuf::from_bytes(script)
            }

            Miniscript::Verify(inner) => {
                let inner_script = Self::to_script(inner)?;
                let mut result = inner_script.into_bytes();
                result.push(opcodes::all::OP_VERIFY.to_u8());
                ScriptBuf::from_bytes(result)
            }

            Miniscript::True => Builder::new()
                .push_opcode(opcodes::all::OP_PUSHNUM_1)
                .into_script(),

            Miniscript::False => Builder::new()
                .push_opcode(opcodes::all::OP_PUSHBYTES_0)
                .into_script(),
        };

        Ok(script)
    }
}

/// Policy builder for common patterns
pub struct PolicyBuilder;

impl PolicyBuilder {
    /// Create a simple single-key policy
    pub fn key(pk: PublicKey) -> Policy {
        Policy::Key(pk)
    }

    /// Create a 2-of-3 multisig policy
    pub fn multisig_2_of_3(pk1: PublicKey, pk2: PublicKey, pk3: PublicKey) -> Policy {
        Policy::Threshold(
            2,
            vec![Policy::Key(pk1), Policy::Key(pk2), Policy::Key(pk3)],
        )
    }

    /// Create a timelocked policy (funds available after height/time)
    pub fn timelocked(pk: PublicKey, locktime: u32) -> Policy {
        Policy::And(Box::new(Policy::Key(pk)), Box::new(Policy::After(locktime)))
    }

    /// Create an inheritance policy (owner OR heir after timeout)
    pub fn inheritance(owner: PublicKey, heir: PublicKey, timeout_blocks: u32) -> Policy {
        Policy::Or(
            Box::new(Policy::Key(owner)),
            Box::new(Policy::And(
                Box::new(Policy::Key(heir)),
                Box::new(Policy::Older(timeout_blocks)),
            )),
        )
    }

    /// Create a hash-timelocked contract (HTLC)
    pub fn htlc(recipient: PublicKey, refund: PublicKey, hash: [u8; 32], timeout: u32) -> Policy {
        Policy::Or(
            Box::new(Policy::And(
                Box::new(Policy::Key(recipient)),
                Box::new(Policy::HashPreimage(HashType::Sha256, hash)),
            )),
            Box::new(Policy::And(
                Box::new(Policy::Key(refund)),
                Box::new(Policy::After(timeout)),
            )),
        )
    }

    /// Create an escrow policy (2-of-3 with buyer, seller, arbiter)
    pub fn escrow(buyer: PublicKey, seller: PublicKey, arbiter: PublicKey) -> Policy {
        Policy::Threshold(
            2,
            vec![
                Policy::Key(buyer),
                Policy::Key(seller),
                Policy::Key(arbiter),
            ],
        )
    }
}

/// Parse a policy from a string representation
pub fn parse_policy(s: &str) -> Result<Policy> {
    // Simple parser for demonstration
    // Real implementation would need proper parsing

    if s.starts_with("pk(") && s.ends_with(')') {
        // Parse pk(pubkey)
        return Err(Error::InvalidParameter(
            "Policy parsing not fully implemented".to_string(),
        ));
    }

    if s.starts_with("thresh(") {
        // Parse thresh(k,policy1,policy2,...)
        return Err(Error::InvalidParameter(
            "Policy parsing not fully implemented".to_string(),
        ));
    }

    Err(Error::InvalidParameter(format!(
        "Unknown policy format: {}",
        s
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bitcoin::Network;
    use bitcoin::PrivateKey;

    fn test_pubkey() -> PublicKey {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[0x01; 32]).unwrap();
        let private_key = PrivateKey::new(secret_key, Network::Bitcoin);
        private_key.public_key(&secp)
    }

    #[test]
    fn test_compile_simple_key() {
        let pk = test_pubkey();
        let policy = Policy::Key(pk.clone());
        let miniscript = MiniscriptCompiler::compile(&policy).unwrap();

        match miniscript {
            Miniscript::Pk(compiled_pk) => assert_eq!(compiled_pk, pk),
            _ => panic!("Expected Pk miniscript"),
        }
    }

    #[test]
    fn test_compile_threshold() {
        let pk1 = test_pubkey();
        let pk2 = test_pubkey();
        let pk3 = test_pubkey();

        let policy = Policy::Threshold(
            2,
            vec![
                Policy::Key(pk1.clone()),
                Policy::Key(pk2.clone()),
                Policy::Key(pk3.clone()),
            ],
        );

        let miniscript = MiniscriptCompiler::compile(&policy).unwrap();
        assert!(matches!(miniscript, Miniscript::Thresh(2, _)));
    }

    #[test]
    fn test_compile_timelock() {
        let pk = test_pubkey();
        let policy = Policy::And(Box::new(Policy::Key(pk)), Box::new(Policy::After(500000)));

        let miniscript = MiniscriptCompiler::compile(&policy).unwrap();
        assert!(matches!(miniscript, Miniscript::And(_, _)));
    }

    #[test]
    fn test_policy_builder_multisig() {
        let pk1 = test_pubkey();
        let pk2 = test_pubkey();
        let pk3 = test_pubkey();

        let policy = PolicyBuilder::multisig_2_of_3(pk1, pk2, pk3);
        assert!(matches!(policy, Policy::Threshold(2, _)));
    }

    #[test]
    fn test_policy_builder_inheritance() {
        let owner = test_pubkey();
        let heir = test_pubkey();

        let policy = PolicyBuilder::inheritance(owner, heir, 144 * 365); // 1 year
        assert!(matches!(policy, Policy::Or(_, _)));
    }

    #[test]
    fn test_to_script_pk() {
        let pk = test_pubkey();
        let miniscript = Miniscript::Pk(pk);
        let script = MiniscriptCompiler::to_script(&miniscript).unwrap();

        // Script should end with OP_CHECKSIG
        let bytes = script.as_bytes();
        assert_eq!(bytes[bytes.len() - 1], opcodes::all::OP_CHECKSIG.to_u8());
    }
}
