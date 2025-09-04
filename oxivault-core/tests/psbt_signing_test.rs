//! Integration tests for PSBT signing functionality

use bitcoin::hashes::Hash;
use bitcoin::{bip32::Xpriv, key::CompressedPublicKey, Network, OutPoint, ScriptBuf, TxOut};
use oxivault_core::{
    psbt::PsbtManager,
    psbt_parser::{validate_psbt_for_signing, PsbtParser},
    Error, Result,
};
use secp256k1::Secp256k1;

/// Test signing a simple P2WPKH transaction
#[test]
fn test_sign_p2wpkh_psbt() -> Result<()> {
    let secp = Secp256k1::new();
    let network = Network::Testnet;

    // Create master key from seed
    let seed = [0x42u8; 32]; // Test seed
    let master = Xpriv::new_master(network, &seed)
        .map_err(|e| Error::BitcoinError(format!("Failed to create master key: {:?}", e)))?;

    // Derive key for m/84'/1'/0'/0/0 (testnet native segwit)
    let path = parse_derivation_path("m/84'/1'/0'/0/0")?;
    let derived = master
        .derive_priv(&secp, &path)
        .map_err(|e| Error::BitcoinError(format!("Failed to derive key: {:?}", e)))?;

    // Create PSBT manager
    let mut psbt_manager = PsbtManager::empty();

    // Add input (spending from a previous P2WPKH)
    let outpoint = OutPoint {
        txid: "0000000000000000000000000000000000000000000000000000000000000001"
            .parse()
            .map_err(|e| Error::InvalidParameter(format!("Invalid txid: {:?}", e)))?,
        vout: 0,
    };
    psbt_manager.add_input(outpoint, 0xffffffff);

    // Create P2WPKH script pubkey for the input we're spending
    let input_pubkey = CompressedPublicKey::from_private_key(&secp, &derived.to_priv())
        .map_err(|e| Error::InvalidParameter(format!("Failed to get pubkey: {:?}", e)))?;
    let input_script = ScriptBuf::new_p2wpkh(&input_pubkey.wpubkey_hash());

    // Set witness UTXO
    let witness_utxo = TxOut {
        value: bitcoin::Amount::from_sat(100_000),
        script_pubkey: input_script,
    };
    psbt_manager.set_witness_utxo(0, witness_utxo)?;

    // Add output (send to another address)
    let output_script = ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_raw_hash(
        bitcoin::hashes::hash160::Hash::all_zeros(),
    ));
    psbt_manager.add_output(output_script, 90_000);

    // Add HD keypaths
    let fingerprint = master.fingerprint(&secp);
    let secp_pubkey = secp256k1::PublicKey::from_slice(&input_pubkey.to_bytes())
        .map_err(|e| Error::Secp256k1Error)?;
    psbt_manager.add_input_hd_keypaths(0, secp_pubkey, fingerprint, path.clone())?;

    // Validate PSBT before signing
    validate_psbt_for_signing(psbt_manager.psbt())?;

    // Sign the PSBT
    psbt_manager.sign_with_key(&derived, &secp)?;

    // Verify signature was added
    assert!(!psbt_manager.psbt().inputs[0].partial_sigs.is_empty());

    // Finalize the PSBT
    psbt_manager.finalize()?;

    // Verify witness was created
    assert!(psbt_manager.psbt().inputs[0].final_script_witness.is_some());

    // Extract final transaction
    let tx = psbt_manager.extract_transaction()?;
    assert!(!tx.input[0].witness.is_empty());

    Ok(())
}

/// Test signing a P2SH-P2WPKH (nested segwit) transaction
#[test]
fn test_sign_p2sh_p2wpkh_psbt() -> Result<()> {
    let secp = Secp256k1::new();
    let network = Network::Testnet;

    // Create master key
    let seed = [0x43u8; 32];
    let master = Xpriv::new_master(network, &seed)
        .map_err(|e| Error::BitcoinError(format!("Failed to create master key: {:?}", e)))?;

    // Derive key for m/49'/1'/0'/0/0 (testnet nested segwit)
    let path = parse_derivation_path("m/49'/1'/0'/0/0")?;
    let derived = master
        .derive_priv(&secp, &path)
        .map_err(|e| Error::BitcoinError(format!("Failed to derive key: {:?}", e)))?;

    // Create PSBT
    let mut psbt_manager = PsbtManager::empty();

    // Add input
    let outpoint = OutPoint {
        txid: "0000000000000000000000000000000000000000000000000000000000000002"
            .parse()
            .map_err(|e| Error::InvalidParameter(format!("Invalid txid: {:?}", e)))?,
        vout: 0,
    };
    psbt_manager.add_input(outpoint, 0xffffffff);

    // Create P2WPKH redeem script
    let pubkey = CompressedPublicKey::from_private_key(&secp, &derived.to_priv())
        .map_err(|e| Error::InvalidParameter(format!("Failed to get pubkey: {:?}", e)))?;
    let redeem_script = ScriptBuf::new_p2wpkh(&pubkey.wpubkey_hash());

    // Create P2SH script pubkey
    let p2sh_script = ScriptBuf::new_p2sh(&redeem_script.script_hash());

    // Set witness UTXO for P2SH
    let witness_utxo = TxOut {
        value: bitcoin::Amount::from_sat(100_000),
        script_pubkey: p2sh_script,
    };
    psbt_manager.set_witness_utxo(0, witness_utxo)?;

    // Set redeem script
    psbt_manager.set_redeem_script(0, redeem_script)?;

    // Add output
    let output_script = ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_raw_hash(
        bitcoin::hashes::hash160::Hash::all_zeros(),
    ));
    psbt_manager.add_output(output_script, 90_000);

    // Sign
    psbt_manager.sign_with_key(&derived, &secp)?;

    // Verify signature
    assert!(!psbt_manager.psbt().inputs[0].partial_sigs.is_empty());

    // Finalize
    psbt_manager.finalize()?;

    // Verify both script sig and witness were created
    assert!(psbt_manager.psbt().inputs[0].final_script_sig.is_some());
    assert!(psbt_manager.psbt().inputs[0].final_script_witness.is_some());

    Ok(())
}

/// Test signing a legacy P2PKH transaction
#[test]
fn test_sign_p2pkh_psbt() -> Result<()> {
    let secp = Secp256k1::new();
    let network = Network::Testnet;

    // Create master key
    let seed = [0x44u8; 32];
    let master = Xpriv::new_master(network, &seed)
        .map_err(|e| Error::BitcoinError(format!("Failed to create master key: {:?}", e)))?;

    // Derive key for m/44'/1'/0'/0/0 (testnet legacy)
    let path = parse_derivation_path("m/44'/1'/0'/0/0")?;
    let derived = master
        .derive_priv(&secp, &path)
        .map_err(|e| Error::BitcoinError(format!("Failed to derive key: {:?}", e)))?;

    // Create PSBT
    let mut psbt_manager = PsbtManager::empty();

    // Add input
    let outpoint = OutPoint {
        txid: "0000000000000000000000000000000000000000000000000000000000000003"
            .parse()
            .map_err(|e| Error::InvalidParameter(format!("Invalid txid: {:?}", e)))?,
        vout: 0,
    };
    psbt_manager.add_input(outpoint, 0xffffffff);

    // Create P2PKH script pubkey
    let pubkey = CompressedPublicKey::from_private_key(&secp, &derived.to_priv())
        .map_err(|e| Error::InvalidParameter(format!("Failed to get pubkey: {:?}", e)))?;
    let p2pkh_script = ScriptBuf::new_p2pkh(&pubkey.pubkey_hash());

    // For legacy, we should use non_witness_utxo, but witness_utxo also works
    let witness_utxo = TxOut {
        value: bitcoin::Amount::from_sat(100_000),
        script_pubkey: p2pkh_script,
    };
    psbt_manager.set_witness_utxo(0, witness_utxo)?;

    // Add output
    let output_script = ScriptBuf::new_p2pkh(&bitcoin::PubkeyHash::from_raw_hash(
        bitcoin::hashes::hash160::Hash::all_zeros(),
    ));
    psbt_manager.add_output(output_script, 90_000);

    // Sign
    psbt_manager.sign_with_key(&derived, &secp)?;

    // Verify signature
    assert!(!psbt_manager.psbt().inputs[0].partial_sigs.is_empty());

    // Finalize
    psbt_manager.finalize()?;

    // Verify script sig was created (no witness for legacy)
    assert!(psbt_manager.psbt().inputs[0].final_script_sig.is_some());
    assert!(psbt_manager.psbt().inputs[0].final_script_witness.is_none());

    Ok(())
}

/// Test round-trip: create, sign, serialize, parse, analyze
#[test]
fn test_psbt_roundtrip() -> Result<()> {
    let secp = Secp256k1::new();
    let network = Network::Testnet;

    // Create and sign a PSBT
    let seed = [0x45u8; 32];
    let master = Xpriv::new_master(network, &seed)
        .map_err(|e| Error::BitcoinError(format!("Failed to create master key: {:?}", e)))?;
    let path = parse_derivation_path("m/84'/1'/0'/0/0")?;
    let derived = master
        .derive_priv(&secp, &path)
        .map_err(|e| Error::BitcoinError(format!("Failed to derive key: {:?}", e)))?;

    let mut psbt_manager = PsbtManager::empty();

    // Build transaction
    let outpoint = OutPoint {
        txid: "0000000000000000000000000000000000000000000000000000000000000004"
            .parse()
            .map_err(|e| Error::InvalidParameter(format!("Invalid txid: {:?}", e)))?,
        vout: 0,
    };
    psbt_manager.add_input(outpoint, 0xffffffff);

    let pubkey = CompressedPublicKey::from_private_key(&secp, &derived.to_priv())
        .map_err(|e| Error::InvalidParameter(format!("Failed to get pubkey: {:?}", e)))?;
    let input_script = ScriptBuf::new_p2wpkh(&pubkey.wpubkey_hash());
    let witness_utxo = TxOut {
        value: bitcoin::Amount::from_sat(100_000),
        script_pubkey: input_script,
    };
    psbt_manager.set_witness_utxo(0, witness_utxo)?;

    let output_script = ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_raw_hash(
        bitcoin::hashes::hash160::Hash::all_zeros(),
    ));
    psbt_manager.add_output(output_script, 90_000);

    // Sign it
    psbt_manager.sign_with_key(&derived, &secp)?;

    // Serialize to bytes
    let psbt_bytes = psbt_manager.to_bytes();

    // Parse with our parser
    let parser = PsbtParser::new(network);
    let parsed_psbt = parser.parse_bytes(&psbt_bytes)?;

    // Analyze it
    let analysis = parser.analyze(&parsed_psbt)?;

    // Verify analysis results
    assert_eq!(analysis.inputs.len(), 1);
    assert_eq!(analysis.outputs.len(), 1);
    assert!(analysis.inputs[0].is_signed);
    assert_eq!(analysis.signatures_present, 1);
    assert_eq!(analysis.total_output_value, 90_000);

    Ok(())
}

/// Test multiple inputs with different script types
#[test]
fn test_sign_mixed_script_types() -> Result<()> {
    let secp = Secp256k1::new();
    let network = Network::Bitcoin;

    // Create master key
    let seed = [0x46u8; 32];
    let master = Xpriv::new_master(network, &seed)
        .map_err(|e| Error::BitcoinError(format!("Failed to create master key: {:?}", e)))?;

    // Create PSBT with multiple inputs
    let mut psbt_manager = PsbtManager::empty();

    // Input 1: P2WPKH (native segwit)
    let path1 = parse_derivation_path("m/84'/0'/0'/0/0")?;
    let key1 = master
        .derive_priv(&secp, &path1)
        .map_err(|e| Error::BitcoinError(format!("Failed to derive key1: {:?}", e)))?;
    let pubkey1 = CompressedPublicKey::from_private_key(&secp, &key1.to_priv())
        .map_err(|e| Error::InvalidParameter(format!("Failed to get pubkey1: {:?}", e)))?;
    let script1 = ScriptBuf::new_p2wpkh(&pubkey1.wpubkey_hash());

    psbt_manager.add_input(
        OutPoint {
            txid: "0000000000000000000000000000000000000000000000000000000000000005"
                .parse()
                .map_err(|e| Error::InvalidParameter(format!("Invalid txid: {:?}", e)))?,
            vout: 0,
        },
        0xffffffff,
    );
    psbt_manager.set_witness_utxo(
        0,
        TxOut {
            value: bitcoin::Amount::from_sat(50_000),
            script_pubkey: script1,
        },
    )?;

    // Input 2: P2SH-P2WPKH (nested segwit)
    let path2 = parse_derivation_path("m/49'/0'/0'/0/0")?;
    let key2 = master
        .derive_priv(&secp, &path2)
        .map_err(|e| Error::BitcoinError(format!("Failed to derive key2: {:?}", e)))?;
    let pubkey2 = CompressedPublicKey::from_private_key(&secp, &key2.to_priv())
        .map_err(|e| Error::InvalidParameter(format!("Failed to get pubkey2: {:?}", e)))?;
    let redeem2 = ScriptBuf::new_p2wpkh(&pubkey2.wpubkey_hash());
    let script2 = ScriptBuf::new_p2sh(&redeem2.script_hash());

    psbt_manager.add_input(
        OutPoint {
            txid: "0000000000000000000000000000000000000000000000000000000000000006"
                .parse()
                .map_err(|e| Error::InvalidParameter(format!("Invalid txid: {:?}", e)))?,
            vout: 0,
        },
        0xffffffff,
    );
    psbt_manager.set_witness_utxo(
        1,
        TxOut {
            value: bitcoin::Amount::from_sat(50_000),
            script_pubkey: script2,
        },
    )?;
    psbt_manager.set_redeem_script(1, redeem2)?;

    // Add output
    let output_script = ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_raw_hash(
        bitcoin::hashes::hash160::Hash::all_zeros(),
    ));
    psbt_manager.add_output(output_script, 95_000);

    // Sign both inputs
    psbt_manager.sign_with_key(&key1, &secp)?;
    psbt_manager.sign_with_key(&key2, &secp)?;

    // Verify both inputs are signed
    assert!(!psbt_manager.psbt().inputs[0].partial_sigs.is_empty());
    assert!(!psbt_manager.psbt().inputs[1].partial_sigs.is_empty());

    // Finalize
    psbt_manager.finalize()?;

    // Verify correct finalization for each type
    assert!(psbt_manager.psbt().inputs[0].final_script_witness.is_some());
    assert!(psbt_manager.psbt().inputs[0].final_script_sig.is_none());

    assert!(psbt_manager.psbt().inputs[1].final_script_witness.is_some());
    assert!(psbt_manager.psbt().inputs[1].final_script_sig.is_some());

    Ok(())
}

/// Test that signing fails gracefully with missing UTXO data
#[test]
fn test_sign_missing_utxo_data() -> Result<()> {
    let secp = Secp256k1::new();
    let network = Network::Bitcoin;

    let seed = [0x47u8; 32];
    let master = Xpriv::new_master(network, &seed)
        .map_err(|e| Error::BitcoinError(format!("Failed to create master key: {:?}", e)))?;
    let path = parse_derivation_path("m/84'/0'/0'/0/0")?;
    let derived = master
        .derive_priv(&secp, &path)
        .map_err(|e| Error::BitcoinError(format!("Failed to derive key: {:?}", e)))?;

    let mut psbt_manager = PsbtManager::empty();

    // Add input without UTXO data
    psbt_manager.add_input(OutPoint::default(), 0xffffffff);

    // Add output
    let output_script = ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_raw_hash(
        bitcoin::hashes::hash160::Hash::all_zeros(),
    ));
    psbt_manager.add_output(output_script, 90_000);

    // Try to sign - should succeed but not add any signatures
    psbt_manager.sign_with_key(&derived, &secp)?;

    // Verify no signatures were added
    assert!(psbt_manager.psbt().inputs[0].partial_sigs.is_empty());

    Ok(())
}

/// Helper to parse derivation path from string
fn parse_derivation_path(s: &str) -> Result<bitcoin::bip32::DerivationPath> {
    use bitcoin::bip32::{ChildNumber, DerivationPath};

    let mut path = vec![];
    for component in s.split('/').skip(1) {
        let (num_str, hardened) = if component.ends_with('\'') || component.ends_with('h') {
            (&component[..component.len() - 1], true)
        } else {
            (component, false)
        };

        let num: u32 = num_str
            .parse()
            .map_err(|_| Error::InvalidParameter(format!("Invalid path: {}", s)))?;

        if hardened {
            path.push(ChildNumber::from_hardened_idx(num).map_err(|_| {
                Error::InvalidParameter(format!("Invalid hardened index: {}", num))
            })?);
        } else {
            path.push(
                ChildNumber::from_normal_idx(num)
                    .map_err(|_| Error::InvalidParameter(format!("Invalid index: {}", num)))?,
            );
        }
    }

    Ok(DerivationPath::from(path))
}
