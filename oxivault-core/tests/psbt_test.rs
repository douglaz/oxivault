//! Tests for PSBT parsing and analysis

use bitcoin::hashes::Hash;
use bitcoin::Network;
use oxivault_core::{
    psbt_parser::{PsbtParser, ScriptType},
    Result,
};

/// Test PSBT created with Bitcoin Core (testnet)
const TEST_PSBT_BASE64: &str = "cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAAAA";

#[test]
fn test_parse_real_psbt() -> Result<()> {
    let parser = PsbtParser::new(Network::Testnet);

    // Parse the PSBT
    let psbt = parser.parse_base64(TEST_PSBT_BASE64)?;

    // Analyze it
    let analysis = parser.analyze(&psbt)?;

    // Verify basic structure
    assert!(analysis.inputs.len() > 0);
    assert!(analysis.outputs.len() > 0);

    // Check that we have values
    assert!(analysis.total_output_value > 0);

    // Print summary for debugging
    let summary = parser.summarize(&analysis);
    println!("PSBT Summary:\n{}", summary);

    Ok(())
}

#[test]
fn test_create_simple_psbt() -> Result<()> {
    use bitcoin::locktime::absolute::LockTime;
    use bitcoin::psbt::Psbt;
    use bitcoin::transaction::Version;
    use bitcoin::{OutPoint, ScriptBuf, Transaction, TxIn, TxOut};

    // Create a simple unsigned transaction
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: "0000000000000000000000000000000000000000000000000000000000000000"
                    .parse()
                    .unwrap(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![TxOut {
            value: bitcoin::Amount::from_sat(100000),
            script_pubkey: ScriptBuf::new_p2pkh(&bitcoin::PubkeyHash::from_raw_hash(
                bitcoin::hashes::hash160::Hash::all_zeros(),
            )),
        }],
    };

    // Create PSBT from transaction
    let psbt = Psbt::from_unsigned_tx(tx).unwrap();

    // Serialize to bytes
    let bytes = bitcoin::psbt::Psbt::serialize(&psbt);

    // Parse it back
    let parser = PsbtParser::new(Network::Bitcoin);
    let parsed_psbt = parser.parse_bytes(&bytes)?;

    // Analyze
    let analysis = parser.analyze(&parsed_psbt)?;

    assert_eq!(analysis.inputs.len(), 1);
    assert_eq!(analysis.outputs.len(), 1);
    assert_eq!(analysis.total_output_value, 100000);
    assert!(!analysis.is_complete);

    Ok(())
}

#[test]
fn test_script_type_detection() {
    use bitcoin::ScriptBuf;

    // Test P2PKH
    let p2pkh = ScriptBuf::new_p2pkh(&bitcoin::PubkeyHash::from_raw_hash(
        bitcoin::hashes::hash160::Hash::all_zeros(),
    ));
    assert_eq!(ScriptType::from_script(&p2pkh), ScriptType::P2PKH);

    // Test P2WPKH
    let p2wpkh = ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_raw_hash(
        bitcoin::hashes::hash160::Hash::all_zeros(),
    ));
    assert_eq!(ScriptType::from_script(&p2wpkh), ScriptType::P2WPKH);

    // Test P2SH
    let p2sh = ScriptBuf::new_p2sh(&bitcoin::ScriptHash::from_raw_hash(
        bitcoin::hashes::hash160::Hash::all_zeros(),
    ));
    assert_eq!(ScriptType::from_script(&p2sh), ScriptType::P2SH);
}

#[test]
fn test_psbt_validation() -> Result<()> {
    use bitcoin::locktime::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin::{psbt::Psbt, Transaction};
    use oxivault_core::psbt_parser::validate_psbt_for_signing;

    // Create empty transaction
    let empty_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    };

    let empty_psbt = Psbt::from_unsigned_tx(empty_tx).unwrap();

    // Should fail validation
    assert!(validate_psbt_for_signing(&empty_psbt).is_err());

    Ok(())
}

#[test]
fn test_invalid_base64() {
    let parser = PsbtParser::new(Network::Bitcoin);

    // Invalid base64 should fail
    assert!(parser.parse_base64("not-valid-base64!@#$").is_err());

    // Empty string should fail
    assert!(parser.parse_base64("").is_err());

    // Valid base64 but not a PSBT should fail
    assert!(parser.parse_base64("SGVsbG8gV29ybGQ=").is_err());
}
