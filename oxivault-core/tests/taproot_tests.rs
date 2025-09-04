//! Integration tests for Taproot functionality

use bitcoin::{
    secp256k1::{Secp256k1, SecretKey},
    ScriptBuf, XOnlyPublicKey,
};
use oxivault_core::{
    taproot::{MuSig2Coordinator, TaprootDescriptor, TaprootKey},
    Network,
};

#[test]
fn test_taproot_address_generation() {
    let secret_key = SecretKey::from_slice(&[0x01; 32]).unwrap();
    let taproot_key = TaprootKey::new(secret_key, Network::Bitcoin);

    // Test simple key-path address
    let address = taproot_key.simple_address();
    assert!(address.to_string().starts_with("bc1p"));

    // Test with script tree
    let script1 = ScriptBuf::from_bytes(vec![0x51]); // OP_1
    let script2 = ScriptBuf::from_bytes(vec![0x52]); // OP_2

    let (address_with_scripts, spend_info) = taproot_key
        .address_with_scripts(vec![script1, script2])
        .unwrap();

    assert!(address_with_scripts.to_string().starts_with("bc1p"));
    assert!(spend_info.merkle_root().is_some());
}

#[test]
fn test_taproot_descriptor_building() {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&[0x02; 32]).unwrap();
    let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &secret_key);
    let (xonly, _) = keypair.x_only_public_key();

    let mut descriptor = TaprootDescriptor::new(xonly);

    // Add some scripts
    let script1 = ScriptBuf::from_bytes(vec![0x51]); // OP_1
    let script2 = ScriptBuf::from_bytes(vec![0x52]); // OP_2

    descriptor.add_leaf(0, script1);
    descriptor.add_leaf(1, script2);

    let address = descriptor.build(&secp, Network::Bitcoin).unwrap();
    assert!(address.to_string().starts_with("bc1p"));

    // Verify spend info was created
    assert!(descriptor.spend_info().is_some());
}

#[test]
fn test_musig2_coordinator_workflow() {
    // Create test keys
    let key1 = XOnlyPublicKey::from_slice(&[
        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
        0x02, 0x02,
    ])
    .unwrap();

    let key2 = XOnlyPublicKey::from_slice(&[
        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
        0x03, 0x03,
    ])
    .unwrap();

    let key3 = XOnlyPublicKey::from_slice(&[
        0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
        0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
        0x04, 0x04,
    ])
    .unwrap();

    // Create coordinator
    let mut coordinator = MuSig2Coordinator::new(vec![key1, key2, key3]);

    // Aggregate keys
    let aggregate_key = coordinator.aggregate_pubkeys().unwrap();
    assert_eq!(aggregate_key, key1); // Simplified implementation returns first key

    // Add partial signatures
    coordinator.add_partial_signature(0, [0x01; 64]).unwrap();
    assert!(!coordinator.is_complete());

    coordinator.add_partial_signature(1, [0x02; 64]).unwrap();
    assert!(!coordinator.is_complete());

    coordinator.add_partial_signature(2, [0x03; 64]).unwrap();
    assert!(coordinator.is_complete());

    // Aggregate signatures
    let final_sig = coordinator.aggregate_signatures().unwrap();
    assert_eq!(final_sig, [0x01; 64]); // Simplified implementation returns first signature
}

#[test]
fn test_taproot_transaction_signing() {
    use bitcoin::sighash::TapSighashType;
    use bitcoin::{Transaction, TxIn, TxOut, Witness};

    let secret_key = SecretKey::from_slice(&[0x05; 32]).unwrap();
    let taproot_key = TaprootKey::new(secret_key, Network::Bitcoin);

    // Create a dummy transaction
    let mut tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn::default()],
        output: vec![TxOut {
            value: bitcoin::Amount::from_sat(100000),
            script_pubkey: ScriptBuf::new(),
        }],
    };

    // Create prevout
    let prevout = TxOut {
        value: bitcoin::Amount::from_sat(200000),
        script_pubkey: taproot_key.simple_address().script_pubkey(),
    };

    // Sign the transaction
    let signature = taproot_key
        .sign_keypath(&tx, 0, &[prevout.clone()], Some(TapSighashType::Default))
        .unwrap();

    // Verify signature exists
    assert_eq!(signature.sighash_type, TapSighashType::Default);

    // In a real implementation, we would verify the signature
    // For now, just check it was created
    tx.input[0].witness = Witness::from_slice(&[signature.to_vec()]);
    assert!(!tx.input[0].witness.is_empty());
}
