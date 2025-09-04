//! Integration tests for multisig functionality

use oxivault_core::{
    multisig::{
        MultisigConfig, MultisigBuilder, CosignerInfo,
        MultisigScriptType, PsbtCoordinator,
    },
    Network,
};
use bitcoin::{
    bip32::{ExtendedPrivKey, Xpub, DerivationPath, Fingerprint},
    psbt::Psbt,
    Transaction, TxIn, TxOut, ScriptBuf,
    secp256k1::Secp256k1,
};
use core::str::FromStr;

fn create_test_cosigner(name: &str, seed: u8) -> CosignerInfo {
    let xprv = ExtendedPrivKey::from_str(
        "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu"
    ).unwrap();
    
    let secp = Secp256k1::new();
    let mut xpub = Xpub::from_priv(&secp, &xprv);
    
    // Modify slightly to create different keys
    let mut key_bytes = xpub.public_key.serialize();
    key_bytes[0] = seed;
    xpub.public_key = bitcoin::secp256k1::PublicKey::from_slice(&key_bytes).unwrap();
    
    CosignerInfo {
        name: name.to_string(),
        fingerprint: Fingerprint::from([seed; 4]),
        xpub,
        derivation: DerivationPath::from_str("m/48'/0'/0'/2'").unwrap(),
    }
}

#[test]
fn test_multisig_2_of_3_setup() {
    let alice = create_test_cosigner("Alice", 0x02);
    let bob = create_test_cosigner("Bob", 0x03);
    let charlie = create_test_cosigner("Charlie", 0x04);
    
    let config = MultisigConfig::new(
        2,
        vec![alice, bob, charlie],
        Network::Bitcoin,
        MultisigScriptType::P2wsh,
    ).unwrap();
    
    assert_eq!(config.threshold, 2);
    assert_eq!(config.total, 3);
    
    // Generate first address
    let address = config.derive_address(0, 0).unwrap();
    assert!(address.to_string().starts_with("bc1"));
    
    // Generate change address
    let change_address = config.derive_address(1, 0).unwrap();
    assert!(change_address.to_string().starts_with("bc1"));
    assert_ne!(address, change_address);
}

#[test]
fn test_multisig_builder_pattern() {
    let alice = create_test_cosigner("Alice", 0x02);
    let bob = create_test_cosigner("Bob", 0x03);
    
    let config = MultisigBuilder::new()
        .threshold(2)
        .add_cosigner(alice.name, alice.fingerprint, alice.xpub, alice.derivation)
        .add_cosigner(bob.name, bob.fingerprint, bob.xpub, bob.derivation)
        .network(Network::Bitcoin)
        .script_type(MultisigScriptType::P2wsh)
        .build()
        .unwrap();
    
    assert_eq!(config.threshold, 2);
    assert_eq!(config.total, 2);
}

#[test]
fn test_multisig_descriptor() {
    let alice = create_test_cosigner("Alice", 0x02);
    let bob = create_test_cosigner("Bob", 0x03);
    
    let config = MultisigConfig::new(
        2,
        vec![alice, bob],
        Network::Bitcoin,
        MultisigScriptType::P2wsh,
    ).unwrap();
    
    let descriptor = config.descriptor();
    
    // Check descriptor format
    assert!(descriptor.starts_with("wsh(multi(2,"));
    assert!(descriptor.contains("/<0;1>/*"));
    assert!(descriptor.ends_with("))"));
}

#[test]
fn test_psbt_coordinator() {
    let alice = create_test_cosigner("Alice", 0x02);
    let bob = create_test_cosigner("Bob", 0x03);
    
    let config = MultisigConfig::new(
        2,
        vec![alice, bob],
        Network::Bitcoin,
        MultisigScriptType::P2wsh,
    ).unwrap();
    
    // Create a dummy PSBT
    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn::default(), TxIn::default()],
        output: vec![TxOut {
            value: bitcoin::Amount::from_sat(100000),
            script_pubkey: ScriptBuf::new(),
        }],
    };
    
    let psbt = Psbt::from_unsigned_tx(tx).unwrap();
    
    let coordinator = PsbtCoordinator::new(config, psbt);
    
    // Check initial state
    assert!(!coordinator.is_complete());
    assert_eq!(coordinator.round(), 0);
    
    let (complete, total) = coordinator.progress();
    assert_eq!(complete, 0);
    assert_eq!(total, 2); // Two inputs
}

#[test]
fn test_invalid_multisig_config() {
    let alice = create_test_cosigner("Alice", 0x02);
    
    // Test invalid threshold (0)
    let result = MultisigConfig::new(
        0,
        vec![alice.clone()],
        Network::Bitcoin,
        MultisigScriptType::P2wsh,
    );
    assert!(result.is_err());
    
    // Test invalid threshold (more than cosigners)
    let result = MultisigConfig::new(
        2,
        vec![alice.clone()],
        Network::Bitcoin,
        MultisigScriptType::P2wsh,
    );
    assert!(result.is_err());
    
    // Test too many cosigners
    let mut cosigners = Vec::new();
    for i in 0..21 {
        cosigners.push(create_test_cosigner(&format!("Cosigner{}", i), i as u8));
    }
    
    let result = MultisigConfig::new(
        11,
        cosigners,
        Network::Bitcoin,
        MultisigScriptType::P2wsh,
    );
    assert!(result.is_err());
}

#[test]
fn test_multisig_script_types() {
    let alice = create_test_cosigner("Alice", 0x02);
    let bob = create_test_cosigner("Bob", 0x03);
    
    // Test P2SH
    let config_p2sh = MultisigConfig::new(
        2,
        vec![alice.clone(), bob.clone()],
        Network::Bitcoin,
        MultisigScriptType::P2sh,
    ).unwrap();
    
    let addr_p2sh = config_p2sh.derive_address(0, 0).unwrap();
    assert!(addr_p2sh.to_string().starts_with("3"));
    
    // Test P2WSH
    let config_p2wsh = MultisigConfig::new(
        2,
        vec![alice.clone(), bob.clone()],
        Network::Bitcoin,
        MultisigScriptType::P2wsh,
    ).unwrap();
    
    let addr_p2wsh = config_p2wsh.derive_address(0, 0).unwrap();
    assert!(addr_p2wsh.to_string().starts_with("bc1"));
    
    // Test P2SH-P2WSH
    let config_nested = MultisigConfig::new(
        2,
        vec![alice.clone(), bob.clone()],
        Network::Bitcoin,
        MultisigScriptType::P2shP2wsh,
    ).unwrap();
    
    let addr_nested = config_nested.derive_address(0, 0).unwrap();
    assert!(addr_nested.to_string().starts_with("3"));
    
    // Addresses should be different
    assert_ne!(addr_p2sh, addr_p2wsh);
    assert_ne!(addr_p2sh, addr_nested);
    assert_ne!(addr_p2wsh, addr_nested);
}