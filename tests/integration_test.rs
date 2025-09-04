//! Integration tests for IronVault

use ironvault_core::{
    bip39::MnemonicManager,
    wallet::{Wallet, ScriptType},
    Network,
    backup::{BackupManager, BackupMetadata},
    miniscript::{PolicyBuilder, MiniscriptCompiler},
};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::{PrivateKey, PublicKey};

#[test]
fn test_wallet_creation_and_derivation() {
    // Test mnemonic generation
    let mnemonic = MnemonicManager::generate(24).unwrap();
    assert_eq!(mnemonic.words().len(), 24);
    
    // Create wallet from mnemonic
    let wallet = Wallet::from_mnemonic(
        mnemonic.phrase(),
        "",
        Network::Testnet,
    ).unwrap();
    
    // Derive addresses for different script types
    let legacy = wallet.get_address(ScriptType::Legacy, 0, 0, 0).unwrap();
    assert!(legacy.to_string().starts_with("m") || legacy.to_string().starts_with("n"));
    
    let nested = wallet.get_address(ScriptType::NestedSegwit, 0, 0, 0).unwrap();
    assert!(nested.to_string().starts_with("2"));
    
    let native = wallet.get_address(ScriptType::NativeSegwit, 0, 0, 0).unwrap();
    assert!(native.to_string().starts_with("tb1q"));
    
    let taproot = wallet.get_address(ScriptType::Taproot, 0, 0, 0).unwrap();
    assert!(taproot.to_string().starts_with("tb1p"));
}

#[test]
fn test_deterministic_derivation() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let wallet = Wallet::from_mnemonic(mnemonic, "", Network::Bitcoin).unwrap();
    
    // Test known address derivation (BIP-84)
    let addr = wallet.get_address(ScriptType::NativeSegwit, 0, 0, 0).unwrap();
    assert_eq!(addr.to_string(), "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
}

#[test]
fn test_backup_and_restore() {
    // Create a wallet
    let mnemonic = MnemonicManager::generate(12).unwrap();
    let wallet = Wallet::from_mnemonic(mnemonic.phrase(), "", Network::Bitcoin).unwrap();
    
    // Create backup
    let mut manager = BackupManager::new();
    let metadata = BackupMetadata {
        name: "Test Wallet".to_string(),
        derivation_paths: vec!["m/84'/0'/0'".to_string()],
        network: "bitcoin".to_string(),
        sequence: 1,
    };
    
    let xpriv = wallet.master_key(Network::Bitcoin).unwrap();
    let backup = manager.create_backup(&xpriv, "test_password", metadata).unwrap();
    
    // Restore from backup
    let restored = manager.restore_backup(&backup, "test_password").unwrap();
    
    // Verify restoration
    let secp = Secp256k1::new();
    assert_eq!(restored.fingerprint(&secp), xpriv.fingerprint(&secp));
}

#[test]
fn test_miniscript_compilation() {
    let secp = Secp256k1::new();
    let secret1 = SecretKey::from_slice(&[0x01; 32]).unwrap();
    let secret2 = SecretKey::from_slice(&[0x02; 32]).unwrap();
    let secret3 = SecretKey::from_slice(&[0x03; 32]).unwrap();
    
    let pk1 = PrivateKey::new(secret1, Network::Bitcoin).public_key(&secp);
    let pk2 = PrivateKey::new(secret2, Network::Bitcoin).public_key(&secp);
    let pk3 = PrivateKey::new(secret3, Network::Bitcoin).public_key(&secp);
    
    // Test 2-of-3 multisig policy
    let policy = PolicyBuilder::multisig_2_of_3(pk1, pk2, pk3);
    let miniscript = MiniscriptCompiler::compile(&policy).unwrap();
    let script = MiniscriptCompiler::to_script(&miniscript).unwrap();
    
    // Script should be non-empty
    assert!(!script.is_empty());
}

#[test]
fn test_inheritance_policy() {
    let secp = Secp256k1::new();
    let owner_secret = SecretKey::from_slice(&[0x04; 32]).unwrap();
    let heir_secret = SecretKey::from_slice(&[0x05; 32]).unwrap();
    
    let owner = PrivateKey::new(owner_secret, Network::Bitcoin).public_key(&secp);
    let heir = PrivateKey::new(heir_secret, Network::Bitcoin).public_key(&secp);
    
    // Create inheritance policy (owner OR heir after 1 year)
    let policy = PolicyBuilder::inheritance(owner, heir, 52560); // ~365 days
    let miniscript = MiniscriptCompiler::compile(&policy).unwrap();
    let script = MiniscriptCompiler::to_script(&miniscript).unwrap();
    
    assert!(!script.is_empty());
}

#[test]
fn test_mnemonic_validation() {
    // Valid mnemonic
    let valid = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    assert!(MnemonicManager::validate(valid));
    
    // Invalid checksum
    let invalid = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
    assert!(!MnemonicManager::validate(invalid));
    
    // Invalid word
    let invalid_word = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon xyz";
    assert!(!MnemonicManager::validate(invalid_word));
}

#[test]
fn test_slip39_shares() {
    use ironvault_core::slip39::{Slip39, ShareConfig};
    
    let secret = b"this is my secret seed phrase!!!"; // 32 bytes
    let config = ShareConfig {
        threshold: 2,
        total_shares: 3,
        identifier: 1234,
    };
    
    // Generate shares
    let shares = Slip39::split_secret(secret, &config).unwrap();
    assert_eq!(shares.len(), 3);
    
    // Recover from any 2 shares
    let recovered = Slip39::combine_shares(&shares[0..2]).unwrap();
    assert_eq!(recovered.as_slice(), secret);
    
    // Also works with different combination
    let recovered2 = Slip39::combine_shares(&shares[1..3]).unwrap();
    assert_eq!(recovered2.as_slice(), secret);
}

#[test]
fn test_multisig_coordinator() {
    use ironvault_core::multisig::{MultisigBuilder, PsbtCoordinator};
    use bitcoin::bip32::{ExtendedPrivKey, Fingerprint};
    use bitcoin::psbt::Psbt;
    
    // Create test keys
    let xprv1 = ExtendedPrivKey::new_master(Network::Bitcoin, &[0x01; 32]).unwrap();
    let xprv2 = ExtendedPrivKey::new_master(Network::Bitcoin, &[0x02; 32]).unwrap();
    let xprv3 = ExtendedPrivKey::new_master(Network::Bitcoin, &[0x03; 32]).unwrap();
    
    let secp = Secp256k1::new();
    
    // Build 2-of-3 multisig
    let config = MultisigBuilder::new()
        .threshold(2)
        .add_cosigner(
            "Alice".to_string(),
            xprv1.fingerprint(&secp),
            xprv1.to_pub(&secp),
            "m/48'/0'/0'/2'".parse().unwrap(),
        )
        .add_cosigner(
            "Bob".to_string(),
            xprv2.fingerprint(&secp),
            xprv2.to_pub(&secp),
            "m/48'/0'/0'/2'".parse().unwrap(),
        )
        .add_cosigner(
            "Charlie".to_string(),
            xprv3.fingerprint(&secp),
            xprv3.to_pub(&secp),
            "m/48'/0'/0'/2'".parse().unwrap(),
        )
        .network(Network::Bitcoin)
        .build()
        .unwrap();
    
    assert_eq!(config.threshold, 2);
    assert_eq!(config.total, 3);
    
    // Test address derivation
    let address = config.derive_address(0, 0).unwrap();
    assert!(address.to_string().starts_with("bc1"));
}

#[test] 
fn test_taproot_key_generation() {
    use ironvault_core::taproot::TaprootKey;
    use bitcoin::secp256k1::SecretKey;
    
    let secret = SecretKey::from_slice(&[0x01; 32]).unwrap();
    let taproot_key = TaprootKey::new(secret, Network::Bitcoin);
    
    // Generate simple address
    let address = taproot_key.simple_address();
    assert!(address.to_string().starts_with("bc1p"));
    
    // Test with script tree
    let script1 = bitcoin::ScriptBuf::from_bytes(vec![0x51]); // OP_1
    let script2 = bitcoin::ScriptBuf::from_bytes(vec![0x52]); // OP_2
    
    let (address_with_scripts, spend_info) = taproot_key
        .address_with_scripts(vec![script1, script2])
        .unwrap();
    
    assert!(address_with_scripts.to_string().starts_with("bc1p"));
    assert!(spend_info.merkle_root().is_some());
}