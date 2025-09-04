//! Integration tests for OxiVault project

use oxivault_core::{
    bip39::MnemonicManager,
    wallet::{Wallet, ScriptType},
    Network,
    multisig::{MultisigBuilder, MultisigScriptType},
    miniscript::{PolicyBuilder, MiniscriptCompiler},
    backup::{BackupManager, BackupMetadata},
    slip39::{Slip39, ShareConfig},
    taproot::TaprootKey,
};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::{PrivateKey, PublicKey};
use bitcoin::bip32::{Xpriv, Fingerprint};

#[test]
fn test_complete_wallet_lifecycle() {
    // 1. Generate mnemonic
    let mnemonic = MnemonicManager::generate(24).expect("Failed to generate mnemonic");
    assert_eq!(mnemonic.words().len(), 24);
    
    // 2. Create wallet
    let wallet = Wallet::from_mnemonic(&mnemonic.phrase(), "test_pass", Network::Bitcoin)
        .expect("Failed to create wallet");
    
    // 3. Derive multiple addresses
    for i in 0..10 {
        let addr = wallet.get_address(ScriptType::NativeSegwit, 0, 0, i)
            .expect("Failed to derive address");
        assert!(addr.to_string().starts_with("bc1"));
    }
}

#[test]
fn test_all_script_types() {
    let wallet = Wallet::from_mnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "",
        Network::Bitcoin,
    ).expect("Failed to create wallet");
    
    // Legacy P2PKH
    let legacy = wallet.get_address(ScriptType::Legacy, 0, 0, 0).unwrap();
    assert!(legacy.to_string().starts_with("1"));
    
    // Nested SegWit P2SH-P2WPKH
    let nested = wallet.get_address(ScriptType::NestedSegwit, 0, 0, 0).unwrap();
    assert!(nested.to_string().starts_with("3"));
    
    // Native SegWit P2WPKH
    let native = wallet.get_address(ScriptType::NativeSegwit, 0, 0, 0).unwrap();
    assert_eq!(native.to_string(), "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    
    // Taproot P2TR
    let taproot = wallet.get_address(ScriptType::Taproot, 0, 0, 0).unwrap();
    assert!(taproot.to_string().starts_with("bc1p"));
}

#[test]
fn test_multisig_2_of_3() {
    let secp = Secp256k1::new();
    
    // Create 3 keys
    let xprv1 = Xpriv::new_master(Network::Bitcoin, &[0x01; 32]).unwrap();
    let xprv2 = Xpriv::new_master(Network::Bitcoin, &[0x02; 32]).unwrap();
    let xprv3 = Xpriv::new_master(Network::Bitcoin, &[0x03; 32]).unwrap();
    
    // Build multisig
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
        .script_type(MultisigScriptType::P2wsh)
        .build()
        .expect("Failed to build multisig");
    
    assert_eq!(config.threshold, 2);
    assert_eq!(config.total, 3);
    
    // Derive address
    let address = config.derive_address(0, 0).unwrap();
    assert!(address.to_string().starts_with("bc1"));
}

#[test]
fn test_miniscript_policy_compilation() {
    let secp = Secp256k1::new();
    
    // Create keys
    let secret1 = SecretKey::from_slice(&[0x01; 32]).unwrap();
    let secret2 = SecretKey::from_slice(&[0x02; 32]).unwrap();
    let secret3 = SecretKey::from_slice(&[0x03; 32]).unwrap();
    
    let pk1 = PrivateKey::new(secret1, Network::Bitcoin).public_key(&secp);
    let pk2 = PrivateKey::new(secret2, Network::Bitcoin).public_key(&secp);
    let pk3 = PrivateKey::new(secret3, Network::Bitcoin).public_key(&secp);
    
    // Create 2-of-3 multisig policy
    let policy = PolicyBuilder::multisig_2_of_3(pk1, pk2, pk3);
    
    // Compile to miniscript
    let miniscript = MiniscriptCompiler::compile(&policy).unwrap();
    let script = MiniscriptCompiler::to_script(&miniscript).unwrap();
    
    assert!(!script.is_empty());
}

#[test]
fn test_inheritance_policy() {
    let secp = Secp256k1::new();
    
    let owner_secret = SecretKey::from_slice(&[0x04; 32]).unwrap();
    let heir_secret = SecretKey::from_slice(&[0x05; 32]).unwrap();
    
    let owner = PrivateKey::new(owner_secret, Network::Bitcoin).public_key(&secp);
    let heir = PrivateKey::new(heir_secret, Network::Bitcoin).public_key(&secp);
    
    // Owner can spend immediately, heir can spend after 1 year
    let policy = PolicyBuilder::inheritance(owner, heir, 52560);
    
    let miniscript = MiniscriptCompiler::compile(&policy).unwrap();
    let script = MiniscriptCompiler::to_script(&miniscript).unwrap();
    
    assert!(!script.is_empty());
}

#[test]
fn test_slip39_shamir_secret_sharing() {
    let secret = b"this is my secret seed phrase!!!"; // 32 bytes
    
    let config = ShareConfig {
        threshold: 2,
        total_shares: 3,
        identifier: 1234,
    };
    
    // Split into shares
    let shares = Slip39::split_secret(secret, &config).unwrap();
    assert_eq!(shares.len(), 3);
    
    // Recover from any 2 shares
    let recovered1 = Slip39::combine_shares(&shares[0..2]).unwrap();
    assert_eq!(recovered1.as_slice(), secret);
    
    let recovered2 = Slip39::combine_shares(&shares[1..3]).unwrap();
    assert_eq!(recovered2.as_slice(), secret);
}

#[test]
fn test_backup_encryption() {
    let mnemonic = MnemonicManager::generate(12).unwrap();
    let wallet = Wallet::from_mnemonic(&mnemonic.phrase(), "", Network::Bitcoin).unwrap();
    
    let mut manager = BackupManager::new();
    let metadata = BackupMetadata {
        name: "Test Wallet".to_string(),
        derivation_paths: vec!["m/84'/0'/0'".to_string()],
        network: "bitcoin".to_string(),
        sequence: 1,
    };
    
    let xpriv = wallet.master_key(Network::Bitcoin).unwrap();
    let backup = manager.create_backup(&xpriv, "strong_password", metadata).unwrap();
    
    // Restore from backup
    let restored = manager.restore_backup(&backup, "strong_password").unwrap();
    
    let secp = Secp256k1::new();
    assert_eq!(restored.fingerprint(&secp), xpriv.fingerprint(&secp));
}

#[test]
fn test_wrong_password_backup_restore() {
    let mut manager = BackupManager::new();
    let metadata = BackupMetadata {
        name: "Test".to_string(),
        derivation_paths: vec![],
        network: "bitcoin".to_string(),
        sequence: 1,
    };
    
    let xpriv = Xpriv::new_master(Network::Bitcoin, &[0x42; 32]).unwrap();
    let backup = manager.create_backup(&xpriv, "correct_password", metadata).unwrap();
    
    // Should fail with wrong password
    let result = manager.restore_backup(&backup, "wrong_password");
    assert!(result.is_err());
}

#[test]
fn test_taproot_key_generation() {
    let secret = SecretKey::from_slice(&[0x01; 32]).unwrap();
    let taproot_key = TaprootKey::new(secret, Network::Bitcoin);
    
    let address = taproot_key.simple_address();
    assert!(address.to_string().starts_with("bc1p"));
}

#[test]
fn test_taproot_with_script_tree() {
    let secret = SecretKey::from_slice(&[0x01; 32]).unwrap();
    let taproot_key = TaprootKey::new(secret, Network::Bitcoin);
    
    // Create some scripts
    let script1 = bitcoin::ScriptBuf::from_bytes(vec![0x51]); // OP_1
    let script2 = bitcoin::ScriptBuf::from_bytes(vec![0x52]); // OP_2
    
    let (address, spend_info) = taproot_key
        .address_with_scripts(vec![script1, script2])
        .unwrap();
    
    assert!(address.to_string().starts_with("bc1p"));
    assert!(spend_info.merkle_root().is_some());
}

#[test]
fn test_mnemonic_with_different_word_counts() {
    // Test 12, 15, 18, 21, 24 words
    for word_count in &[12, 15, 18, 21, 24] {
        let mnemonic = MnemonicManager::generate(*word_count).unwrap();
        assert_eq!(mnemonic.words().len(), *word_count);
        assert!(MnemonicManager::validate(&mnemonic.phrase()));
    }
}

#[test]
fn test_invalid_mnemonic_validation() {
    // Wrong checksum
    let invalid1 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
    assert!(!MnemonicManager::validate(invalid1));
    
    // Invalid word
    let invalid2 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon xyz";
    assert!(!MnemonicManager::validate(invalid2));
    
    // Wrong word count
    let invalid3 = "abandon abandon abandon";
    assert!(!MnemonicManager::validate(invalid3));
}

#[test]
fn test_bip32_derivation_paths() {
    let wallet = Wallet::from_mnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "",
        Network::Bitcoin,
    ).unwrap();
    
    // BIP-44 (Legacy)
    let bip44 = wallet.get_address(ScriptType::Legacy, 0, 0, 0).unwrap();
    
    // BIP-49 (Nested SegWit)
    let bip49 = wallet.get_address(ScriptType::NestedSegwit, 0, 0, 0).unwrap();
    
    // BIP-84 (Native SegWit)
    let bip84 = wallet.get_address(ScriptType::NativeSegwit, 0, 0, 0).unwrap();
    
    // BIP-86 (Taproot)
    let bip86 = wallet.get_address(ScriptType::Taproot, 0, 0, 0).unwrap();
    
    // All should be different
    assert_ne!(bip44.to_string(), bip49.to_string());
    assert_ne!(bip49.to_string(), bip84.to_string());
    assert_ne!(bip84.to_string(), bip86.to_string());
}

#[test]
fn test_passphrase_creates_different_wallet() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    
    let wallet1 = Wallet::from_mnemonic(mnemonic, "", Network::Bitcoin).unwrap();
    let wallet2 = Wallet::from_mnemonic(mnemonic, "passphrase", Network::Bitcoin).unwrap();
    
    let addr1 = wallet1.get_address(ScriptType::NativeSegwit, 0, 0, 0).unwrap();
    let addr2 = wallet2.get_address(ScriptType::NativeSegwit, 0, 0, 0).unwrap();
    
    assert_ne!(addr1.to_string(), addr2.to_string());
}

#[test]
fn test_network_separation() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    
    let mainnet = Wallet::from_mnemonic(mnemonic, "", Network::Bitcoin).unwrap();
    let testnet = Wallet::from_mnemonic(mnemonic, "", Network::Testnet).unwrap();
    let signet = Wallet::from_mnemonic(mnemonic, "", Network::Signet).unwrap();
    let regtest = Wallet::from_mnemonic(mnemonic, "", Network::Regtest).unwrap();
    
    let m_addr = mainnet.get_address(ScriptType::NativeSegwit, 0, 0, 0).unwrap();
    let t_addr = testnet.get_address(ScriptType::NativeSegwit, 0, 0, 0).unwrap();
    let s_addr = signet.get_address(ScriptType::NativeSegwit, 0, 0, 0).unwrap();
    let r_addr = regtest.get_address(ScriptType::NativeSegwit, 0, 0, 0).unwrap();
    
    assert!(m_addr.to_string().starts_with("bc1"));
    assert!(t_addr.to_string().starts_with("tb1"));
    assert!(s_addr.to_string().starts_with("tb1"));
    assert!(r_addr.to_string().starts_with("bcrt1"));
}

#[test]
fn test_hardened_derivation() {
    let wallet = Wallet::from_mnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "",
        Network::Bitcoin,
    ).unwrap();
    
    // Account 0 (hardened)
    let account0 = wallet.get_address(ScriptType::NativeSegwit, 0, 0, 0).unwrap();
    
    // Account 1 (hardened)
    let account1 = wallet.get_address(ScriptType::NativeSegwit, 1, 0, 0).unwrap();
    
    // Account 2147483647 (max hardened)
    let account_max = wallet.get_address(ScriptType::NativeSegwit, 2147483647, 0, 0).unwrap();
    
    // All should be different
    assert_ne!(account0.to_string(), account1.to_string());
    assert_ne!(account1.to_string(), account_max.to_string());
}

#[test]
fn test_deterministic_address_generation() {
    // Same mnemonic should always generate same addresses
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    
    for _ in 0..10 {
        let wallet = Wallet::from_mnemonic(mnemonic, "", Network::Bitcoin).unwrap();
        let addr = wallet.get_address(ScriptType::NativeSegwit, 0, 0, 0).unwrap();
        assert_eq!(addr.to_string(), "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    }
}

#[test]
fn test_large_address_index() {
    let wallet = Wallet::from_mnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "",
        Network::Bitcoin,
    ).unwrap();
    
    // Test with large but valid index
    let addr = wallet.get_address(ScriptType::NativeSegwit, 0, 0, 999999).unwrap();
    assert!(addr.to_string().starts_with("bc1"));
}

#[test]
fn test_multiple_accounts_and_change() {
    let wallet = Wallet::from_mnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "",
        Network::Bitcoin,
    ).unwrap();
    
    let addresses = vec![
        wallet.get_address(ScriptType::NativeSegwit, 0, 0, 0).unwrap(), // Account 0, external
        wallet.get_address(ScriptType::NativeSegwit, 0, 1, 0).unwrap(), // Account 0, internal
        wallet.get_address(ScriptType::NativeSegwit, 1, 0, 0).unwrap(), // Account 1, external
        wallet.get_address(ScriptType::NativeSegwit, 1, 1, 0).unwrap(), // Account 1, internal
    ];
    
    // All addresses should be unique
    for i in 0..addresses.len() {
        for j in (i + 1)..addresses.len() {
            assert_ne!(addresses[i].to_string(), addresses[j].to_string());
        }
    }
}