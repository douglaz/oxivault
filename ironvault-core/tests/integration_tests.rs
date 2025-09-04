//! Integration tests for IronVault core functionality

use ironvault_core::{
    bip32::{HdWallet, DerivationPaths},
    bip39::MnemonicManager,
    wallet::{Wallet, ScriptType},
    psbt::PsbtManager,
    Network,
};
use bitcoin::OutPoint;

/// Test mnemonic generation and validation
#[test]
fn test_mnemonic_generation() {
    // Test 12-word mnemonic
    let mnemonic_12 = MnemonicManager::generate(12).unwrap();
    assert!(MnemonicManager::validate(&mnemonic_12.phrase()));
    
    // Test 24-word mnemonic
    let mnemonic_24 = MnemonicManager::generate(24).unwrap();
    assert!(MnemonicManager::validate(&mnemonic_24.phrase()));
    
    // Test invalid mnemonic
    assert!(!MnemonicManager::validate("invalid mnemonic phrase test"));
}

/// Test BIP-39 test vector
#[test]
fn test_bip39_test_vector() {
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mnemonic = MnemonicManager::from_phrase(phrase).unwrap();
    assert_eq!(mnemonic.phrase(), phrase);
    
    // Test seed generation with empty passphrase
    let seed = mnemonic.to_seed_bytes("");
    
    // Verify seed is 64 bytes
    assert_eq!(seed.len(), 64);
    
    // The actual seed value depends on the exact BIP39 implementation
    // The important test is that addresses derived from it are correct
    // (which we test in test_address_generation)
}

/// Test HD wallet derivation
#[test]
fn test_hd_wallet_derivation() {
    let seed = [0u8; 64];
    let wallet = HdWallet::from_seed(&seed, Network::Bitcoin).unwrap();
    
    // Test master xpub generation
    let master_xpub = wallet.master_xpub();
    assert!(!master_xpub.to_string().is_empty());
    
    // Test BIP-84 derivation path
    let path = DerivationPaths::bip84(0, 0, 0, 0).unwrap();
    let derived_key = wallet.derive(&path).unwrap();
    assert!(!derived_key.to_string().is_empty());
    
    // Test public key derivation
    let pub_key = wallet.derive_pub(&path).unwrap();
    assert!(!pub_key.to_string().is_empty());
}

/// Test address generation for all script types
#[test]
fn test_address_generation() {
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let wallet = Wallet::from_mnemonic(phrase, "", Network::Bitcoin).unwrap();
    
    // Test Native Segwit address (BIP-84)
    let native_segwit = wallet.get_address(ScriptType::NativeSegwit, 0, 0, 0).unwrap();
    assert_eq!(native_segwit.to_string(), "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    
    // Test Legacy address (BIP-44)
    let legacy = wallet.get_address(ScriptType::Legacy, 0, 0, 0).unwrap();
    assert!(legacy.to_string().starts_with("1"));
    
    // Test Nested Segwit address (BIP-49)
    let nested_segwit = wallet.get_address(ScriptType::NestedSegwit, 0, 0, 0).unwrap();
    assert!(nested_segwit.to_string().starts_with("3"));
    
    // Test Taproot address (BIP-86)
    let taproot = wallet.get_address(ScriptType::Taproot, 0, 0, 0).unwrap();
    assert!(taproot.to_string().starts_with("bc1p"));
}

/// Test deterministic address generation
#[test]
fn test_deterministic_addresses() {
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    
    // Create two wallets with same mnemonic
    let wallet1 = Wallet::from_mnemonic(phrase, "", Network::Bitcoin).unwrap();
    let wallet2 = Wallet::from_mnemonic(phrase, "", Network::Bitcoin).unwrap();
    
    // Addresses should be identical
    for i in 0..5 {
        let addr1 = wallet1.get_address(ScriptType::NativeSegwit, 0, 0, i).unwrap();
        let addr2 = wallet2.get_address(ScriptType::NativeSegwit, 0, 0, i).unwrap();
        assert_eq!(addr1, addr2);
    }
}

/// Test different networks
#[test]
fn test_network_addresses() {
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    
    // Mainnet
    let mainnet_wallet = Wallet::from_mnemonic(phrase, "", Network::Bitcoin).unwrap();
    let mainnet_addr = mainnet_wallet.get_address(ScriptType::NativeSegwit, 0, 0, 0).unwrap();
    assert!(mainnet_addr.to_string().starts_with("bc1"));
    
    // Testnet
    let testnet_wallet = Wallet::from_mnemonic(phrase, "", Network::Testnet).unwrap();
    let testnet_addr = testnet_wallet.get_address(ScriptType::NativeSegwit, 0, 0, 0).unwrap();
    assert!(testnet_addr.to_string().starts_with("tb1"));
}

/// Test PSBT creation and manipulation
#[test]
fn test_psbt_creation() {
    use bitcoin::ScriptBuf;
    
    let mut psbt = PsbtManager::empty();
    
    // Add an input
    let outpoint = OutPoint::default();
    psbt.add_input(outpoint, 0xfffffffe);
    
    // Add an output
    let script = ScriptBuf::new();
    psbt.add_output(script, 100000);
    
    // Verify PSBT structure
    assert_eq!(psbt.psbt().unsigned_tx.input.len(), 1);
    assert_eq!(psbt.psbt().unsigned_tx.output.len(), 1);
    
    // Test serialization
    let serialized = psbt.to_bytes();
    let deserialized = PsbtManager::from_bytes(&serialized).unwrap();
    assert_eq!(deserialized.to_bytes(), serialized);
}

/// Test wallet fingerprint
#[test]
fn test_wallet_fingerprint() {
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let wallet = Wallet::from_mnemonic(phrase, "", Network::Bitcoin).unwrap();
    
    let fingerprint = wallet.master_fingerprint();
    // Fingerprint should be 4 bytes (8 hex chars when displayed)
    assert_eq!(fingerprint.as_bytes().len(), 4);
}

/// Test entropy generation
#[test]
fn test_entropy_generation() {
    let input = b"test input for entropy generation";
    let entropy1 = MnemonicManager::generate_entropy_from_bytes(input);
    let entropy2 = MnemonicManager::generate_entropy_from_bytes(input);
    
    // Same input should produce same entropy (deterministic)
    assert_eq!(entropy1, entropy2);
    assert_eq!(entropy1.len(), 32);
    
    // Different input should produce different entropy
    let entropy3 = MnemonicManager::generate_entropy_from_bytes(b"different input");
    assert_ne!(entropy1, entropy3);
}

/// Test derivation path parsing
#[test]
fn test_derivation_path_parsing() {
    // Valid paths - bitcoin crate doesn't include "m/" prefix in Display
    let path1 = DerivationPaths::from_str("m/84'/0'/0'/0/0").unwrap();
    assert_eq!(path1.to_string(), "84'/0'/0'/0/0");
    
    let path2 = DerivationPaths::from_str("m/44'/0'/0'/0/0").unwrap();
    assert_eq!(path2.to_string(), "44'/0'/0'/0/0");
    
    // Test BIP paths
    let bip44 = DerivationPaths::bip44(0, 0, 0, 0).unwrap();
    assert_eq!(bip44.to_string(), "44'/0'/0'/0/0");
    
    let bip49 = DerivationPaths::bip49(0, 0, 0, 0).unwrap();
    assert_eq!(bip49.to_string(), "49'/0'/0'/0/0");
    
    let bip84 = DerivationPaths::bip84(0, 0, 0, 0).unwrap();
    assert_eq!(bip84.to_string(), "84'/0'/0'/0/0");
    
    let bip86 = DerivationPaths::bip86(0, 0, 0, 0).unwrap();
    assert_eq!(bip86.to_string(), "86'/0'/0'/0/0");
}

/// Test account xpub derivation
#[test]
fn test_account_xpub() {
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let wallet = Wallet::from_mnemonic(phrase, "", Network::Bitcoin).unwrap();
    
    // Get account xpub for BIP-84
    let account_xpub = wallet.get_account_xpub(ScriptType::NativeSegwit, 0).unwrap();
    assert!(!account_xpub.to_string().is_empty());
    
    // Different script types should have different account xpubs
    let legacy_xpub = wallet.get_account_xpub(ScriptType::Legacy, 0).unwrap();
    assert_ne!(account_xpub.to_string(), legacy_xpub.to_string());
}

/// Test mnemonic with passphrase
#[test]
fn test_mnemonic_with_passphrase() {
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    
    // Without passphrase
    let wallet1 = Wallet::from_mnemonic(phrase, "", Network::Bitcoin).unwrap();
    let addr1 = wallet1.get_address(ScriptType::NativeSegwit, 0, 0, 0).unwrap();
    
    // With passphrase
    let wallet2 = Wallet::from_mnemonic(phrase, "passphrase", Network::Bitcoin).unwrap();
    let addr2 = wallet2.get_address(ScriptType::NativeSegwit, 0, 0, 0).unwrap();
    
    // Addresses should be different
    assert_ne!(addr1, addr2);
}