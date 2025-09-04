//! Comprehensive integration tests for OxiVault Core

use oxivault_core::{
    Result,
    wallet::{Wallet, ScriptType, MultisigWallet},
    bip39::MnemonicManager,
    bip32::{HdWallet, DerivationPaths},
};
use bitcoin::{Network, Address};

const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[test]
fn test_end_to_end_wallet_flow() -> Result<()> {
    // 1. Generate a mnemonic
    let mnemonic = MnemonicManager::generate(12)?;
    assert_eq!(mnemonic.words().len(), 12);
    
    // 2. Create wallet from mnemonic
    let wallet = Wallet::from_mnemonic(&mnemonic.phrase(), "", Network::Testnet)?;
    
    // 3. Derive different address types
    let native_segwit = wallet.get_address(ScriptType::NativeSegwit, 0, 0, 0)?;
    assert!(native_segwit.to_string().starts_with("tb1q")); // testnet bech32
    
    let taproot = wallet.get_address(ScriptType::Taproot, 0, 0, 0)?;
    assert!(taproot.to_string().starts_with("tb1p")); // testnet taproot
    
    let legacy = wallet.get_address(ScriptType::Legacy, 0, 0, 0)?;
    assert!(legacy.to_string().starts_with("m") || legacy.to_string().starts_with("n")); // testnet legacy
    
    // 4. Verify deterministic generation
    let wallet2 = Wallet::from_mnemonic(&mnemonic.phrase(), "", Network::Testnet)?;
    let addr2 = wallet2.get_address(ScriptType::NativeSegwit, 0, 0, 0)?;
    assert_eq!(native_segwit, addr2);
    
    Ok(())
}

#[test]
fn test_multisig_wallet_creation() -> Result<()> {
    // Create 3 wallets for multisig with different valid mnemonics
    let wallet1 = Wallet::from_mnemonic(TEST_MNEMONIC, "", Network::Bitcoin)?;
    let wallet2 = Wallet::from_mnemonic(
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        "",
        Network::Bitcoin
    )?;
    let wallet3 = Wallet::from_mnemonic(
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "",
        Network::Bitcoin
    )?;
    
    // Get account xpubs
    let xpub1 = wallet1.get_account_xpub(ScriptType::NativeSegwit, 0)?;
    let xpub2 = wallet2.get_account_xpub(ScriptType::NativeSegwit, 0)?;
    let xpub3 = wallet3.get_account_xpub(ScriptType::NativeSegwit, 0)?;
    
    // Create 2-of-3 multisig
    let multisig = MultisigWallet::new(2, vec![xpub1, xpub2, xpub3], Network::Bitcoin)?;
    
    // Verify configuration
    let (m, n) = multisig.config();
    assert_eq!(m, 2);
    assert_eq!(n, 3);
    
    // Generate addresses
    let addr1 = multisig.get_address(0, 0)?;
    let addr2 = multisig.get_address(0, 1)?;
    
    // Addresses should be different
    assert_ne!(addr1, addr2);
    
    // Should be P2WSH addresses
    assert!(addr1.to_string().starts_with("bc1q"));
    
    Ok(())
}

#[test]
fn test_bip32_derivation_paths() -> Result<()> {
    let seed = [0x42u8; 64];
    let hd_wallet = HdWallet::from_seed(&seed, Network::Bitcoin)?;
    
    // Test BIP44 path (Legacy)
    let path44 = DerivationPaths::bip44(0, 0, 0, 0)?;
    let key44 = hd_wallet.derive(&path44)?;
    
    // Test BIP49 path (Nested Segwit)
    let path49 = DerivationPaths::bip49(0, 0, 0, 0)?;
    let key49 = hd_wallet.derive(&path49)?;
    
    // Test BIP84 path (Native Segwit)
    let path84 = DerivationPaths::bip84(0, 0, 0, 0)?;
    let key84 = hd_wallet.derive(&path84)?;
    
    // Test BIP86 path (Taproot)
    let path86 = DerivationPaths::bip86(0, 0, 0, 0)?;
    let key86 = hd_wallet.derive(&path86)?;
    
    // Keys should all be different
    assert_ne!(key44.to_priv().to_bytes(), key49.to_priv().to_bytes());
    assert_ne!(key49.to_priv().to_bytes(), key84.to_priv().to_bytes());
    assert_ne!(key84.to_priv().to_bytes(), key86.to_priv().to_bytes());
    
    Ok(())
}

#[test]
fn test_mnemonic_entropy_generation() -> Result<()> {
    // Test entropy generation from bytes
    let input = b"user provided entropy for mnemonic generation";
    let entropy = MnemonicManager::generate_entropy_from_bytes(input);
    assert_eq!(entropy.len(), 32);
    
    // Verify deterministic
    let entropy2 = MnemonicManager::generate_entropy_from_bytes(input);
    assert_eq!(entropy, entropy2);
    
    // Different input should give different entropy
    let entropy3 = MnemonicManager::generate_entropy_from_bytes(b"different input");
    assert_ne!(entropy, entropy3);
    
    Ok(())
}

#[test]
fn test_address_derivation_consistency() -> Result<()> {
    let wallet = Wallet::from_mnemonic(TEST_MNEMONIC, "", Network::Bitcoin)?;
    
    // Generate multiple addresses
    let addresses: Vec<Address> = (0..10)
        .map(|i| wallet.get_address(ScriptType::NativeSegwit, 0, 0, i))
        .collect::<Result<Vec<_>>>()?;
    
    // All should be unique
    for i in 0..addresses.len() {
        for j in i+1..addresses.len() {
            assert_ne!(addresses[i], addresses[j]);
        }
    }
    
    // All should be valid native segwit
    for addr in &addresses {
        assert!(addr.to_string().starts_with("bc1q"));
    }
    
    Ok(())
}

#[test]
fn test_passphrase_affects_seed() -> Result<()> {
    let mnemonic = MnemonicManager::from_phrase(TEST_MNEMONIC)?;
    
    // Different passphrases should generate different seeds
    let seed1 = mnemonic.to_seed_bytes("");
    let seed2 = mnemonic.to_seed_bytes("passphrase123");
    
    assert_ne!(seed1, seed2);
    
    // Same passphrase should generate same seed
    let seed3 = mnemonic.to_seed_bytes("");
    assert_eq!(seed1, seed3);
    
    Ok(())
}

#[test]
fn test_wallet_fingerprint() -> Result<()> {
    let wallet = Wallet::from_mnemonic(TEST_MNEMONIC, "", Network::Bitcoin)?;
    let fingerprint = wallet.master_fingerprint();
    
    // Fingerprint should be consistent
    let wallet2 = Wallet::from_mnemonic(TEST_MNEMONIC, "", Network::Bitcoin)?;
    let fingerprint2 = wallet2.master_fingerprint();
    
    assert_eq!(fingerprint, fingerprint2);
    
    // Different mnemonic should have different fingerprint
    let wallet3 = Wallet::from_mnemonic(
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "",
        Network::Bitcoin
    )?;
    let fingerprint3 = wallet3.master_fingerprint();
    
    assert_ne!(fingerprint, fingerprint3);
    
    Ok(())
}

#[test]
fn test_network_address_formats() -> Result<()> {
    let mnemonic = MnemonicManager::from_phrase(TEST_MNEMONIC)?;
    
    // Bitcoin mainnet
    let wallet_main = Wallet::from_mnemonic(&mnemonic.phrase(), "", Network::Bitcoin)?;
    let addr_main = wallet_main.get_address(ScriptType::NativeSegwit, 0, 0, 0)?;
    assert!(addr_main.to_string().starts_with("bc1"));
    
    // Bitcoin testnet
    let wallet_test = Wallet::from_mnemonic(&mnemonic.phrase(), "", Network::Testnet)?;
    let addr_test = wallet_test.get_address(ScriptType::NativeSegwit, 0, 0, 0)?;
    assert!(addr_test.to_string().starts_with("tb1"));
    
    // Regtest
    let wallet_reg = Wallet::from_mnemonic(&mnemonic.phrase(), "", Network::Regtest)?;
    let addr_reg = wallet_reg.get_address(ScriptType::NativeSegwit, 0, 0, 0)?;
    assert!(addr_reg.to_string().starts_with("bcrt1"));
    
    Ok(())
}