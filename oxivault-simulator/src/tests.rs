//! Unit tests for OxiVault simulator

#[cfg(test)]
mod tests {
    use oxivault_core::{
        bip39::MnemonicManager,
        wallet::{Wallet, ScriptType},
        Network,
    };
    
    #[test]
    fn test_mnemonic_generation_12_words() {
        let mnemonic = MnemonicManager::generate(12).expect("Failed to generate mnemonic");
        assert_eq!(mnemonic.words().len(), 12);
        assert!(MnemonicManager::validate(&mnemonic.phrase()));
    }
    
    #[test]
    fn test_mnemonic_generation_24_words() {
        let mnemonic = MnemonicManager::generate(24).expect("Failed to generate mnemonic");
        assert_eq!(mnemonic.words().len(), 24);
        assert!(MnemonicManager::validate(&mnemonic.phrase()));
    }
    
    #[test]
    fn test_mnemonic_validation() {
        // Valid test mnemonic
        let valid = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert!(MnemonicManager::validate(valid));
        
        // Invalid checksum
        let invalid = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        assert!(!MnemonicManager::validate(invalid));
    }
    
    #[test]
    fn test_wallet_creation_from_mnemonic() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet = Wallet::from_mnemonic(mnemonic, "", Network::Bitcoin)
            .expect("Failed to create wallet");
        
        // Test that wallet can derive addresses
        let addr = wallet.get_address(ScriptType::NativeSegwit, 0, 0, 0)
            .expect("Failed to derive address");
        
        // Known address for this test mnemonic
        assert_eq!(addr.to_string(), "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    }
    
    #[test]
    fn test_address_derivation_all_types() {
        let mnemonic = MnemonicManager::generate(12).expect("Failed to generate mnemonic");
        let wallet = Wallet::from_mnemonic(&mnemonic.phrase(), "", Network::Testnet)
            .expect("Failed to create wallet");
        
        // Test Legacy (P2PKH)
        let legacy = wallet.get_address(ScriptType::Legacy, 0, 0, 0)
            .expect("Failed to derive legacy address");
        assert!(legacy.to_string().starts_with("m") || legacy.to_string().starts_with("n"));
        
        // Test Nested Segwit (P2SH-P2WPKH)
        let nested = wallet.get_address(ScriptType::NestedSegwit, 0, 0, 0)
            .expect("Failed to derive nested segwit address");
        assert!(nested.to_string().starts_with("2"));
        
        // Test Native Segwit (P2WPKH)
        let native = wallet.get_address(ScriptType::NativeSegwit, 0, 0, 0)
            .expect("Failed to derive native segwit address");
        assert!(native.to_string().starts_with("tb1q"));
        
        // Test Taproot (P2TR)
        let taproot = wallet.get_address(ScriptType::Taproot, 0, 0, 0)
            .expect("Failed to derive taproot address");
        assert!(taproot.to_string().starts_with("tb1p"));
    }
    
    #[test]
    fn test_multiple_addresses_from_same_wallet() {
        let wallet = Wallet::from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "",
            Network::Bitcoin,
        ).expect("Failed to create wallet");
        
        // Derive multiple addresses
        let addr1 = wallet.get_address(ScriptType::NativeSegwit, 0, 0, 0).unwrap();
        let addr2 = wallet.get_address(ScriptType::NativeSegwit, 0, 0, 1).unwrap();
        let addr3 = wallet.get_address(ScriptType::NativeSegwit, 0, 0, 2).unwrap();
        
        // Verify they're all different
        assert_ne!(addr1.to_string(), addr2.to_string());
        assert_ne!(addr2.to_string(), addr3.to_string());
        assert_ne!(addr1.to_string(), addr3.to_string());
        
        // Verify first address matches expected
        assert_eq!(addr1.to_string(), "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    }
    
    #[test]
    fn test_change_addresses() {
        let wallet = Wallet::from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "",
            Network::Bitcoin,
        ).expect("Failed to create wallet");
        
        // External address (change = 0)
        let external = wallet.get_address(ScriptType::NativeSegwit, 0, 0, 0).unwrap();
        
        // Internal address (change = 1)
        let internal = wallet.get_address(ScriptType::NativeSegwit, 0, 1, 0).unwrap();
        
        // Should be different
        assert_ne!(external.to_string(), internal.to_string());
    }
    
    #[test]
    fn test_different_accounts() {
        let wallet = Wallet::from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "",
            Network::Bitcoin,
        ).expect("Failed to create wallet");
        
        // Account 0
        let account0 = wallet.get_address(ScriptType::NativeSegwit, 0, 0, 0).unwrap();
        
        // Account 1
        let account1 = wallet.get_address(ScriptType::NativeSegwit, 1, 0, 0).unwrap();
        
        // Should be different
        assert_ne!(account0.to_string(), account1.to_string());
    }
    
    #[test]
    fn test_network_separation() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        
        // Bitcoin mainnet wallet
        let mainnet_wallet = Wallet::from_mnemonic(mnemonic, "", Network::Bitcoin)
            .expect("Failed to create mainnet wallet");
        let mainnet_addr = mainnet_wallet.get_address(ScriptType::NativeSegwit, 0, 0, 0).unwrap();
        
        // Bitcoin testnet wallet
        let testnet_wallet = Wallet::from_mnemonic(mnemonic, "", Network::Testnet)
            .expect("Failed to create testnet wallet");
        let testnet_addr = testnet_wallet.get_address(ScriptType::NativeSegwit, 0, 0, 0).unwrap();
        
        // Addresses should have different prefixes
        assert!(mainnet_addr.to_string().starts_with("bc1"));
        assert!(testnet_addr.to_string().starts_with("tb1"));
    }
    
    #[test]
    fn test_passphrase_support() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        
        // Wallet without passphrase
        let wallet_no_pass = Wallet::from_mnemonic(mnemonic, "", Network::Bitcoin)
            .expect("Failed to create wallet");
        let addr_no_pass = wallet_no_pass.get_address(ScriptType::NativeSegwit, 0, 0, 0).unwrap();
        
        // Wallet with passphrase
        let wallet_with_pass = Wallet::from_mnemonic(mnemonic, "test_passphrase", Network::Bitcoin)
            .expect("Failed to create wallet with passphrase");
        let addr_with_pass = wallet_with_pass.get_address(ScriptType::NativeSegwit, 0, 0, 0).unwrap();
        
        // Different passphrases should produce different addresses
        assert_ne!(addr_no_pass.to_string(), addr_with_pass.to_string());
    }
}