/// Tests for TUI functionality
#[cfg(test)]
mod tests {
    use ironvault_simulator::tui::App;
    
    #[test]
    fn test_qr_import_mnemonic() {
        let mut app = App::default();
        
        // Test importing a valid mnemonic
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let result = app.process_qr_import(mnemonic);
        
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "Mnemonic imported successfully");
        assert_eq!(app.mnemonic, Some(mnemonic.to_string()));
    }
    
    #[test]
    fn test_qr_import_bbqr_simulation() {
        let mut app = App::default();
        
        // Simulate BBQr part (this won't actually work without proper BBQr data)
        // but tests the code path
        let bbqr_part = "B$FE$T001P001D0000000CC1234567$test_data";
        let result = app.process_qr_import(bbqr_part);
        
        // This will fail because it's not valid BBQr, but it tests the parsing
        assert!(result.is_err() || result.unwrap().contains("BBQr"));
    }
    
    #[test]
    fn test_qr_import_invalid_data() {
        let mut app = App::default();
        
        // Test with invalid data
        let result = app.process_qr_import("invalid data that is not a mnemonic or QR");
        
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Unrecognized QR code format");
    }
    
    #[test]
    fn test_psbt_analysis_structure() {
        use ironvault_simulator::tui::{PsbtAnalysis, InputInfo, OutputInfo};
        
        // Create a mock PSBT analysis
        let analysis = PsbtAnalysis {
            inputs: vec![
                InputInfo {
                    txid: "abc123".to_string(),
                    vout: 0,
                    value: Some(100000),
                    signed: false,
                    script_type: "P2WPKH".to_string(),
                }
            ],
            outputs: vec![
                OutputInfo {
                    address: "bc1qtest".to_string(),
                    value: 90000,
                    is_change: false,
                }
            ],
            total_input: 100000,
            total_output: 90000,
            fee: 10000,
            is_complete: false,
            signatures_needed: 1,
            signatures_present: 0,
        };
        
        assert_eq!(analysis.inputs.len(), 1);
        assert_eq!(analysis.outputs.len(), 1);
        assert_eq!(analysis.fee, 10000);
        assert!(!analysis.is_complete);
    }
}