//! Integration tests for entropy generation

use oxivault_core::{
    bip39::MnemonicManager,
    entropy::{EntropyGenerator, CoinFlip, PlayingCard},
};

#[test]
fn test_dice_to_mnemonic() {
    // Simulate 99 dice rolls (enough for 256-bit entropy)
    let dice_string = "123456".repeat(17); // 102 characters
    let rolls = EntropyGenerator::parse_dice_string(&dice_string).unwrap();
    
    // Generate entropy from dice
    let entropy = EntropyGenerator::from_dice_rolls(&rolls).unwrap();
    
    // Create mnemonic from entropy  
    let mnemonic = MnemonicManager::from_entropy(&entropy).unwrap();
    let phrase = mnemonic.phrase();
    
    // Verify we got a 24-word mnemonic (256 bits / 32 bytes)
    let words: Vec<&str> = phrase.split_whitespace().collect();
    assert_eq!(words.len(), 24);
    
    // Verify the mnemonic is valid
    assert!(MnemonicManager::validate(&phrase));
}

#[test]
fn test_coin_flips_to_mnemonic() {
    // Generate 256 coin flips
    let coin_string = "HT".repeat(128);
    let flips = EntropyGenerator::parse_coin_string(&coin_string).unwrap();
    
    // Generate entropy from coin flips
    let entropy = EntropyGenerator::from_coin_flips(&flips).unwrap();
    
    // Create 24-word mnemonic
    let mnemonic = MnemonicManager::from_entropy(&entropy).unwrap();
    let phrase = mnemonic.phrase();
    
    let words: Vec<&str> = phrase.split_whitespace().collect();
    assert_eq!(words.len(), 24);
    assert!(MnemonicManager::validate(&phrase));
}

#[test]
fn test_hex_to_mnemonic() {
    // Use a known hex string (64 hex chars = 32 bytes)
    let hex = "deadbeefcafe1234567890abcdef0123456789abcdef0123456789abcdef0123";
    
    // Generate entropy from hex
    let entropy = EntropyGenerator::from_hex_string(hex).unwrap();
    assert_eq!(entropy.len(), 32);
    
    // Create mnemonic
    let mnemonic = MnemonicManager::from_entropy(&entropy).unwrap();
    let phrase = mnemonic.phrase();
    
    // Should be 24 words for 256-bit entropy
    let words: Vec<&str> = phrase.split_whitespace().collect();
    assert_eq!(words.len(), 24);
}

#[test]
fn test_12_word_mnemonic_from_dice() {
    // Use 50 dice rolls for 128-bit entropy (12-word mnemonic)
    let dice_string = "123456".repeat(9); // 54 dice rolls
    let rolls = EntropyGenerator::parse_dice_string(&dice_string[..50]).unwrap();
    
    // Generate entropy
    let entropy = EntropyGenerator::from_dice_rolls(&rolls).unwrap();
    
    // Take first 16 bytes for 12-word mnemonic
    let entropy_128 = &entropy[..16];
    let mnemonic = MnemonicManager::from_entropy(entropy_128).unwrap();
    let phrase = mnemonic.phrase();
    
    // Should be 12 words
    let words: Vec<&str> = phrase.split_whitespace().collect();
    assert_eq!(words.len(), 12);
    assert!(MnemonicManager::validate(&phrase));
}

#[test]
fn test_card_deck_entropy() {
    // Create a standard deck of 52 cards in order
    let mut cards = Vec::new();
    
    // Add all cards in order: Clubs, Diamonds, Hearts, Spades
    for suit in 0..4 {
        for rank in 1..=13 {
            cards.push(PlayingCard::new(suit, rank).unwrap());
        }
    }
    
    // Shuffle simulation - just reverse the deck for testing
    cards.reverse();
    
    // Generate entropy from the shuffled deck
    let entropy = EntropyGenerator::from_card_deck(&cards).unwrap();
    assert_eq!(entropy.len(), 32); // Always 256 bits from full deck
    
    // Create mnemonic
    let mnemonic = MnemonicManager::from_entropy(&entropy).unwrap();
    let phrase = mnemonic.phrase();
    
    let words: Vec<&str> = phrase.split_whitespace().collect();
    assert_eq!(words.len(), 24);
    assert!(MnemonicManager::validate(&phrase));
}

#[test]
fn test_deterministic_entropy() {
    // Same input should produce same entropy (and thus same mnemonic)
    let dice1 = "111111222222333333444444555555666666111111222222333333";
    let dice2 = "111111222222333333444444555555666666111111222222333333";
    
    let rolls1 = EntropyGenerator::parse_dice_string(dice1).unwrap();
    let rolls2 = EntropyGenerator::parse_dice_string(dice2).unwrap();
    
    let entropy1 = EntropyGenerator::from_dice_rolls(&rolls1).unwrap();
    let entropy2 = EntropyGenerator::from_dice_rolls(&rolls2).unwrap();
    
    assert_eq!(entropy1, entropy2);
    
    // And should produce same mnemonic
    let mnemonic1 = MnemonicManager::from_entropy(&entropy1).unwrap();
    let mnemonic2 = MnemonicManager::from_entropy(&entropy2).unwrap();
    
    assert_eq!(mnemonic1.phrase(), mnemonic2.phrase());
}

#[test]
fn test_mixed_coin_notation() {
    // Test parsing different coin flip notations
    let mixed = "HHT tth 110 001";
    let flips = EntropyGenerator::parse_coin_string(mixed).unwrap();
    
    assert_eq!(flips.len(), 12);
    assert_eq!(flips[0], CoinFlip::Heads);
    assert_eq!(flips[2], CoinFlip::Tails);
    assert_eq!(flips[3], CoinFlip::Tails);
    assert_eq!(flips[6], CoinFlip::Heads);
    assert_eq!(flips[9], CoinFlip::Tails);
}

#[test]
fn test_card_notation_parsing() {
    // Test various card notations
    let card_string = "AS 2C 10D TD KH QS JC";
    let cards = EntropyGenerator::parse_card_string(card_string).unwrap();
    
    assert_eq!(cards.len(), 7);
    assert_eq!(cards[0].index(), 39); // Ace of Spades
    assert_eq!(cards[1].index(), 1);  // 2 of Clubs
    assert_eq!(cards[2].index(), 22); // 10 of Diamonds
    assert_eq!(cards[3].index(), 22); // Also 10 of Diamonds (T notation)
    assert_eq!(cards[4].index(), 38); // King of Hearts
    assert_eq!(cards[5].index(), 50); // Queen of Spades
    assert_eq!(cards[6].index(), 10); // Jack of Clubs (0*13 + 10)
}