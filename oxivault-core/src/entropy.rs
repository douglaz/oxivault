//! Entropy generation methods for creating secure mnemonics
//!
//! Provides multiple methods for generating entropy from various sources:
//! - Dice rolls (6-sided dice)
//! - Coin flips (binary entropy)
//! - Card draws (deck of cards)
//! - Custom hex input

use crate::{Error, Result};
use sha2::{Digest, Sha256};

#[cfg(not(feature = "std"))]
use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

/// Entropy source types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EntropySource {
    /// 6-sided dice rolls
    Dice,
    /// Coin flips (heads/tails)
    CoinFlips,
    /// Playing card draws
    Cards,
    /// Raw hex string
    Hex,
    /// System random number generator
    System,
}

/// Dice roll value (1-6)
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DiceRoll(u8);

impl DiceRoll {
    /// Create a new dice roll (1-6)
    pub fn new(value: u8) -> Result<Self> {
        if !(1..=6).contains(&value) {
            return Err(Error::InvalidEntropy("Dice value must be 1-6".into()));
        }
        Ok(Self(value))
    }

    /// Get the value
    pub fn value(&self) -> u8 {
        self.0
    }
}

/// Coin flip result
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CoinFlip {
    Heads,
    Tails,
}

impl CoinFlip {
    /// Convert to bit value
    pub fn to_bit(&self) -> u8 {
        match self {
            CoinFlip::Heads => 1,
            CoinFlip::Tails => 0,
        }
    }

    /// Parse from character (H/h for heads, T/t for tails)
    pub fn from_char(c: char) -> Result<Self> {
        match c.to_ascii_lowercase() {
            'h' | '1' => Ok(CoinFlip::Heads),
            't' | '0' => Ok(CoinFlip::Tails),
            _ => Err(Error::InvalidEntropy("Invalid coin flip character".into())),
        }
    }
}

/// Playing card for entropy
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PlayingCard {
    /// Suit: 0=Clubs, 1=Diamonds, 2=Hearts, 3=Spades
    suit: u8,
    /// Rank: 1=Ace, 2-10=Number cards, 11=Jack, 12=Queen, 13=King
    rank: u8,
}

impl PlayingCard {
    /// Create a new playing card
    pub fn new(suit: u8, rank: u8) -> Result<Self> {
        if suit > 3 {
            return Err(Error::InvalidEntropy("Invalid suit (0-3)".into()));
        }
        if !(1..=13).contains(&rank) {
            return Err(Error::InvalidEntropy("Invalid rank (1-13)".into()));
        }
        Ok(Self { suit, rank })
    }

    /// Get card index (0-51)
    pub fn index(&self) -> u8 {
        self.suit * 13 + (self.rank - 1)
    }

    /// Parse from string notation (e.g., "AS" for Ace of Spades)
    pub fn from_str(s: &str) -> Result<Self> {
        if s.len() < 2 {
            return Err(Error::InvalidEntropy("Card notation too short".into()));
        }

        let chars: Vec<char> = s.chars().collect();

        // Check for "10" special case
        let (rank, suit_idx) = if s.starts_with("10") {
            (10u8, 2usize)
        } else {
            // Parse single character rank
            let rank = match chars[0].to_ascii_uppercase() {
                'A' => 1,
                '2'..='9' => chars[0] as u8 - b'0',
                'T' => 10,
                'J' => 11,
                'Q' => 12,
                'K' => 13,
                _ => return Err(Error::InvalidEntropy("Invalid card rank".into())),
            };
            (rank, 1)
        };

        // Parse suit
        if suit_idx >= chars.len() {
            return Err(Error::InvalidEntropy(
                "Missing suit in card notation".into(),
            ));
        }
        let suit_char = chars[suit_idx];

        let suit = match suit_char.to_ascii_uppercase() {
            'C' => 0, // Clubs
            'D' => 1, // Diamonds
            'H' => 2, // Hearts
            'S' => 3, // Spades
            _ => return Err(Error::InvalidEntropy("Invalid card suit".into())),
        };

        Self::new(suit, rank)
    }
}

/// Entropy generator for creating secure random data
pub struct EntropyGenerator;

impl EntropyGenerator {
    /// Generate entropy from dice rolls
    /// Requires at least 50 rolls for 128 bits of entropy (12-word mnemonic)
    /// or 99 rolls for 256 bits (24-word mnemonic)
    pub fn from_dice_rolls(rolls: &[DiceRoll]) -> Result<Vec<u8>> {
        if rolls.len() < 50 {
            return Err(Error::InvalidEntropy(
                "Need at least 50 dice rolls for 128-bit entropy".into(),
            ));
        }

        // Convert dice rolls to a byte array for hashing
        let mut input = Vec::with_capacity(rolls.len());
        for roll in rolls {
            input.push(roll.value());
        }

        // Generate entropy using double SHA-256
        Ok(Self::hash_to_entropy(&input))
    }

    /// Generate entropy from coin flips
    /// Requires at least 128 flips for 128 bits of entropy (12-word mnemonic)
    /// or 256 flips for 256 bits (24-word mnemonic)
    pub fn from_coin_flips(flips: &[CoinFlip]) -> Result<Vec<u8>> {
        if flips.len() < 128 {
            return Err(Error::InvalidEntropy(
                "Need at least 128 coin flips for 128-bit entropy".into(),
            ));
        }

        // Pack bits into bytes
        let mut bytes = Vec::new();
        for chunk in flips.chunks(8) {
            let mut byte = 0u8;
            for (i, flip) in chunk.iter().enumerate() {
                byte |= flip.to_bit() << (7 - i);
            }
            bytes.push(byte);
        }

        // Generate entropy using double SHA-256
        Ok(Self::hash_to_entropy(&bytes))
    }

    /// Generate entropy from playing cards
    /// Requires a shuffled deck (52 cards) for entropy generation
    pub fn from_card_deck(cards: &[PlayingCard]) -> Result<Vec<u8>> {
        if cards.len() != 52 {
            return Err(Error::InvalidEntropy(
                "Need exactly 52 cards for entropy generation".into(),
            ));
        }

        // Verify no duplicates
        let mut seen = [false; 52];
        for card in cards {
            let idx = card.index() as usize;
            if seen[idx] {
                return Err(Error::InvalidEntropy("Duplicate card detected".into()));
            }
            seen[idx] = true;
        }

        // Convert card sequence to bytes
        let mut input = Vec::with_capacity(cards.len());
        for card in cards {
            input.push(card.index());
        }

        // Generate entropy using double SHA-256
        Ok(Self::hash_to_entropy(&input))
    }

    /// Generate entropy from hex string
    pub fn from_hex_string(hex: &str) -> Result<Vec<u8>> {
        let hex = hex.trim().replace(" ", "").replace(":", "");

        if hex.len() < 32 {
            return Err(Error::InvalidEntropy(
                "Need at least 32 hex characters (16 bytes) for 128-bit entropy".into(),
            ));
        }

        // Parse hex to bytes
        let mut bytes = Vec::new();
        for chunk in hex.as_bytes().chunks(2) {
            if chunk.len() != 2 {
                return Err(Error::InvalidEntropy("Odd number of hex characters".into()));
            }

            let high = Self::hex_char_to_nibble(chunk[0] as char)?;
            let low = Self::hex_char_to_nibble(chunk[1] as char)?;
            bytes.push((high << 4) | low);
        }

        // Generate entropy using double SHA-256
        Ok(Self::hash_to_entropy(&bytes))
    }

    /// Parse a sequence of dice rolls from a string (e.g., "123456")
    pub fn parse_dice_string(s: &str) -> Result<Vec<DiceRoll>> {
        let mut rolls = Vec::new();
        for c in s.chars() {
            if c.is_whitespace() {
                continue;
            }
            match c {
                '1'..='6' => {
                    let value = c as u8 - b'0';
                    rolls.push(DiceRoll::new(value)?);
                }
                _ => return Err(Error::InvalidEntropy("Invalid dice value".into())),
            }
        }
        Ok(rolls)
    }

    /// Parse a sequence of coin flips from a string (e.g., "HHTTHHT" or "1100110")
    pub fn parse_coin_string(s: &str) -> Result<Vec<CoinFlip>> {
        let mut flips = Vec::new();
        for c in s.chars() {
            if c.is_whitespace() {
                continue;
            }
            flips.push(CoinFlip::from_char(c)?);
        }
        Ok(flips)
    }

    /// Parse a deck of cards from a string (e.g., "AS KH 2C 3D...")
    pub fn parse_card_string(s: &str) -> Result<Vec<PlayingCard>> {
        let mut cards = Vec::new();
        for card_str in s.split_whitespace() {
            cards.push(PlayingCard::from_str(card_str)?);
        }
        Ok(cards)
    }

    /// Mix user entropy with system RNG for enhanced security
    ///
    /// This combines user-provided entropy (dice, coins, etc.) with
    /// system random data to ensure cryptographic security even if
    /// the user's entropy source has biases.
    #[cfg(feature = "std")]
    pub fn mix_with_system_rng(user_entropy: &[u8]) -> Result<Vec<u8>> {
        use crate::rng::{EntropyMixer, RandomSource, SecureRng};

        let mut mixer = EntropyMixer::new();
        let mut rng = SecureRng::new();

        // Mix hardware RNG with user entropy
        mixer.mix_sources(&mut rng, Some(user_entropy))?;

        // Extract final entropy (32 bytes for 256-bit security)
        let mut output = vec![0u8; 32];
        mixer.random_bytes(&mut output)?;

        Ok(output)
    }

    /// Create mnemonic-compatible entropy (with correct length)
    ///
    /// Ensures the entropy is the right length for BIP-39:
    /// - 16 bytes (128 bits) for 12-word mnemonic
    /// - 24 bytes (192 bits) for 18-word mnemonic
    /// - 32 bytes (256 bits) for 24-word mnemonic
    pub fn to_mnemonic_entropy(entropy: &[u8], word_count: usize) -> Result<Vec<u8>> {
        let entropy_bytes = match word_count {
            12 => 16,
            18 => 24,
            24 => 32,
            _ => {
                return Err(Error::InvalidEntropy(
                    "Invalid word count (use 12, 18, or 24)".into(),
                ))
            }
        };

        // If entropy is already the right size, use it directly
        if entropy.len() == entropy_bytes {
            return Ok(entropy.to_vec());
        }

        // Otherwise, hash it to get consistent size
        let hashed = Self::hash_to_entropy(entropy);
        Ok(hashed[..entropy_bytes].to_vec())
    }

    /// Hash input data to entropy using double SHA-256
    fn hash_to_entropy(input: &[u8]) -> Vec<u8> {
        let hash1 = Sha256::digest(input);
        let hash2 = Sha256::digest(hash1);
        hash2.to_vec()
    }

    /// Convert hex character to nibble (4 bits)
    fn hex_char_to_nibble(c: char) -> Result<u8> {
        match c.to_ascii_lowercase() {
            '0'..='9' => Ok(c as u8 - b'0'),
            'a'..='f' => Ok(c as u8 - b'a' + 10),
            _ => Err(Error::InvalidEntropy("Invalid hex character".into())),
        }
    }
}

/// Get hardware entropy from the secure element or RNG
/// This is used by the backup module for generating salts
pub fn get_hardware_entropy(buffer: &mut [u8]) -> Result<()> {
    #[cfg(feature = "std")]
    {
        // Use system RNG when std is available
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        rng.fill_bytes(buffer);
        Ok(())
    }

    #[cfg(not(feature = "std"))]
    {
        // In embedded, this would use the hardware RNG
        // For now, use a deterministic fill for no_std builds
        // Real implementation would use hardware RNG peripheral
        for (i, byte) in buffer.iter_mut().enumerate() {
            *byte = ((i * 31 + 17) % 256) as u8;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dice_rolls() -> Result<()> {
        let rolls = vec![
            DiceRoll::new(1)?,
            DiceRoll::new(2)?,
            DiceRoll::new(3)?,
            DiceRoll::new(4)?,
            DiceRoll::new(5)?,
            DiceRoll::new(6)?,
        ];

        for (i, roll) in rolls.iter().enumerate() {
            assert_eq!(roll.value(), (i + 1) as u8);
        }

        // Test invalid dice value
        assert!(DiceRoll::new(0).is_err());
        assert!(DiceRoll::new(7).is_err());

        Ok(())
    }

    #[test]
    fn test_coin_flips() -> Result<()> {
        assert_eq!(CoinFlip::Heads.to_bit(), 1);
        assert_eq!(CoinFlip::Tails.to_bit(), 0);

        assert_eq!(CoinFlip::from_char('H')?, CoinFlip::Heads);
        assert_eq!(CoinFlip::from_char('h')?, CoinFlip::Heads);
        assert_eq!(CoinFlip::from_char('1')?, CoinFlip::Heads);

        assert_eq!(CoinFlip::from_char('T')?, CoinFlip::Tails);
        assert_eq!(CoinFlip::from_char('t')?, CoinFlip::Tails);
        assert_eq!(CoinFlip::from_char('0')?, CoinFlip::Tails);

        assert!(CoinFlip::from_char('X').is_err());

        Ok(())
    }

    #[test]
    fn test_playing_cards() -> Result<()> {
        // Test Ace of Spades
        let ace_spades = PlayingCard::new(3, 1)?;
        assert_eq!(ace_spades.index(), 39);

        // Test parsing
        assert_eq!(PlayingCard::from_str("AS")?.index(), 39);
        assert_eq!(PlayingCard::from_str("2C")?.index(), 1);
        assert_eq!(PlayingCard::from_str("KH")?.index(), 38);
        assert_eq!(PlayingCard::from_str("10D")?.index(), 22);
        assert_eq!(PlayingCard::from_str("TD")?.index(), 22);

        // Test invalid cards
        assert!(PlayingCard::new(4, 1).is_err());
        assert!(PlayingCard::new(0, 14).is_err());

        Ok(())
    }

    #[test]
    fn test_dice_entropy() -> Result<()> {
        // Create 99 dice rolls for 256-bit entropy
        let mut rolls = Vec::new();
        for _ in 0..99 {
            rolls.push(DiceRoll::new(((rolls.len() % 6) + 1) as u8)?);
        }

        let entropy = EntropyGenerator::from_dice_rolls(&rolls)?;
        assert_eq!(entropy.len(), 32); // 256 bits

        // Test insufficient rolls
        let short_rolls = vec![DiceRoll::new(1)?; 49];
        assert!(EntropyGenerator::from_dice_rolls(&short_rolls).is_err());

        Ok(())
    }

    #[test]
    fn test_coin_entropy() -> Result<()> {
        // Create 256 coin flips
        let mut flips = Vec::new();
        for i in 0..256 {
            flips.push(if i % 2 == 0 {
                CoinFlip::Heads
            } else {
                CoinFlip::Tails
            });
        }

        let entropy = EntropyGenerator::from_coin_flips(&flips)?;
        assert_eq!(entropy.len(), 32); // 256 bits

        // Test insufficient flips
        let short_flips = vec![CoinFlip::Heads; 127];
        assert!(EntropyGenerator::from_coin_flips(&short_flips).is_err());

        Ok(())
    }

    #[test]
    fn test_parse_dice_string() -> Result<()> {
        let rolls = EntropyGenerator::parse_dice_string("123456 111222")?;
        assert_eq!(rolls.len(), 12);
        assert_eq!(rolls[0].value(), 1);
        assert_eq!(rolls[5].value(), 6);
        assert_eq!(rolls[6].value(), 1);

        // Test invalid input
        assert!(EntropyGenerator::parse_dice_string("1234567").is_err());
        assert!(EntropyGenerator::parse_dice_string("123a56").is_err());

        Ok(())
    }

    #[test]
    fn test_parse_coin_string() -> Result<()> {
        let flips = EntropyGenerator::parse_coin_string("HHTTHT 101010")?;
        assert_eq!(flips.len(), 12);
        assert_eq!(flips[0], CoinFlip::Heads);
        assert_eq!(flips[2], CoinFlip::Tails);
        assert_eq!(flips[6], CoinFlip::Heads);

        Ok(())
    }

    #[test]
    fn test_hex_entropy() -> Result<()> {
        let hex = "deadbeef".repeat(8); // 32 bytes
        let entropy = EntropyGenerator::from_hex_string(&hex)?;
        assert_eq!(entropy.len(), 32);

        // Test with spaces and colons (common formatting)
        let formatted = "de:ad:be:ef de ad be ef".repeat(4);
        let entropy2 = EntropyGenerator::from_hex_string(&formatted)?;
        assert_eq!(entropy2.len(), 32);

        // Test insufficient length
        assert!(EntropyGenerator::from_hex_string("deadbeef").is_err());

        Ok(())
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_entropy_mixing() -> Result<()> {
        // Create user entropy from dice
        let rolls = vec![DiceRoll::new(1)?; 99];
        let user_entropy = EntropyGenerator::from_dice_rolls(&rolls)?;

        // Mix with system RNG
        let mixed = EntropyGenerator::mix_with_system_rng(&user_entropy)?;
        assert_eq!(mixed.len(), 32);

        // Verify it's different from just the user entropy
        assert_ne!(mixed, user_entropy);

        // Mix same user entropy again - should get different result due to system RNG
        let mixed2 = EntropyGenerator::mix_with_system_rng(&user_entropy)?;
        assert_ne!(mixed, mixed2);

        Ok(())
    }

    #[test]
    fn test_mnemonic_entropy() -> Result<()> {
        let input = vec![0x42u8; 50]; // Some arbitrary input

        // Test 12-word mnemonic (128 bits)
        let entropy12 = EntropyGenerator::to_mnemonic_entropy(&input, 12)?;
        assert_eq!(entropy12.len(), 16);

        // Test 18-word mnemonic (192 bits)
        let entropy18 = EntropyGenerator::to_mnemonic_entropy(&input, 18)?;
        assert_eq!(entropy18.len(), 24);

        // Test 24-word mnemonic (256 bits)
        let entropy24 = EntropyGenerator::to_mnemonic_entropy(&input, 24)?;
        assert_eq!(entropy24.len(), 32);

        // Test invalid word count
        assert!(EntropyGenerator::to_mnemonic_entropy(&input, 15).is_err());

        // Test exact size pass-through
        let exact = vec![0x42u8; 16];
        let result = EntropyGenerator::to_mnemonic_entropy(&exact, 12)?;
        assert_eq!(result, exact);

        Ok(())
    }
}
