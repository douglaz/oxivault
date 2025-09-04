//! Terminal User Interface for OxiVault simulator

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    Frame, Terminal,
};
use std::io;

use oxivault_core::{
    bip39::MnemonicManager,
    psbt_parser::{PsbtAnalysis as CorePsbtAnalysis, PsbtParser},
    wallet::{ScriptType, Wallet},
    Network,
};
use oxivault_qr::{AsciiQrRenderer, BBQrEncoder, EncodingType, FileType, QrGenerator};

/// Application state
pub struct App {
    /// Current screen
    pub screen: Screen,
    /// Generated mnemonic
    pub mnemonic: Option<String>,
    /// Derived addresses
    pub addresses: Vec<String>,
    /// Current menu selection
    pub selected_index: usize,
    /// Input buffer
    pub input: String,
    /// Status message
    pub status: String,
    /// Should quit
    pub should_quit: bool,
    /// QR code display data
    pub qr_display: Option<String>,
    /// BBQr parts for multi-part display
    pub bbqr_parts: Vec<String>,
    /// Current BBQr part index
    pub bbqr_index: usize,
    /// Current PSBT for inspection/signing
    pub current_psbt: Option<Vec<u8>>,
    /// PSBT analysis results
    pub psbt_analysis: Option<PsbtAnalysis>,
}

/// PSBT analysis results
#[derive(Clone, Debug)]
pub struct PsbtAnalysis {
    pub inputs: Vec<InputInfo>,
    pub outputs: Vec<OutputInfo>,
    pub total_input: u64,
    pub total_output: u64,
    pub fee: u64,
    pub is_complete: bool,
    pub signatures_needed: usize,
    pub signatures_present: usize,
}

#[derive(Clone, Debug)]
pub struct InputInfo {
    pub txid: String,
    pub vout: u32,
    pub value: Option<u64>,
    pub signed: bool,
    pub script_type: String,
}

#[derive(Clone, Debug)]
pub struct OutputInfo {
    pub address: String,
    pub value: u64,
    pub is_change: bool,
}

/// Different screens in the app
#[derive(Debug, Clone, PartialEq)]
pub enum Screen {
    MainMenu,
    GenerateMnemonic,
    ShowMnemonic,
    DeriveAddresses,
    ShowAddresses,
    ImportMnemonic,
    QrOperations,
    ShowQr,
    ShowBBQr,
    ImportQr,
    PsbtMenu,
    PsbtImport,
    PsbtInspector,
    PsbtSign,
    About,
}

impl Default for App {
    fn default() -> Self {
        Self {
            screen: Screen::MainMenu,
            mnemonic: None,
            addresses: Vec::new(),
            selected_index: 0,
            input: String::new(),
            status: "Welcome to OxiVault Simulator".to_string(),
            should_quit: false,
            qr_display: None,
            bbqr_parts: Vec::new(),
            bbqr_index: 0,
            current_psbt: None,
            psbt_analysis: None,
        }
    }
}

impl App {
    /// Run the TUI application
    pub fn run() -> io::Result<()> {
        // Setup terminal
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        // Create app and run
        let mut app = App::default();
        let res = app.run_loop(&mut terminal);

        // Restore terminal
        disable_raw_mode()?;
        execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )?;
        terminal.show_cursor()?;

        res
    }

    fn run_loop<B: Backend>(&mut self, terminal: &mut Terminal<B>) -> io::Result<()> {
        loop {
            terminal.draw(|f| self.draw(f))?;

            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match self.screen {
                        Screen::MainMenu => self.handle_main_menu(key.code),
                        Screen::GenerateMnemonic => self.handle_generate_mnemonic(key.code),
                        Screen::ShowMnemonic => self.handle_show_mnemonic(key.code),
                        Screen::DeriveAddresses => self.handle_derive_addresses(key.code),
                        Screen::ShowAddresses => self.handle_show_addresses(key.code),
                        Screen::ImportMnemonic => self.handle_import_mnemonic(key.code),
                        Screen::QrOperations => self.handle_qr_operations(key.code),
                        Screen::ImportQr => self.handle_import_qr(key.code),
                        Screen::ShowQr => self.handle_show_qr(key.code),
                        Screen::ShowBBQr => self.handle_show_bbqr(key.code),
                        Screen::About => self.handle_about(key.code),
                        Screen::PsbtMenu => self.handle_psbt_menu(key.code),
                        Screen::PsbtImport => self.handle_psbt_import(key.code),
                        Screen::PsbtInspector => self.handle_psbt_inspector(key.code),
                        Screen::PsbtSign => self.handle_psbt_sign(key.code),
                    }
                }
            }

            if self.should_quit {
                return Ok(());
            }
        }
    }

    fn draw(&mut self, f: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(3), // Title
                Constraint::Min(10),   // Content
                Constraint::Length(3), // Status
            ])
            .split(f.area());

        // Title
        let title = Paragraph::new("OxiVault Hardware Wallet Simulator")
            .style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL));
        f.render_widget(title, chunks[0]);

        // Content based on screen
        match self.screen {
            Screen::MainMenu => self.draw_main_menu(f, chunks[1]),
            Screen::GenerateMnemonic => self.draw_generate_mnemonic(f, chunks[1]),
            Screen::ShowMnemonic => self.draw_show_mnemonic(f, chunks[1]),
            Screen::DeriveAddresses => self.draw_derive_addresses(f, chunks[1]),
            Screen::ShowAddresses => self.draw_show_addresses(f, chunks[1]),
            Screen::ImportMnemonic => self.draw_import_mnemonic(f, chunks[1]),
            Screen::QrOperations => self.draw_qr_operations(f, chunks[1]),
            Screen::ImportQr => self.draw_import_qr(f, chunks[1]),
            Screen::ShowQr => self.draw_show_qr(f, chunks[1]),
            Screen::ShowBBQr => self.draw_show_bbqr(f, chunks[1]),
            Screen::About => self.draw_about(f, chunks[1]),
            Screen::PsbtMenu => self.draw_psbt_menu(f, chunks[1]),
            Screen::PsbtImport => self.draw_psbt_import(f, chunks[1]),
            Screen::PsbtInspector => self.draw_psbt_inspector(f, chunks[1]),
            Screen::PsbtSign => self.draw_psbt_sign(f, chunks[1]),
        }

        // Status bar
        let status = Paragraph::new(self.status.clone())
            .style(Style::default().fg(Color::Yellow))
            .block(Block::default().borders(Borders::ALL).title("Status"));
        f.render_widget(status, chunks[2]);
    }

    fn draw_main_menu(&self, f: &mut Frame, area: Rect) {
        let menu_items = vec![
            "1. Generate New Mnemonic",
            "2. Import Mnemonic",
            "3. Derive Addresses",
            "4. QR Code Operations",
            "5. PSBT Operations",
            "6. About",
            "7. Quit (ESC)",
        ];

        let items: Vec<ListItem> = menu_items
            .iter()
            .enumerate()
            .map(|(i, item)| {
                let style = if i == self.selected_index {
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                ListItem::new(*item).style(style)
            })
            .collect();

        let menu = List::new(items)
            .block(Block::default().borders(Borders::ALL).title("Main Menu"))
            .style(Style::default().fg(Color::White));

        f.render_widget(menu, area);
    }

    fn draw_generate_mnemonic(&self, f: &mut Frame, area: Rect) {
        let text = vec![
            Line::from("Select mnemonic length:"),
            Line::from(""),
            Line::from(if self.selected_index == 0 {
                Span::styled("→ 12 words", Style::default().fg(Color::Yellow))
            } else {
                Span::raw("  12 words")
            }),
            Line::from(if self.selected_index == 1 {
                Span::styled("→ 24 words", Style::default().fg(Color::Yellow))
            } else {
                Span::raw("  24 words")
            }),
            Line::from(""),
            Line::from("Press Enter to generate, ESC to go back"),
        ];

        let paragraph = Paragraph::new(text)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Generate Mnemonic"),
            )
            .wrap(Wrap { trim: true });

        f.render_widget(paragraph, area);
    }

    fn draw_show_mnemonic(&self, f: &mut Frame, area: Rect) {
        if let Some(mnemonic) = &self.mnemonic {
            let words: Vec<&str> = mnemonic.split_whitespace().collect();
            let mut lines = vec![Line::from("Your mnemonic phrase:"), Line::from("")];

            for (i, word) in words.iter().enumerate() {
                lines.push(Line::from(format!("{:2}. {}", i + 1, word)));
            }

            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "⚠️  Write this down and keep it safe!",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from("Press Enter to continue, ESC to go back"));

            let paragraph = Paragraph::new(lines)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("Mnemonic Generated"),
                )
                .wrap(Wrap { trim: true });

            f.render_widget(paragraph, area);
        }
    }

    fn draw_derive_addresses(&self, f: &mut Frame, area: Rect) {
        let text = vec![
            Line::from("Select address type:"),
            Line::from(""),
            Line::from(if self.selected_index == 0 {
                Span::styled(
                    "→ Native Segwit (bc1...)",
                    Style::default().fg(Color::Yellow),
                )
            } else {
                Span::raw("  Native Segwit (bc1...)")
            }),
            Line::from(if self.selected_index == 1 {
                Span::styled("→ Taproot (bc1p...)", Style::default().fg(Color::Yellow))
            } else {
                Span::raw("  Taproot (bc1p...)")
            }),
            Line::from(if self.selected_index == 2 {
                Span::styled("→ Legacy (1...)", Style::default().fg(Color::Yellow))
            } else {
                Span::raw("  Legacy (1...)")
            }),
            Line::from(""),
            Line::from("Press Enter to derive, ESC to go back"),
        ];

        let paragraph = Paragraph::new(text)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Derive Addresses"),
            )
            .wrap(Wrap { trim: true });

        f.render_widget(paragraph, area);
    }

    fn draw_show_addresses(&self, f: &mut Frame, area: Rect) {
        let mut lines = vec![Line::from("Derived addresses:"), Line::from("")];

        for (i, addr) in self.addresses.iter().enumerate() {
            lines.push(Line::from(format!("m/84'/0'/0'/0/{}: {}", i, addr)));
        }

        lines.push(Line::from(""));
        lines.push(Line::from("Press ESC to go back"));

        let paragraph = Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title("Addresses"))
            .wrap(Wrap { trim: true });

        f.render_widget(paragraph, area);
    }

    fn draw_import_mnemonic(&self, f: &mut Frame, area: Rect) {
        let text = vec![
            Line::from("Enter your mnemonic phrase:"),
            Line::from(""),
            Line::from(self.input.clone()),
            Line::from(""),
            Line::from("Press Enter to import, ESC to cancel"),
        ];

        let paragraph = Paragraph::new(text)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Import Mnemonic"),
            )
            .wrap(Wrap { trim: true });

        f.render_widget(paragraph, area);
    }

    fn draw_about(&self, f: &mut Frame, area: Rect) {
        let text = vec![
            Line::from("OxiVault - Next-Generation Rust Hardware Wallet"),
            Line::from(""),
            Line::from("A modern, secure, and efficient Bitcoin hardware wallet"),
            Line::from("implementation in Rust, designed to compete with and"),
            Line::from("surpass existing Python-based solutions."),
            Line::from(""),
            Line::from("Features:"),
            Line::from("• BIP-39 mnemonic generation"),
            Line::from("• BIP-32 HD key derivation"),
            Line::from("• Native Segwit & Taproot support"),
            Line::from("• PSBT transaction signing"),
            Line::from("• 10x smaller than Python implementations"),
            Line::from(""),
            Line::from("Press ESC to go back"),
        ];

        let paragraph = Paragraph::new(text)
            .block(Block::default().borders(Borders::ALL).title("About"))
            .wrap(Wrap { trim: true });

        f.render_widget(paragraph, area);
    }

    fn handle_main_menu(&mut self, key: KeyCode) {
        match key {
            KeyCode::Esc => self.should_quit = true,
            KeyCode::Up => {
                if self.selected_index > 0 {
                    self.selected_index -= 1;
                }
            }
            KeyCode::Down => {
                if self.selected_index < 6 {
                    self.selected_index += 1;
                }
            }
            KeyCode::Enter | KeyCode::Char(' ') => match self.selected_index {
                0 => {
                    self.screen = Screen::GenerateMnemonic;
                    self.selected_index = 0;
                }
                1 => {
                    self.screen = Screen::ImportMnemonic;
                    self.input.clear();
                }
                2 => {
                    if self.mnemonic.is_some() {
                        self.screen = Screen::DeriveAddresses;
                        self.selected_index = 0;
                    } else {
                        self.status = "Please generate or import a mnemonic first".to_string();
                    }
                }
                3 => {
                    self.screen = Screen::QrOperations;
                    self.selected_index = 0;
                }
                4 => {
                    self.screen = Screen::PsbtMenu;
                    self.selected_index = 0;
                }
                5 => self.screen = Screen::About,
                6 => self.should_quit = true,
                _ => {}
            },
            KeyCode::Char('1') => {
                self.screen = Screen::GenerateMnemonic;
                self.selected_index = 0;
            }
            KeyCode::Char('2') => {
                self.screen = Screen::ImportMnemonic;
                self.input.clear();
            }
            KeyCode::Char('3') => {
                if self.mnemonic.is_some() {
                    self.screen = Screen::DeriveAddresses;
                    self.selected_index = 0;
                } else {
                    self.status = "Please generate or import a mnemonic first".to_string();
                }
            }
            KeyCode::Char('4') => {
                self.screen = Screen::QrOperations;
                self.selected_index = 0;
            }
            KeyCode::Char('5') => {
                self.screen = Screen::PsbtMenu;
                self.selected_index = 0;
            }
            KeyCode::Char('6') => self.screen = Screen::About,
            KeyCode::Char('7') => self.should_quit = true,
            _ => {}
        }
    }

    fn handle_generate_mnemonic(&mut self, key: KeyCode) {
        match key {
            KeyCode::Esc => {
                self.screen = Screen::MainMenu;
                self.selected_index = 0;
            }
            KeyCode::Up => {
                if self.selected_index > 0 {
                    self.selected_index -= 1;
                }
            }
            KeyCode::Down => {
                if self.selected_index < 1 {
                    self.selected_index += 1;
                }
            }
            KeyCode::Enter => {
                let word_count = if self.selected_index == 0 { 12 } else { 24 };
                match MnemonicManager::generate(word_count) {
                    Ok(manager) => {
                        self.mnemonic = Some(manager.phrase());
                        self.status = format!("Generated {} word mnemonic", word_count);
                        self.screen = Screen::ShowMnemonic;
                    }
                    Err(e) => {
                        self.status = format!("Error: {:?}", e);
                    }
                }
            }
            _ => {}
        }
    }

    fn handle_show_mnemonic(&mut self, key: KeyCode) {
        match key {
            KeyCode::Esc => {
                self.screen = Screen::GenerateMnemonic;
            }
            KeyCode::Enter => {
                self.screen = Screen::MainMenu;
                self.selected_index = 0;
            }
            _ => {}
        }
    }

    fn handle_derive_addresses(&mut self, key: KeyCode) {
        match key {
            KeyCode::Esc => {
                self.screen = Screen::MainMenu;
                self.selected_index = 0;
            }
            KeyCode::Up => {
                if self.selected_index > 0 {
                    self.selected_index -= 1;
                }
            }
            KeyCode::Down => {
                if self.selected_index < 2 {
                    self.selected_index += 1;
                }
            }
            KeyCode::Enter => {
                if let Some(mnemonic) = &self.mnemonic {
                    let script_type = match self.selected_index {
                        0 => ScriptType::NativeSegwit,
                        1 => ScriptType::Taproot,
                        2 => ScriptType::Legacy,
                        _ => ScriptType::NativeSegwit,
                    };

                    match Wallet::from_mnemonic(mnemonic, "", Network::Bitcoin) {
                        Ok(wallet) => {
                            self.addresses.clear();
                            for i in 0..5 {
                                match wallet.get_address(script_type, 0, 0, i) {
                                    Ok(addr) => self.addresses.push(addr.to_string()),
                                    Err(e) => {
                                        self.status = format!("Error deriving address: {:?}", e);
                                        return;
                                    }
                                }
                            }
                            self.status = format!(
                                "Derived 5 {} addresses",
                                match script_type {
                                    ScriptType::NativeSegwit => "Native Segwit",
                                    ScriptType::Taproot => "Taproot",
                                    ScriptType::Legacy => "Legacy",
                                    _ => "Unknown",
                                }
                            );
                            self.screen = Screen::ShowAddresses;
                        }
                        Err(e) => {
                            self.status = format!("Error creating wallet: {:?}", e);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn handle_show_addresses(&mut self, key: KeyCode) {
        if key == KeyCode::Esc {
            self.screen = Screen::DeriveAddresses;
            self.selected_index = 0;
        }
    }

    fn handle_import_mnemonic(&mut self, key: KeyCode) {
        match key {
            KeyCode::Esc => {
                self.screen = Screen::MainMenu;
                self.selected_index = 1;
            }
            KeyCode::Enter => {
                if MnemonicManager::validate(&self.input) {
                    self.mnemonic = Some(self.input.clone());
                    self.status = "Mnemonic imported successfully".to_string();
                    self.screen = Screen::MainMenu;
                    self.selected_index = 0;
                } else {
                    self.status = "Invalid mnemonic phrase".to_string();
                }
            }
            KeyCode::Backspace => {
                self.input.pop();
            }
            KeyCode::Char(c) => {
                self.input.push(c);
            }
            _ => {}
        }
    }

    fn handle_about(&mut self, key: KeyCode) {
        if key == KeyCode::Esc {
            self.screen = Screen::MainMenu;
            self.selected_index = 4;
        }
    }

    fn handle_qr_operations(&mut self, key: KeyCode) {
        match key {
            KeyCode::Esc => {
                self.screen = Screen::MainMenu;
                self.selected_index = 3;
            }
            KeyCode::Up => {
                if self.selected_index > 0 {
                    self.selected_index -= 1;
                }
            }
            KeyCode::Down => {
                if self.selected_index < 2 {
                    self.selected_index += 1;
                }
            }
            KeyCode::Enter => match self.selected_index {
                0 => {
                    // Show address as QR
                    if !self.addresses.is_empty() {
                        if let Ok(qr) = QrGenerator::generate(&self.addresses[0]) {
                            self.qr_display = Some(AsciiQrRenderer::render_compact(&qr));
                            self.screen = Screen::ShowQr;
                        }
                    } else {
                        self.status = "Generate addresses first".to_string();
                    }
                }
                1 => {
                    // Show mnemonic as BBQr
                    if let Some(ref mnemonic) = self.mnemonic {
                        let encoder = BBQrEncoder::new(FileType::Text, EncodingType::Raw, 100);
                        if let Ok(parts) = encoder.split(mnemonic.as_bytes()) {
                            self.bbqr_parts = parts;
                            self.bbqr_index = 0;
                            self.screen = Screen::ShowBBQr;
                        }
                    } else {
                        self.status = "Generate mnemonic first".to_string();
                    }
                }
                2 => {
                    // Import from QR
                    self.input.clear();
                    self.screen = Screen::ImportQr;
                    self.status =
                        "Paste QR code data or BBQr part (Enter to process, ESC to cancel)"
                            .to_string();
                }
                _ => {}
            },
            _ => {}
        }
    }

    fn handle_show_qr(&mut self, key: KeyCode) {
        match key {
            KeyCode::Esc | KeyCode::Enter => {
                self.screen = Screen::QrOperations;
                self.qr_display = None;
            }
            _ => {}
        }
    }

    fn handle_show_bbqr(&mut self, key: KeyCode) {
        match key {
            KeyCode::Esc => {
                self.screen = Screen::QrOperations;
                self.bbqr_parts.clear();
                self.bbqr_index = 0;
            }
            KeyCode::Right | KeyCode::Char(' ') => {
                if self.bbqr_index < self.bbqr_parts.len() - 1 {
                    self.bbqr_index += 1;
                }
            }
            KeyCode::Left => {
                if self.bbqr_index > 0 {
                    self.bbqr_index -= 1;
                }
            }
            _ => {}
        }
    }

    fn draw_qr_operations(&self, f: &mut Frame, area: Rect) {
        let items = vec![
            if self.selected_index == 0 {
                "→ Display Address as QR"
            } else {
                "  Display Address as QR"
            },
            if self.selected_index == 1 {
                "→ Display Mnemonic as BBQr (animated)"
            } else {
                "  Display Mnemonic as BBQr (animated)"
            },
            if self.selected_index == 2 {
                "→ Import from QR (coming soon)"
            } else {
                "  Import from QR (coming soon)"
            },
        ];

        let mut lines = vec![Line::from("QR Code Operations:"), Line::from("")];

        for item in items {
            lines.push(Line::from(item));
        }

        lines.push(Line::from(""));
        lines.push(Line::from("Press Enter to select, ESC to go back"));

        let paragraph = Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("QR Operations"),
            )
            .wrap(Wrap { trim: true });

        f.render_widget(paragraph, area);
    }

    fn draw_show_qr(&self, f: &mut Frame, area: Rect) {
        if let Some(ref qr_display) = self.qr_display {
            let lines: Vec<Line> = qr_display.lines().map(|l| Line::from(l)).collect();

            let paragraph = Paragraph::new(lines)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("QR Code Display"),
                )
                .alignment(Alignment::Center);

            f.render_widget(paragraph, area);

            // Add instructions at the bottom
            let instructions =
                Paragraph::new("Press Enter or ESC to go back").alignment(Alignment::Center);

            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(0), Constraint::Length(3)].as_ref())
                .split(area);

            f.render_widget(instructions, chunks[1]);
        }
    }

    fn draw_show_bbqr(&self, f: &mut Frame, area: Rect) {
        if !self.bbqr_parts.is_empty() && self.bbqr_index < self.bbqr_parts.len() {
            let part = &self.bbqr_parts[self.bbqr_index];

            // Generate QR for current part
            if let Ok(qr) = QrGenerator::generate(part) {
                let qr_display = AsciiQrRenderer::render_compact(&qr);
                let lines: Vec<Line> = qr_display.lines().map(|l| Line::from(l)).collect();

                let title = format!(
                    "BBQr Part {}/{}",
                    self.bbqr_index + 1,
                    self.bbqr_parts.len()
                );
                let paragraph = Paragraph::new(lines)
                    .block(Block::default().borders(Borders::ALL).title(title))
                    .alignment(Alignment::Center);

                f.render_widget(paragraph, area);

                // Add navigation instructions
                let instructions =
                    Paragraph::new("Use ← → or Space to navigate parts, ESC to go back")
                        .alignment(Alignment::Center);

                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Min(0), Constraint::Length(3)].as_ref())
                    .split(area);

                f.render_widget(instructions, chunks[1]);
            }
        }
    }

    fn handle_import_qr(&mut self, key: KeyCode) {
        match key {
            KeyCode::Esc => {
                self.screen = Screen::QrOperations;
                self.input.clear();
            }
            KeyCode::Enter => {
                if !self.input.is_empty() {
                    // Try to decode the input as QR data
                    if let Ok(decoded) = self.process_qr_import(&self.input.clone()) {
                        self.status = format!("Successfully imported: {}", decoded);
                        self.screen = Screen::QrOperations;
                        self.input.clear();
                    } else {
                        self.status = "Invalid QR code data".to_string();
                    }
                }
            }
            KeyCode::Char(c) => {
                self.input.push(c);
            }
            KeyCode::Backspace => {
                self.input.pop();
            }
            _ => {}
        }
    }

    fn handle_psbt_menu(&mut self, key: KeyCode) {
        match key {
            KeyCode::Esc => {
                self.screen = Screen::MainMenu;
                self.selected_index = 4;
            }
            KeyCode::Up => {
                if self.selected_index > 0 {
                    self.selected_index -= 1;
                }
            }
            KeyCode::Down => {
                if self.selected_index < 2 {
                    self.selected_index += 1;
                }
            }
            KeyCode::Enter => match self.selected_index {
                0 => {
                    self.input.clear();
                    self.screen = Screen::PsbtImport;
                }
                1 => {
                    if self.current_psbt.is_some() {
                        self.screen = Screen::PsbtInspector;
                    } else {
                        self.status = "No PSBT loaded. Import one first.".to_string();
                    }
                }
                2 => {
                    if self.current_psbt.is_some() {
                        self.screen = Screen::PsbtSign;
                    } else {
                        self.status = "No PSBT loaded. Import one first.".to_string();
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }

    fn handle_psbt_import(&mut self, key: KeyCode) {
        match key {
            KeyCode::Esc => {
                self.screen = Screen::PsbtMenu;
                self.input.clear();
            }
            KeyCode::Enter => {
                if !self.input.is_empty() {
                    // Try to parse PSBT using real parser
                    let parser = PsbtParser::new(Network::Bitcoin);
                    match parser.parse_base64(&self.input) {
                        Ok(psbt) => {
                            // Analyze the PSBT
                            match parser.analyze(&psbt) {
                                Ok(analysis) => {
                                    // Convert to TUI analysis format
                                    let inputs: Vec<InputInfo> = analysis
                                        .inputs
                                        .iter()
                                        .map(|i| InputInfo {
                                            txid: i.previous_txid.clone(),
                                            vout: i.previous_vout,
                                            value: i.value,
                                            signed: i.is_signed,
                                            script_type: format!("{:?}", i.script_type),
                                        })
                                        .collect();

                                    let outputs: Vec<OutputInfo> = analysis
                                        .outputs
                                        .iter()
                                        .map(|o| OutputInfo {
                                            address: o.address.clone(),
                                            value: o.value,
                                            is_change: o.is_change,
                                        })
                                        .collect();

                                    self.psbt_analysis = Some(PsbtAnalysis {
                                        inputs,
                                        outputs,
                                        total_input: analysis.total_input_value.unwrap_or(0),
                                        total_output: analysis.total_output_value,
                                        fee: analysis.fee.unwrap_or(0),
                                        is_complete: analysis.is_complete,
                                        signatures_needed: analysis.signatures_required,
                                        signatures_present: analysis.signatures_present,
                                    });

                                    // Store raw PSBT bytes
                                    use base64::{engine::general_purpose::STANDARD, Engine as _};
                                    if let Ok(data) = STANDARD.decode(&self.input) {
                                        self.current_psbt = Some(data);
                                    }

                                    self.status =
                                        "PSBT imported and analyzed successfully".to_string();
                                    self.screen = Screen::PsbtMenu;
                                    self.input.clear();
                                }
                                Err(e) => {
                                    self.status = format!("Failed to analyze PSBT: {:?}", e);
                                }
                            }
                        }
                        Err(e) => {
                            self.status = format!("Invalid PSBT: {:?}", e);
                        }
                    }
                }
            }
            KeyCode::Backspace => {
                self.input.pop();
            }
            KeyCode::Char(c) => {
                self.input.push(c);
            }
            _ => {}
        }
    }

    fn handle_psbt_inspector(&mut self, key: KeyCode) {
        if key == KeyCode::Esc {
            self.screen = Screen::PsbtMenu;
        }
    }

    fn handle_psbt_sign(&mut self, key: KeyCode) {
        match key {
            KeyCode::Esc => {
                self.screen = Screen::PsbtMenu;
            }
            KeyCode::Enter => {
                if self.current_psbt.is_some() && self.mnemonic.is_some() {
                    // In a real implementation, this would sign the PSBT
                    self.status = "PSBT signed successfully (simulated)".to_string();

                    // Update analysis to show signed
                    if let Some(ref mut analysis) = self.psbt_analysis {
                        analysis.signatures_present = 1;
                        analysis.is_complete = true;
                        for input in &mut analysis.inputs {
                            input.signed = true;
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn draw_import_qr(&self, f: &mut Frame, area: Rect) {
        let content = vec![
            Line::from("Import from QR Code"),
            Line::from(""),
            Line::from("Paste QR code data:"),
            Line::from(Span::styled(
                &self.input,
                Style::default().fg(Color::Yellow),
            )),
            Line::from(""),
            Line::from("Supported formats:"),
            Line::from("- BIP-39 Mnemonic words"),
            Line::from("- PSBT (base64 encoded)"),
            Line::from("- BBQr multi-part codes"),
            Line::from(""),
            Line::from("Press Enter to process, ESC to cancel"),
        ];

        let paragraph = Paragraph::new(content)
            .block(Block::default().borders(Borders::ALL).title("QR Import"))
            .wrap(Wrap { trim: true });

        f.render_widget(paragraph, area);
    }

    fn draw_psbt_menu(&self, f: &mut Frame, area: Rect) {
        let items = vec![
            if self.selected_index == 0 {
                "→ Import PSBT"
            } else {
                "  Import PSBT"
            },
            if self.selected_index == 1 {
                "→ Inspect PSBT"
            } else {
                "  Inspect PSBT"
            },
            if self.selected_index == 2 {
                "→ Sign PSBT"
            } else {
                "  Sign PSBT"
            },
        ];

        let content: Vec<Line> = vec![Line::from("PSBT Operations"), Line::from("")]
            .into_iter()
            .chain(items.iter().map(|&item| Line::from(item)))
            .chain(
                vec![
                    Line::from(""),
                    Line::from("Press Enter to select, ESC to go back"),
                ]
                .into_iter(),
            )
            .collect();

        let paragraph = Paragraph::new(content)
            .block(Block::default().borders(Borders::ALL).title("PSBT Menu"))
            .wrap(Wrap { trim: true });

        f.render_widget(paragraph, area);
    }

    fn draw_psbt_import(&self, f: &mut Frame, area: Rect) {
        let content = vec![
            Line::from("Import PSBT"),
            Line::from(""),
            Line::from("Enter base64-encoded PSBT:"),
            Line::from(Span::styled(
                &self.input,
                Style::default().fg(Color::Yellow),
            )),
            Line::from(""),
            Line::from("Press Enter to import, ESC to cancel"),
        ];

        let paragraph = Paragraph::new(content)
            .block(Block::default().borders(Borders::ALL).title("PSBT Import"))
            .wrap(Wrap { trim: true });

        f.render_widget(paragraph, area);
    }

    fn draw_psbt_inspector(&self, f: &mut Frame, area: Rect) {
        let mut lines = vec![Line::from("PSBT Inspector"), Line::from("")];

        if let Some(ref analysis) = self.psbt_analysis {
            lines.push(Line::from(format!(
                "Total Input: {} sats",
                analysis.total_input
            )));
            lines.push(Line::from(format!(
                "Total Output: {} sats",
                analysis.total_output
            )));
            lines.push(Line::from(format!("Fee: {} sats", analysis.fee)));
            lines.push(Line::from(format!(
                "Complete: {}",
                if analysis.is_complete { "Yes" } else { "No" }
            )));
            lines.push(Line::from(format!(
                "Signatures: {}/{}",
                analysis.signatures_present, analysis.signatures_needed
            )));
            lines.push(Line::from(""));
            lines.push(Line::from("Inputs:"));

            for (i, input) in analysis.inputs.iter().enumerate() {
                let value_str = input.value.map_or("unknown".to_string(), |v| v.to_string());
                lines.push(Line::from(format!(
                    "  #{}: {} ({} sats)",
                    i, input.script_type, value_str
                )));
            }

            lines.push(Line::from(""));
            lines.push(Line::from("Outputs:"));

            for (i, output) in analysis.outputs.iter().enumerate() {
                lines.push(Line::from(format!(
                    "  #{}: {} ({} sats)",
                    i, output.address, output.value
                )));
            }
        } else {
            lines.push(Line::from("No PSBT loaded"));
        }

        lines.push(Line::from(""));
        lines.push(Line::from("Press ESC to go back"));

        let paragraph = Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("PSBT Inspector"),
            )
            .wrap(Wrap { trim: true });

        f.render_widget(paragraph, area);
    }

    fn draw_psbt_sign(&self, f: &mut Frame, area: Rect) {
        let mut lines = vec![Line::from("Sign PSBT"), Line::from("")];

        if self.current_psbt.is_some() {
            if self.mnemonic.is_some() {
                lines.push(Line::from("Ready to sign transaction"));
                lines.push(Line::from(""));
                lines.push(Line::from("Press Enter to sign, ESC to cancel"));
            } else {
                lines.push(Line::from(Span::styled(
                    "No wallet loaded!",
                    Style::default().fg(Color::Red),
                )));
                lines.push(Line::from(""));
                lines.push(Line::from("Please import or generate a mnemonic first"));
            }
        } else {
            lines.push(Line::from("No PSBT loaded"));
        }

        lines.push(Line::from(""));
        lines.push(Line::from("Press ESC to go back"));

        let paragraph = Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title("Sign PSBT"))
            .wrap(Wrap { trim: true });

        f.render_widget(paragraph, area);
    }

    pub fn process_qr_import(&mut self, data: &str) -> Result<String, String> {
        use oxivault_qr::BBQrDecoder;

        // Check if it's a BBQr part
        if data.starts_with("B$") {
            // Initialize or get existing decoder
            static mut DECODER: Option<BBQrDecoder> = None;

            unsafe {
                if DECODER.is_none() {
                    DECODER = Some(BBQrDecoder::new());
                }

                if let Some(decoder) = &mut DECODER {
                    match decoder.add_part(data) {
                        Ok(_) => {
                            if decoder.is_complete() {
                                match decoder.combine() {
                                    Ok(decoded_data) => {
                                        // Try to process the decoded data
                                        // First try as UTF-8 text (could be mnemonic or JSON)
                                        let result = if let Ok(text) =
                                            String::from_utf8(decoded_data.clone())
                                        {
                                            // Check if it's a mnemonic
                                            let words: Vec<&str> =
                                                text.split_whitespace().collect();
                                            if words.len() >= 12 && words.len() <= 24 {
                                                // Try to validate as mnemonic
                                                match MnemonicManager::from_phrase(&text) {
                                                    Ok(_) => {
                                                        self.mnemonic = Some(text.clone());
                                                        "Mnemonic imported from BBQr".to_string()
                                                    }
                                                    Err(_) => {
                                                        format!(
                                                            "Text data imported: {} bytes",
                                                            decoded_data.len()
                                                        )
                                                    }
                                                }
                                            } else {
                                                format!(
                                                    "Text data imported: {} bytes",
                                                    decoded_data.len()
                                                )
                                            }
                                        } else {
                                            // Binary data - could be PSBT or transaction
                                            format!("Binary data imported: {} bytes (PSBT processing not yet implemented)", decoded_data.len())
                                        };

                                        // Reset decoder for next import
                                        DECODER = None;
                                        return Ok(result);
                                    }
                                    Err(e) => {
                                        DECODER = None;
                                        return Err(format!("Failed to decode BBQr: {}", e));
                                    }
                                }
                            } else {
                                let progress = decoder.progress();
                                return Ok(format!(
                                    "BBQr part added ({}/{})",
                                    progress.0, progress.1
                                ));
                            }
                        }
                        Err(e) => {
                            DECODER = None;
                            return Err(format!("Failed to add BBQr part: {}", e));
                        }
                    }
                }
            }
        }

        // Try as a plain mnemonic
        let words: Vec<&str> = data.split_whitespace().collect();
        if words.len() >= 12 && words.len() <= 24 {
            // Validate mnemonic
            match MnemonicManager::from_phrase(data) {
                Ok(_) => {
                    self.mnemonic = Some(data.to_string());
                    return Ok("Mnemonic imported successfully".to_string());
                }
                Err(_) => {
                    // Not a valid mnemonic, try other formats
                }
            }
        }

        // Try as base64 PSBT
        if data.len() > 10 && !data.contains(' ') {
            // Looks like it could be base64
            return Ok("PSBT import not yet fully implemented".to_string());
        }

        Err("Unrecognized QR code format".to_string())
    }
}
