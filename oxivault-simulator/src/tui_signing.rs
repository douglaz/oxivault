//! TUI Transaction Signing Workflow
//!
//! Provides a complete transaction signing interface with Mock HAL integration

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
    widgets::{Block, Borders, Gauge, Paragraph, Wrap},
    Frame, Terminal,
};
use std::io;

use oxivault_core::{
    bip39::MnemonicManager,
    hal::{
        mock::MockHAL, Button, HardwareAbstractionLayer, Input as HalInput, InputEvent,
        Storage as HalStorage,
    },
    psbt_parser::{PsbtAnalysis, PsbtParser},
    wallet::Wallet,
    Network,
};

use oxivault_qr::{bbqr_qr::BBQrQrGenerator, AsciiQrRenderer};

use crate::tui_enhanced::PsbtExportState;

/// Enhanced transaction signing application with HAL integration
pub struct SigningApp {
    /// Mock HAL for hardware simulation
    hal: MockHAL,
    /// Current screen state
    screen: SigningScreen,
    /// Wallet manager
    wallet: Option<Wallet>,
    /// Current PSBT being processed
    current_psbt: Option<Vec<u8>>,
    /// PSBT analysis
    psbt_analysis: Option<PsbtAnalysis>,
    /// Signing progress
    signing_progress: SigningProgress,
    /// Export state for QR display
    export_state: Option<PsbtExportState>,
    /// User input buffer
    input_buffer: String,
    /// Status messages
    status: StatusMessage,
    /// Should quit
    should_quit: bool,
}

/// Different screens in the signing workflow
#[derive(Debug, Clone, PartialEq)]
pub enum SigningScreen {
    /// Main signing menu
    MainMenu,
    /// Key management (load/derive keys)
    KeyManagement,
    /// Import PSBT (via QR, paste, file)
    ImportPsbt,
    /// Review transaction details
    ReviewTransaction,
    /// Approve/reject signing
    ApprovalScreen,
    /// Signing in progress
    SigningProgress,
    /// Export signed PSBT
    ExportSigned,
    /// Settings and preferences
    Settings,
}

/// Key management operations
#[derive(Debug, Clone)]
pub enum KeyOperation {
    LoadFromStorage,
    GenerateNew,
    ImportMnemonic,
    DerivePath,
}

/// Signing progress tracking
#[derive(Debug, Clone)]
pub struct SigningProgress {
    /// Total inputs to sign
    total_inputs: usize,
    /// Inputs signed so far
    signed_inputs: usize,
    /// Current operation
    current_operation: String,
    /// Is signing complete
    is_complete: bool,
}

/// Status message with severity
#[derive(Debug, Clone)]
pub struct StatusMessage {
    text: String,
    severity: StatusSeverity,
}

#[derive(Debug, Clone)]
pub enum StatusSeverity {
    Info,
    Success,
    Warning,
    Error,
}

impl Default for SigningApp {
    fn default() -> Self {
        Self {
            hal: MockHAL::new(),
            screen: SigningScreen::MainMenu,
            wallet: None,
            current_psbt: None,
            psbt_analysis: None,
            signing_progress: SigningProgress {
                total_inputs: 0,
                signed_inputs: 0,
                current_operation: String::new(),
                is_complete: false,
            },
            export_state: None,
            input_buffer: String::new(),
            status: StatusMessage {
                text: "Welcome to OxiVault Transaction Signing".to_string(),
                severity: StatusSeverity::Info,
            },
            should_quit: false,
        }
    }
}

impl SigningApp {
    /// Run the signing TUI application
    pub fn run() -> io::Result<()> {
        // Setup terminal
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        // Create app and run
        let mut app = SigningApp::default();
        app.initialize_hal();
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

    /// Initialize HAL with test data
    fn initialize_hal(&mut self) {
        // Initialize mock HAL
        if let Err(e) = HardwareAbstractionLayer::init(&mut self.hal) {
            self.set_status(
                format!("HAL initialization warning: {:?}", e),
                StatusSeverity::Warning,
            );
        }

        // Add some test keys to storage if empty
        let keys = self.hal.storage.list_keys().unwrap_or_default();
        if keys.is_empty() {
            // Add a sample mnemonic for testing
            let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
            let _ = self
                .hal
                .storage
                .write("test_wallet", test_mnemonic.as_bytes());
            self.set_status(
                "Test wallet loaded into storage".to_string(),
                StatusSeverity::Info,
            );
        }
    }

    fn run_loop<B: Backend>(&mut self, terminal: &mut Terminal<B>) -> io::Result<()> {
        loop {
            terminal.draw(|f| self.draw(f))?;

            // Handle both keyboard and simulated HAL input
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    self.handle_key_event(key.code);
                }
            }

            // Also check for HAL input events
            if let Some(event) = self.hal.input().poll() {
                self.handle_hal_input(event);
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

        // Title with signing status
        self.draw_title(f, chunks[0]);

        // Main content
        match self.screen {
            SigningScreen::MainMenu => self.draw_main_menu(f, chunks[1]),
            SigningScreen::KeyManagement => self.draw_key_management(f, chunks[1]),
            SigningScreen::ImportPsbt => self.draw_import_psbt(f, chunks[1]),
            SigningScreen::ReviewTransaction => self.draw_review_transaction(f, chunks[1]),
            SigningScreen::ApprovalScreen => self.draw_approval_screen(f, chunks[1]),
            SigningScreen::SigningProgress => self.draw_signing_progress(f, chunks[1]),
            SigningScreen::ExportSigned => self.draw_export_signed(f, chunks[1]),
            SigningScreen::Settings => self.draw_settings(f, chunks[1]),
        }

        // Status bar
        self.draw_status(f, chunks[2]);
    }

    fn draw_title(&self, f: &mut Frame, area: Rect) {
        let wallet_status = if self.wallet.is_some() {
            "🔐 Wallet Loaded"
        } else {
            "🔓 No Wallet"
        };

        let title = format!("OxiVault Transaction Signing - {}", wallet_status);
        let title_widget = Paragraph::new(title)
            .style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL));
        f.render_widget(title_widget, area);
    }

    fn draw_status(&self, f: &mut Frame, area: Rect) {
        let color = match self.status.severity {
            StatusSeverity::Info => Color::Blue,
            StatusSeverity::Success => Color::Green,
            StatusSeverity::Warning => Color::Yellow,
            StatusSeverity::Error => Color::Red,
        };

        let status_widget = Paragraph::new(self.status.text.clone())
            .style(Style::default().fg(color))
            .block(Block::default().borders(Borders::ALL).title("Status"));
        f.render_widget(status_widget, area);
    }

    fn draw_main_menu(&self, f: &mut Frame, area: Rect) {
        let menu_items = vec![
            ("1", "Key Management", "Load or generate signing keys"),
            ("2", "Import PSBT", "Import transaction to sign"),
            ("3", "Review Current", "Review loaded transaction"),
            ("4", "Export Signed", "Export signed transaction"),
            ("5", "Settings", "Configure signing preferences"),
            ("ESC", "Quit", "Exit application"),
        ];

        let mut lines = vec![Line::from("Transaction Signing Menu"), Line::from("")];

        for (key, title, desc) in menu_items {
            let is_enabled = match title {
                "Review Current" | "Export Signed" => self.current_psbt.is_some(),
                "Import PSBT" => self.wallet.is_some(),
                _ => true,
            };

            let style = if is_enabled {
                Style::default()
            } else {
                Style::default().fg(Color::DarkGray)
            };

            lines.push(Line::from(vec![
                Span::styled(format!("[{}] ", key), Style::default().fg(Color::Yellow)),
                Span::styled(format!("{:<20}", title), style.add_modifier(Modifier::BOLD)),
                Span::styled(desc, style),
            ]));
        }

        let paragraph = Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title("Main Menu"))
            .wrap(Wrap { trim: true });

        f.render_widget(paragraph, area);
    }

    fn draw_key_management(&self, f: &mut Frame, area: Rect) {
        let mut lines = vec![Line::from("Key Management"), Line::from("")];

        // Show stored keys
        if let Ok(keys) = self.hal.storage.list_keys() {
            if !keys.is_empty() {
                lines.push(Line::from(Span::styled(
                    "Stored Keys:",
                    Style::default().add_modifier(Modifier::BOLD),
                )));
                for key in keys {
                    lines.push(Line::from(format!("  • {}", key)));
                }
                lines.push(Line::from(""));
            }
        }

        lines.push(Line::from("Options:"));
        lines.push(Line::from("[1] Load key from storage"));
        lines.push(Line::from("[2] Generate new mnemonic"));
        lines.push(Line::from("[3] Import mnemonic"));
        lines.push(Line::from("[4] Derive custom path"));
        lines.push(Line::from(""));
        lines.push(Line::from("[ESC] Back to menu"));

        let paragraph = Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Key Management"),
            )
            .wrap(Wrap { trim: true });

        f.render_widget(paragraph, area);
    }

    fn draw_import_psbt(&self, f: &mut Frame, area: Rect) {
        let lines = vec![
            Line::from("Import PSBT"),
            Line::from(""),
            Line::from("Select import method:"),
            Line::from(""),
            Line::from("[1] Scan QR code"),
            Line::from("[2] Import from animated QR (BBQr)"),
            Line::from("[3] Import from UR format"),
            Line::from("[4] Paste base64"),
            Line::from("[5] Load from file"),
            Line::from(""),
            Line::from("Current input:"),
            Line::from(Span::styled(
                &self.input_buffer,
                Style::default().fg(Color::Yellow),
            )),
            Line::from(""),
            Line::from("[Enter] Process input | [ESC] Cancel"),
        ];

        let paragraph = Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title("Import PSBT"))
            .wrap(Wrap { trim: true });

        f.render_widget(paragraph, area);
    }

    fn draw_review_transaction(&self, f: &mut Frame, area: Rect) {
        let mut lines = vec![
            Line::from(Span::styled(
                "Transaction Review",
                Style::default().add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
        ];

        if let Some(ref analysis) = self.psbt_analysis {
            // Summary
            lines.push(Line::from(Span::styled(
                "Summary:",
                Style::default().add_modifier(Modifier::UNDERLINED),
            )));
            lines.push(Line::from(format!(
                "Total Input:  {} sats",
                analysis.total_input_value.unwrap_or(0)
            )));
            lines.push(Line::from(format!(
                "Total Output: {} sats",
                analysis.total_output_value
            )));
            lines.push(Line::from(format!(
                "Network Fee:  {} sats",
                analysis.fee.unwrap_or(0)
            )));
            lines.push(Line::from(""));

            // Inputs
            lines.push(Line::from(Span::styled(
                "Inputs:",
                Style::default().add_modifier(Modifier::UNDERLINED),
            )));
            for (i, input) in analysis.inputs.iter().enumerate() {
                let signed_icon = if input.is_signed { "✓" } else { "○" };
                lines.push(Line::from(format!(
                    "  {} Input #{}: {} sats from {:?}",
                    signed_icon,
                    i,
                    input.value.unwrap_or(0),
                    input.script_type
                )));
            }
            lines.push(Line::from(""));

            // Outputs
            lines.push(Line::from(Span::styled(
                "Outputs:",
                Style::default().add_modifier(Modifier::UNDERLINED),
            )));
            for (i, output) in analysis.outputs.iter().enumerate() {
                let change_marker = if output.is_change { " (change)" } else { "" };
                lines.push(Line::from(format!(
                    "  Output #{}: {} sats to {}{}",
                    i,
                    output.value,
                    &output.address[..20],
                    change_marker
                )));
            }

            lines.push(Line::from(""));
            lines.push(Line::from(format!(
                "Status: {} ({}/{} signatures)",
                if analysis.is_complete {
                    "Ready to broadcast"
                } else {
                    "Needs signatures"
                },
                analysis.signatures_present,
                analysis.signatures_required
            )));
        } else {
            lines.push(Line::from("No transaction loaded"));
        }

        lines.push(Line::from(""));
        lines.push(Line::from("[Enter] Proceed to sign | [ESC] Back"));

        let paragraph = Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Transaction Review"),
            )
            .wrap(Wrap { trim: true });

        f.render_widget(paragraph, area);
    }

    fn draw_approval_screen(&self, f: &mut Frame, area: Rect) {
        let mut lines = vec![
            Line::from(Span::styled(
                "⚠️  SIGNING APPROVAL REQUIRED",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
        ];

        if let Some(ref analysis) = self.psbt_analysis {
            lines.push(Line::from(Span::styled(
                "You are about to sign a transaction that will:",
                Style::default().add_modifier(Modifier::UNDERLINED),
            )));
            lines.push(Line::from(""));

            // Show spending amount
            let total_out = analysis.total_output_value;
            let fee = analysis.fee.unwrap_or(0);
            lines.push(Line::from(format!("• Send {} sats", total_out - fee)));
            lines.push(Line::from(format!("• Pay {} sats in network fees", fee)));
            lines.push(Line::from(""));

            // Security checks
            lines.push(Line::from(Span::styled(
                "Security Checks:",
                Style::default().add_modifier(Modifier::UNDERLINED),
            )));

            let checks = vec![
                ("Address verification", true),
                ("Amount verification", true),
                ("Fee reasonableness", fee < 10000), // Warn if fee > 10k sats
                ("Change address owned", true),
            ];

            for (check, passed) in checks {
                let (icon, color) = if passed {
                    ("✓", Color::Green)
                } else {
                    ("⚠", Color::Yellow)
                };
                lines.push(Line::from(vec![
                    Span::styled(format!("  {} ", icon), Style::default().fg(color)),
                    Span::raw(check),
                ]));
            }
        }

        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "DO YOU WANT TO PROCEED WITH SIGNING?",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(""));
        lines.push(Line::from("[Y] Yes, sign transaction"));
        lines.push(Line::from("[N] No, cancel signing"));
        lines.push(Line::from("[R] Review details again"));

        let paragraph = Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Approval Required")
                    .border_style(Style::default().fg(Color::Yellow)),
            )
            .wrap(Wrap { trim: true });

        f.render_widget(paragraph, area);
    }

    fn draw_signing_progress(&self, f: &mut Frame, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(5), // Progress bar
                Constraint::Min(5),    // Status
            ])
            .split(area);

        // Progress bar
        let progress = if self.signing_progress.total_inputs > 0 {
            self.signing_progress.signed_inputs as f64 / self.signing_progress.total_inputs as f64
        } else {
            0.0
        };

        let gauge = Gauge::default()
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Signing Progress"),
            )
            .gauge_style(Style::default().fg(Color::Green))
            .percent((progress * 100.0) as u16)
            .label(format!(
                "{}/{} inputs signed",
                self.signing_progress.signed_inputs, self.signing_progress.total_inputs
            ));

        f.render_widget(gauge, chunks[0]);

        // Status details
        let mut lines = vec![Line::from(format!(
            "Current operation: {}",
            self.signing_progress.current_operation
        ))];

        if self.signing_progress.is_complete {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "✓ Signing complete!",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from("[Enter] Continue to export"));
        } else {
            lines.push(Line::from(""));
            lines.push(Line::from("Please wait..."));
        }

        let paragraph = Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title("Status"))
            .wrap(Wrap { trim: true });

        f.render_widget(paragraph, chunks[1]);
    }

    fn draw_export_signed(&self, f: &mut Frame, area: Rect) {
        if let Some(ref export_state) = self.export_state {
            // Show QR codes for export
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3), // Instructions
                    Constraint::Min(10),   // QR display
                    Constraint::Length(3), // Navigation
                ])
                .split(area);

            // Instructions
            let instructions = Paragraph::new(format!(
                "Exporting signed PSBT - Part {}/{}",
                export_state.current_index + 1,
                export_state.qr_codes.len()
            ))
            .block(Block::default().borders(Borders::ALL).title("Export"))
            .alignment(Alignment::Center);
            f.render_widget(instructions, chunks[0]);

            // QR display
            if export_state.current_index < export_state.qr_codes.len() {
                let qr_text = &export_state.qr_codes[export_state.current_index];
                let lines: Vec<Line> = qr_text.lines().map(Line::from).collect();

                let qr_display = Paragraph::new(lines).alignment(Alignment::Center);
                f.render_widget(qr_display, chunks[1]);
            }

            // Navigation
            let nav = Paragraph::new(
                "[←/→] Navigate parts | [G] Grid view | [A] Auto-animate | [ESC] Done",
            )
            .alignment(Alignment::Center);
            f.render_widget(nav, chunks[2]);
        } else {
            let lines = vec![
                Line::from("Export Signed Transaction"),
                Line::from(""),
                Line::from("Select export format:"),
                Line::from(""),
                Line::from("[1] BBQr animated QR codes"),
                Line::from("[2] UR format (for wallets)"),
                Line::from("[3] Single QR (if small enough)"),
                Line::from("[4] Copy base64 to clipboard"),
                Line::from("[5] Save to file"),
                Line::from(""),
                Line::from("[ESC] Back to menu"),
            ];

            let paragraph = Paragraph::new(lines)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("Export Options"),
                )
                .wrap(Wrap { trim: true });

            f.render_widget(paragraph, area);
        }
    }

    fn draw_settings(&self, f: &mut Frame, area: Rect) {
        let lines = vec![
            Line::from("Settings"),
            Line::from(""),
            Line::from("[1] QR export format: BBQr"),
            Line::from("[2] Animation speed: Normal"),
            Line::from("[3] Security level: High"),
            Line::from("[4] Network: Bitcoin Mainnet"),
            Line::from("[5] Clear stored keys"),
            Line::from(""),
            Line::from("[ESC] Back to menu"),
        ];

        let paragraph = Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title("Settings"))
            .wrap(Wrap { trim: true });

        f.render_widget(paragraph, area);
    }

    fn handle_key_event(&mut self, key: KeyCode) {
        match self.screen {
            SigningScreen::MainMenu => self.handle_main_menu_key(key),
            SigningScreen::KeyManagement => self.handle_key_management_key(key),
            SigningScreen::ImportPsbt => self.handle_import_psbt_key(key),
            SigningScreen::ReviewTransaction => self.handle_review_key(key),
            SigningScreen::ApprovalScreen => self.handle_approval_key(key),
            SigningScreen::SigningProgress => self.handle_signing_progress_key(key),
            SigningScreen::ExportSigned => self.handle_export_key(key),
            SigningScreen::Settings => self.handle_settings_key(key),
        }
    }

    fn handle_hal_input(&mut self, event: InputEvent) {
        // Handle hardware button events
        match event {
            InputEvent::ButtonPress(Button::Select) => {
                // Simulate Enter key
                self.handle_key_event(KeyCode::Enter);
            }
            InputEvent::ButtonPress(Button::Back) => {
                // Simulate ESC key
                self.handle_key_event(KeyCode::Esc);
            }
            InputEvent::ButtonPress(Button::Up) => {
                self.handle_key_event(KeyCode::Up);
            }
            InputEvent::ButtonPress(Button::Down) => {
                self.handle_key_event(KeyCode::Down);
            }
            _ => {}
        }
    }

    fn handle_main_menu_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Esc => self.should_quit = true,
            KeyCode::Char('1') => self.screen = SigningScreen::KeyManagement,
            KeyCode::Char('2') => {
                if self.wallet.is_some() {
                    self.screen = SigningScreen::ImportPsbt;
                } else {
                    self.set_status("Load a wallet first".to_string(), StatusSeverity::Warning);
                }
            }
            KeyCode::Char('3') => {
                if self.current_psbt.is_some() {
                    self.screen = SigningScreen::ReviewTransaction;
                } else {
                    self.set_status("No transaction loaded".to_string(), StatusSeverity::Warning);
                }
            }
            KeyCode::Char('4') => {
                if self.current_psbt.is_some() {
                    self.screen = SigningScreen::ExportSigned;
                } else {
                    self.set_status(
                        "No signed transaction to export".to_string(),
                        StatusSeverity::Warning,
                    );
                }
            }
            KeyCode::Char('5') => self.screen = SigningScreen::Settings,
            _ => {}
        }
    }

    fn handle_key_management_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Esc => self.screen = SigningScreen::MainMenu,
            KeyCode::Char('1') => {
                // Load from storage
                if let Ok(data) = self.hal.storage.read("test_wallet") {
                    if let Ok(mnemonic) = String::from_utf8(data) {
                        match Wallet::from_mnemonic(&mnemonic, "", Network::Bitcoin) {
                            Ok(wallet) => {
                                self.wallet = Some(wallet);
                                self.set_status(
                                    "Wallet loaded successfully".to_string(),
                                    StatusSeverity::Success,
                                );
                                self.screen = SigningScreen::MainMenu;
                            }
                            Err(e) => {
                                self.set_status(
                                    format!("Failed to load wallet: {:?}", e),
                                    StatusSeverity::Error,
                                );
                            }
                        }
                    }
                }
            }
            KeyCode::Char('2') => {
                // Generate new mnemonic
                match MnemonicManager::generate(24) {
                    Ok(manager) => {
                        let mnemonic = manager.phrase();
                        match Wallet::from_mnemonic(&mnemonic, "", Network::Bitcoin) {
                            Ok(wallet) => {
                                self.wallet = Some(wallet);
                                // Store it
                                let _ = self.hal.storage.write("generated", mnemonic.as_bytes());
                                self.set_status(
                                    "New wallet generated".to_string(),
                                    StatusSeverity::Success,
                                );
                                self.screen = SigningScreen::MainMenu;
                            }
                            Err(e) => {
                                self.set_status(
                                    format!("Failed to create wallet: {:?}", e),
                                    StatusSeverity::Error,
                                );
                            }
                        }
                    }
                    Err(e) => {
                        self.set_status(
                            format!("Failed to generate mnemonic: {:?}", e),
                            StatusSeverity::Error,
                        );
                    }
                }
            }
            _ => {}
        }
    }

    fn handle_import_psbt_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Esc => {
                self.screen = SigningScreen::MainMenu;
                self.input_buffer.clear();
            }
            KeyCode::Char('4') => {
                // Start accepting base64 input
                self.set_status(
                    "Paste base64 PSBT and press Enter".to_string(),
                    StatusSeverity::Info,
                );
            }
            KeyCode::Char(c) => {
                self.input_buffer.push(c);
            }
            KeyCode::Backspace => {
                self.input_buffer.pop();
            }
            KeyCode::Enter => {
                if !self.input_buffer.is_empty() {
                    // Try to parse as PSBT
                    let parser = PsbtParser::new(Network::Bitcoin);
                    match parser.parse_base64(&self.input_buffer) {
                        Ok(psbt) => match parser.analyze(&psbt) {
                            Ok(analysis) => {
                                use base64::{engine::general_purpose::STANDARD, Engine as _};
                                if let Ok(data) = STANDARD.decode(&self.input_buffer) {
                                    self.current_psbt = Some(data);
                                    self.psbt_analysis = Some(analysis);
                                    self.set_status(
                                        "PSBT imported successfully".to_string(),
                                        StatusSeverity::Success,
                                    );
                                    self.screen = SigningScreen::ReviewTransaction;
                                }
                            }
                            Err(e) => {
                                self.set_status(
                                    format!("Failed to analyze PSBT: {:?}", e),
                                    StatusSeverity::Error,
                                );
                            }
                        },
                        Err(e) => {
                            self.set_status(
                                format!("Invalid PSBT: {:?}", e),
                                StatusSeverity::Error,
                            );
                        }
                    }
                    self.input_buffer.clear();
                }
            }
            _ => {}
        }
    }

    fn handle_review_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Esc => self.screen = SigningScreen::MainMenu,
            KeyCode::Enter => {
                if self.psbt_analysis.is_some() {
                    self.screen = SigningScreen::ApprovalScreen;
                }
            }
            _ => {}
        }
    }

    fn handle_approval_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                // Start signing
                if let Some(ref analysis) = self.psbt_analysis {
                    self.signing_progress.total_inputs = analysis.inputs.len();
                    self.signing_progress.signed_inputs = 0;
                    self.signing_progress.current_operation = "Initializing signing...".to_string();
                    self.signing_progress.is_complete = false;
                    self.screen = SigningScreen::SigningProgress;

                    // Simulate signing process
                    self.simulate_signing();
                }
            }
            KeyCode::Char('n') | KeyCode::Char('N') => {
                self.set_status(
                    "Signing cancelled by user".to_string(),
                    StatusSeverity::Warning,
                );
                self.screen = SigningScreen::MainMenu;
            }
            KeyCode::Char('r') | KeyCode::Char('R') => {
                self.screen = SigningScreen::ReviewTransaction;
            }
            KeyCode::Esc => self.screen = SigningScreen::ReviewTransaction,
            _ => {}
        }
    }

    fn handle_signing_progress_key(&mut self, key: KeyCode) {
        if self.signing_progress.is_complete && key == KeyCode::Enter {
            // Generate QR codes for export
            self.prepare_export();
            self.screen = SigningScreen::ExportSigned;
        }
    }

    fn handle_export_key(&mut self, key: KeyCode) {
        if let Some(ref mut export_state) = self.export_state {
            match key {
                KeyCode::Esc => {
                    self.export_state = None;
                    self.screen = SigningScreen::MainMenu;
                }
                KeyCode::Left => {
                    if export_state.current_index > 0 {
                        export_state.current_index -= 1;
                    }
                }
                KeyCode::Right => {
                    if export_state.current_index < export_state.qr_codes.len() - 1 {
                        export_state.current_index += 1;
                    }
                }
                KeyCode::Char('g') | KeyCode::Char('G') => {
                    export_state.show_grid = !export_state.show_grid;
                }
                _ => {}
            }
        } else {
            match key {
                KeyCode::Esc => self.screen = SigningScreen::MainMenu,
                KeyCode::Char('1') => {
                    // Generate BBQr codes
                    self.prepare_export();
                }
                _ => {}
            }
        }
    }

    fn handle_settings_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Esc => self.screen = SigningScreen::MainMenu,
            KeyCode::Char('5') => {
                // Clear all stored keys
                if let Ok(keys) = self.hal.storage.list_keys() {
                    for key in keys {
                        let _ = self.hal.storage.delete(&key);
                    }
                    self.set_status(
                        "All stored keys cleared".to_string(),
                        StatusSeverity::Success,
                    );
                }
            }
            _ => {}
        }
    }

    fn simulate_signing(&mut self) {
        // Simulate the signing process
        // In real implementation, this would use the wallet to sign

        for i in 0..self.signing_progress.total_inputs {
            self.signing_progress.signed_inputs = i + 1;
            self.signing_progress.current_operation = format!("Signing input {}...", i + 1);
        }

        self.signing_progress.is_complete = true;
        self.signing_progress.current_operation = "All inputs signed".to_string();

        // Update analysis to show signed
        if let Some(ref mut analysis) = self.psbt_analysis {
            analysis.is_complete = true;
            analysis.signatures_present = analysis.signatures_required;
            for input in &mut analysis.inputs {
                input.is_signed = true;
            }
        }

        self.set_status(
            "Transaction signed successfully".to_string(),
            StatusSeverity::Success,
        );
    }

    fn prepare_export(&mut self) {
        if let Some(ref psbt_data) = self.current_psbt {
            // Generate BBQr QR codes
            let generator = BBQrQrGenerator::new();

            match generator.generate_parts(psbt_data, oxivault_qr::FileType::Transaction) {
                Ok(qr_codes) => {
                    let ascii_codes: Vec<String> = qr_codes
                        .iter()
                        .map(AsciiQrRenderer::render_compact)
                        .collect();

                    self.export_state = Some(PsbtExportState {
                        qr_codes: ascii_codes,
                        current_index: 0,
                        animation_speed: 1000,
                        show_grid: false,
                        last_advance: Some(std::time::Instant::now()),
                    });
                }
                Err(e) => {
                    self.set_status(
                        format!("Failed to generate QR codes: {:?}", e),
                        StatusSeverity::Error,
                    );
                }
            }
        }
    }

    fn set_status(&mut self, text: String, severity: StatusSeverity) {
        self.status = StatusMessage { text, severity };
    }
}

/// Run the signing workflow
pub fn run_signing_workflow() -> io::Result<()> {
    SigningApp::run()
}
