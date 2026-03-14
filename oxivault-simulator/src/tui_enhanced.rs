//! Enhanced TUI functions for BBQr integration

use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::Line,
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use oxivault_qr::{AsciiQrRenderer, BBQrDecoder, BBQrEncoder, EncodingType, FileType};

use crossterm::event::KeyCode;
use std::time::{Duration, Instant};

/// Enhanced PSBT export state
#[derive(Default)]
pub struct PsbtExportState {
    /// BBQr QR codes for the PSBT
    pub qr_codes: Vec<String>,
    /// Current QR index being displayed
    pub current_index: usize,
    /// Auto-advance timer
    pub last_advance: Option<Instant>,
    /// Animation speed (ms)
    pub animation_speed: u64,
    /// Show all parts at once
    pub show_grid: bool,
}

impl PsbtExportState {
    pub fn new() -> Self {
        Self {
            animation_speed: 500,
            ..Default::default()
        }
    }

    /// Generate BBQr codes for PSBT data
    pub fn generate_for_psbt(&mut self, psbt_bytes: &[u8]) -> Result<(), String> {
        // Use BBQr encoder for PSBT
        let encoder = BBQrEncoder::new(
            FileType::Psbt,
            EncodingType::Base32, // Use Base32 encoding
            200,                  // Max fragment size
        );

        // Split data into parts
        let parts = encoder
            .split(psbt_bytes)
            .map_err(|e| format!("Failed to encode: {}", e))?;

        // Convert each part to QR code and then to ASCII for terminal display
        self.qr_codes.clear();
        for part in parts {
            // Generate QR code from the BBQr part
            match qrcode::QrCode::new(&part) {
                Ok(qr) => {
                    let ascii = AsciiQrRenderer::render_compact(&qr);
                    self.qr_codes.push(ascii);
                }
                Err(e) => return Err(format!("Failed to generate QR: {:?}", e)),
            }
        }

        self.current_index = 0;
        self.last_advance = Some(Instant::now());

        Ok(())
    }

    /// Auto-advance to next QR if enough time has passed
    pub fn maybe_advance(&mut self) {
        if let Some(last) = self.last_advance {
            if last.elapsed() > Duration::from_millis(self.animation_speed) {
                self.next();
                self.last_advance = Some(Instant::now());
            }
        }
    }

    /// Move to next QR code
    pub fn next(&mut self) {
        if !self.qr_codes.is_empty() {
            self.current_index = (self.current_index + 1) % self.qr_codes.len();
        }
    }

    /// Move to previous QR code
    pub fn prev(&mut self) {
        if !self.qr_codes.is_empty() {
            if self.current_index == 0 {
                self.current_index = self.qr_codes.len() - 1;
            } else {
                self.current_index -= 1;
            }
        }
    }

    /// Toggle grid view
    pub fn toggle_grid(&mut self) {
        self.show_grid = !self.show_grid;
    }
}

/// Draw enhanced PSBT export screen
pub fn draw_psbt_export(state: &PsbtExportState, f: &mut Frame, area: Rect) {
    if state.qr_codes.is_empty() {
        let text = vec![
            Line::from("No PSBT data to export"),
            Line::from(""),
            Line::from("Press ESC to go back"),
        ];

        let paragraph = Paragraph::new(text)
            .block(Block::default().borders(Borders::ALL).title("PSBT Export"))
            .alignment(Alignment::Center);

        f.render_widget(paragraph, area);
        return;
    }

    if state.show_grid && state.qr_codes.len() > 1 {
        // Show all QR codes in a grid
        draw_qr_grid(state, f, area);
    } else {
        // Show animated single QR
        draw_animated_qr(state, f, area);
    }
}

/// Draw single animated QR code
fn draw_animated_qr(state: &PsbtExportState, f: &mut Frame, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(5),    // QR Code
            Constraint::Length(4), // Controls
        ])
        .split(area);

    // Header with progress
    let header = format!(
        "PSBT Export - Part {}/{} (BBQr)",
        state.current_index + 1,
        state.qr_codes.len()
    );
    let header_widget = Paragraph::new(header)
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(header_widget, chunks[0]);

    // QR Code display
    if let Some(qr_ascii) = state.qr_codes.get(state.current_index) {
        let lines: Vec<Line> = qr_ascii.lines().map(Line::from).collect();
        let qr_widget = Paragraph::new(lines)
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL));
        f.render_widget(qr_widget, chunks[1]);
    }

    // Controls
    let controls = vec![
        Line::from(""),
        Line::from("← Previous | → Next | Space: Pause | G: Grid View"),
        Line::from(format!(
            "Auto-advance: {}ms | +/- to adjust",
            state.animation_speed
        )),
        Line::from("ESC: Back"),
    ];

    let controls_widget = Paragraph::new(controls)
        .alignment(Alignment::Center)
        .style(Style::default().fg(Color::Gray));
    f.render_widget(controls_widget, chunks[2]);
}

/// Draw all QR codes in a grid
fn draw_qr_grid(state: &PsbtExportState, f: &mut Frame, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(5),    // Grid
            Constraint::Length(3), // Controls
        ])
        .split(area);

    // Header
    let header = format!("PSBT Export - {} parts (Grid View)", state.qr_codes.len());
    let header_widget = Paragraph::new(header)
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(header_widget, chunks[0]);

    // Calculate grid layout
    let cols = ((state.qr_codes.len() as f32).sqrt().ceil()) as usize;
    let rows = state.qr_codes.len().div_ceil(cols);

    // Create row chunks
    let row_constraints: Vec<Constraint> = (0..rows)
        .map(|_| Constraint::Ratio(1, rows as u32))
        .collect();
    let row_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(&row_constraints)
        .split(chunks[1]);

    // Draw QR codes in grid
    let mut qr_idx = 0;
    for row_chunk in row_chunks.iter() {
        let col_constraints: Vec<Constraint> = (0..cols)
            .map(|_| Constraint::Ratio(1, cols as u32))
            .collect();
        let col_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(&col_constraints)
            .split(*row_chunk);

        for col_chunk in col_chunks.iter() {
            if qr_idx < state.qr_codes.len() {
                if let Some(qr_ascii) = state.qr_codes.get(qr_idx) {
                    // Make smaller QR for grid
                    let lines: Vec<Line> = qr_ascii
                        .lines()
                        .take(10) // Limit height in grid
                        .map(|l| {
                            let truncated = if l.len() > 20 { &l[..20] } else { l };
                            Line::from(truncated)
                        })
                        .collect();

                    let title = format!("Part {}", qr_idx + 1);
                    let qr_widget = Paragraph::new(lines)
                        .alignment(Alignment::Center)
                        .block(Block::default().borders(Borders::ALL).title(title));
                    f.render_widget(qr_widget, *col_chunk);
                }
                qr_idx += 1;
            }
        }
    }

    // Controls
    let controls = vec![Line::from("G: Single View | ESC: Back")];

    let controls_widget = Paragraph::new(controls)
        .alignment(Alignment::Center)
        .style(Style::default().fg(Color::Gray));
    f.render_widget(controls_widget, chunks[2]);
}

/// Handle keyboard input for PSBT export
pub fn handle_psbt_export_input(state: &mut PsbtExportState, key: KeyCode) -> Option<KeyCode> {
    match key {
        KeyCode::Left => {
            state.prev();
            state.last_advance = Some(Instant::now());
            None
        }
        KeyCode::Right => {
            state.next();
            state.last_advance = Some(Instant::now());
            None
        }
        KeyCode::Char(' ') => {
            // Toggle auto-advance
            state.last_advance = if state.last_advance.is_some() {
                None
            } else {
                Some(Instant::now())
            };
            None
        }
        KeyCode::Char('g') | KeyCode::Char('G') => {
            state.toggle_grid();
            None
        }
        KeyCode::Char('+') => {
            state.animation_speed = (state.animation_speed + 100).min(5000);
            None
        }
        KeyCode::Char('-') => {
            state.animation_speed = (state.animation_speed.saturating_sub(100)).max(100);
            None
        }
        KeyCode::Esc => Some(KeyCode::Esc),
        _ => None,
    }
}

/// QR import state for scanning BBQr sequences
pub struct QrImportState {
    decoder: BBQrDecoder,
    scanned_parts: Vec<String>,
    result_data: Option<Vec<u8>>,
    error_message: Option<String>,
}

impl Default for QrImportState {
    fn default() -> Self {
        Self::new()
    }
}

impl QrImportState {
    pub fn new() -> Self {
        Self {
            decoder: BBQrDecoder::new(),
            scanned_parts: Vec::new(),
            result_data: None,
            error_message: None,
        }
    }

    /// Process a scanned QR code string
    pub fn scan_qr(&mut self, qr_data: &str) -> Result<(), String> {
        match self.decoder.add_part(qr_data) {
            Ok(_) => {
                if self.decoder.is_complete() {
                    // Combine the complete data
                    match self.decoder.combine() {
                        Ok(data) => {
                            self.result_data = Some(data);
                            Ok(())
                        }
                        Err(e) => {
                            self.error_message = Some(format!("Decode error: {}", e));
                            Err(format!("Decode error: {}", e))
                        }
                    }
                } else {
                    let (received, total) = self.decoder.progress();
                    self.scanned_parts
                        .push(format!("Part {}/{} scanned", received, total));
                    Ok(())
                }
            }
            Err(e) => {
                self.error_message = Some(format!("Scan error: {:?}", e));
                Err(format!("Scan error: {:?}", e))
            }
        }
    }

    /// Get progress
    pub fn progress(&self) -> (usize, usize) {
        self.decoder.progress()
    }

    /// Reset scanner
    pub fn reset(&mut self) {
        self.decoder = BBQrDecoder::new();
        self.scanned_parts.clear();
        self.result_data = None;
        self.error_message = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_psbt_export_state() {
        let mut state = PsbtExportState::new();
        let test_data = b"test psbt data";

        assert!(state.generate_for_psbt(test_data).is_ok());
        assert!(!state.qr_codes.is_empty());

        let initial = state.current_index;
        state.next();
        if state.qr_codes.len() > 1 {
            assert_ne!(state.current_index, initial);
        }
    }

    #[test]
    fn test_qr_import_state() {
        let mut state = QrImportState::new();
        assert_eq!(state.progress(), (0, 0));

        // Would need actual BBQr data to test scanning
        state.reset();
        assert_eq!(state.progress(), (0, 0));
    }
}
