//! Terminal QR rendering for identity sharing (beads tp-w43).
//!
//! Renders a `.onion` address as a scannable QR code using Unicode half-block
//! characters, so each text row encodes two QR module rows and the result is
//! roughly square in a typical terminal cell aspect ratio. A 2-module quiet zone
//! (light border) is added so phone scanners lock on.
//!
//! Rendering is pure (string in, string out) and deterministic, so it is unit
//! testable without a terminal.

use qrcode::{EcLevel, QrCode};

use crate::error::Error;

/// Width (in QR modules) of the quiet zone added on every side.
///
/// The QR spec recommends 4; 2 is the practical minimum that most phone scanners
/// still lock on while keeping the terminal output compact.
const QUIET: usize = 2;

/// Half-block glyphs. A printed block is an "ink" (dark) cell; a space is a
/// light (background) cell. Two stacked QR rows collapse into one text row:
/// the top row drives the upper half, the bottom row the lower half.
const FULL: char = '\u{2588}'; // both halves dark
const UPPER: char = '\u{2580}'; // top dark, bottom light
const LOWER: char = '\u{2584}'; // top light, bottom dark
const EMPTY: char = ' '; // both halves light

/// Render `onion` (or any non-empty string) as a terminal QR code.
///
/// Returns the multi-line string (each line newline-terminated) ready to print.
/// Dark modules map to dark/ink terminal cells; light modules to background.
pub fn render_onion(onion: &str) -> Result<String, Error> {
    if onion.trim().is_empty() {
        return Err(Error::Qr("cannot encode an empty identity".into()));
    }

    // Medium EC: a sensible robustness/size tradeoff for an onion-length payload.
    let code = QrCode::with_error_correction_level(onion.as_bytes(), EcLevel::M)
        .map_err(|e| Error::Qr(e.to_string()))?;

    let width = code.width();
    let modules = code.to_colors();
    // `is_dark`: true where the module is a dark (printed) cell, with the quiet
    // zone treated as light. Indices are offset by the quiet-zone border.
    let padded = width + 2 * QUIET;
    let is_dark = |row: usize, col: usize| -> bool {
        if row < QUIET || col < QUIET || row >= width + QUIET || col >= width + QUIET {
            return false; // quiet zone: light
        }
        let r = row - QUIET;
        let c = col - QUIET;
        modules[r * width + c] == qrcode::Color::Dark
    };

    let mut out = String::with_capacity(padded * (padded / 2 + 1) * 4);
    // Step over rows two at a time; the second of a pair may be off the bottom
    // edge for an odd-height padded grid, in which case it is treated as light.
    let mut row = 0;
    while row < padded {
        for col in 0..padded {
            let top = is_dark(row, col);
            let bottom = if row + 1 < padded {
                is_dark(row + 1, col)
            } else {
                false
            };
            out.push(match (top, bottom) {
                (true, true) => FULL,
                (true, false) => UPPER,
                (false, true) => LOWER,
                (false, false) => EMPTY,
            });
        }
        out.push('\n');
        row += 2;
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";

    #[test]
    fn renders_non_empty_with_block_chars() {
        let out = render_onion(SAMPLE).expect("render");
        assert!(!out.is_empty());
        assert!(
            out.chars().any(|c| c == FULL || c == UPPER || c == LOWER),
            "expected at least one block glyph in the output"
        );
    }

    #[test]
    fn deterministic() {
        let a = render_onion(SAMPLE).expect("render a");
        let b = render_onion(SAMPLE).expect("render b");
        assert_eq!(a, b, "rendering must be deterministic");
    }

    #[test]
    fn quiet_zone_border_present() {
        let code =
            QrCode::with_error_correction_level(SAMPLE.as_bytes(), EcLevel::M).expect("encode");
        let width = code.width();
        let padded = width + 2 * QUIET;

        let rendered = render_onion(SAMPLE).expect("render");
        let lines: Vec<&str> = rendered.lines().collect();

        // Half-block packing: ceil(padded / 2) rows, padded columns each.
        let expected_rows = padded.div_ceil(2);
        assert_eq!(lines.len(), expected_rows, "row count");
        for line in &lines {
            assert_eq!(line.chars().count(), padded, "every line is `padded` wide");
        }

        // Top QUIET module rows are entirely light => first ceil(QUIET/2) text
        // rows are all spaces (QUIET is even, so QUIET/2 full light rows).
        for line in lines.iter().take(QUIET / 2) {
            assert!(
                line.chars().all(|c| c == EMPTY),
                "top quiet-zone text row must be all spaces"
            );
        }
        // Left and right QUIET columns of every text row are light (the side
        // borders), since the quiet zone is light on both module halves.
        for line in &lines {
            let chars: Vec<char> = line.chars().collect();
            for &c in chars.iter().take(QUIET) {
                assert_eq!(c, EMPTY, "left quiet-zone column must be a space");
            }
            for &c in chars.iter().rev().take(QUIET) {
                assert_eq!(c, EMPTY, "right quiet-zone column must be a space");
            }
        }
    }

    #[test]
    fn empty_input_errors() {
        assert!(render_onion("").is_err());
        assert!(render_onion("   ").is_err());
    }

    #[test]
    fn arbitrary_nonempty_string_renders() {
        // Not a valid onion, but render is payload-agnostic and must succeed.
        let out = render_onion("hello-world").expect("render");
        assert!(!out.is_empty());
    }
}
