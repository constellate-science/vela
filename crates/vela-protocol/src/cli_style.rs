//! CLI output discipline for Vela.
//!
//! The rules:
//!   - Signal blue (#3B5BDB) is reserved for live state — the current step of a
//!     running audit or the active cursor. It is never used for success.
//!   - State chips use a muted engraved palette derived from ink, not a
//!     traffic-light green/red: moss for ok, brass for contested, dust for
//!     stale, madder for lost.
//!   - `·` (middle dot) is the only decorative separator.
//!   - Banners are a dim tick row and a mono eyebrow, never `===` or `---`.
//!   - All ANSI is gated on a TTY stdout and NO_COLOR being unset.
//!
//! Every styled string in `cli.rs` should route through a helper here so the
//! discipline is enforced in one place.

use colored::{ColoredString, Colorize};
use indicatif::ProgressStyle;
use std::io::IsTerminal;
use std::sync::Once;

// --- palette -----------------------------------------------------------------

pub const MOSS: (u8, u8, u8) = (0x3F, 0x6B, 0x4E);
pub const BRASS: (u8, u8, u8) = (0x8A, 0x6A, 0x1F);
pub const DUST: (u8, u8, u8) = (0x7A, 0x6F, 0x5C);
pub const MADDER: (u8, u8, u8) = (0x8A, 0x3A, 0x3A);
pub const SIGNAL: (u8, u8, u8) = (0x3B, 0x5B, 0xDB);

// --- init --------------------------------------------------------------------

static INIT: Once = Once::new();

/// Initialize styling. Call once near the CLI entry point.
///
/// Disables all ANSI output when stdout is not a terminal or `NO_COLOR` is set.
/// Safe to call multiple times; only the first call takes effect.
pub fn init() {
    INIT.call_once(|| {
        let no_color = std::env::var_os("NO_COLOR").is_some();
        let is_tty = std::io::stdout().is_terminal();
        if no_color || !is_tty {
            colored::control::set_override(false);
        }
    });
}

// --- primitives --------------------------------------------------------------

#[must_use]
pub fn dim(s: &str) -> ColoredString {
    s.dimmed()
}

#[must_use]
pub fn mono_eyebrow(label: &str) -> ColoredString {
    // Tracked uppercase lives at the call site; we just dim the mono.
    label.dimmed()
}

/// A tick row — dim `·` characters of a given visual width.
#[must_use]
pub fn tick_row(width: usize) -> String {
    let row = "·".repeat(width);
    format!("{}", row.dimmed())
}

// --- ink-derived color wrappers ---------------------------------------------
// These exist so `cli.rs` and friends can migrate from `.green()`/`.red()` to
// a muted engraved palette without loss of semantic pairing (added / removed,
// ok / lost, current / stale).

#[must_use]
pub fn moss(s: impl AsRef<str>) -> ColoredString {
    let (r, g, b) = MOSS;
    s.as_ref().truecolor(r, g, b)
}

#[must_use]
pub fn madder(s: impl AsRef<str>) -> ColoredString {
    let (r, g, b) = MADDER;
    s.as_ref().truecolor(r, g, b)
}

#[must_use]
pub fn brass(s: impl AsRef<str>) -> ColoredString {
    let (r, g, b) = BRASS;
    s.as_ref().truecolor(r, g, b)
}

#[must_use]
pub fn dust_color(s: impl AsRef<str>) -> ColoredString {
    let (r, g, b) = DUST;
    s.as_ref().truecolor(r, g, b)
}

#[must_use]
pub fn signal(s: impl AsRef<str>) -> ColoredString {
    let (r, g, b) = SIGNAL;
    s.as_ref().truecolor(r, g, b)
}

// --- state chips -------------------------------------------------------------

/// Engraved state chip: `· label` in the state color. Lowercase, mono-ish.
#[must_use]
pub fn chip(label: &str, rgb: (u8, u8, u8)) -> String {
    let dot = "·".truecolor(rgb.0, rgb.1, rgb.2);
    let text = label.truecolor(rgb.0, rgb.1, rgb.2);
    format!("{dot} {text}")
}

#[must_use]
pub fn ok(label: &str) -> String {
    chip(label, MOSS)
}

#[must_use]
pub fn warn(label: &str) -> String {
    chip(label, BRASS)
}

#[must_use]
pub fn stale(label: &str) -> String {
    chip(label, DUST)
}

#[must_use]
pub fn lost(label: &str) -> String {
    chip(label, MADDER)
}

/// Signal-blue chip — reserved for live state only.
#[must_use]
pub fn live(label: &str) -> String {
    chip(label, SIGNAL)
}

// --- headers -----------------------------------------------------------------

/// A header block: dim mono eyebrow, bold title, dim tick row.
///
/// Prints three lines to stdout.
pub fn header(eyebrow: &str, title: &str) {
    println!("  {}", eyebrow.dimmed());
    println!("  {}", title.bold());
    println!("  {}", tick_row(60));
}

/// An error prefix — `err ·` in madder, lowercase.
#[must_use]
pub fn err_prefix() -> String {
    let (r, g, b) = MADDER;
    format!("{}", "err ·".truecolor(r, g, b))
}

// --- progress bar ------------------------------------------------------------

/// Progress-bar style for long-running work.
///
/// Uses a hairline bar (`──` filled, blank unfilled), signal-blue for the
/// current position, and `·` as the separator.
#[must_use]
pub fn progress_style(unit: &str) -> ProgressStyle {
    let template = format!("  {{bar:30}} {{pos}}/{{len}} · {unit} · {{msg}}");
    ProgressStyle::with_template(&template)
        .unwrap_or_else(|_| ProgressStyle::default_bar())
        .progress_chars("──╌")
}
