#![no_main]
//! Fuzz target for `SessionId::new`.
//!
//! Goal: ensure no arbitrary byte sequence causes a panic.
//! A validation error is the correct outcome for invalid input.

use libfuzzer_sys::fuzz_target;
use queue_runtime::SessionId;

fuzz_target!(|data: &[u8]| {
    // Valid UTF-8 path.
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = SessionId::new(s.to_string());
    }
    // Lossy path: replace invalid bytes with U+FFFD — must not panic.
    let lossy = String::from_utf8_lossy(data).into_owned();
    let _ = SessionId::new(lossy);
});
