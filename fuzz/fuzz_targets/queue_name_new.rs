#![no_main]
//! Fuzz target for `QueueName::new`.
//!
//! Goal: ensure no arbitrary byte sequence causes a panic.
//! A validation error is the correct outcome for invalid input.

use libfuzzer_sys::fuzz_target;
use queue_runtime::QueueName;

fuzz_target!(|data: &[u8]| {
    // Convert bytes to a string if possible.
    // Invalid UTF-8 must not panic — it should simply fail validation.
    if let Ok(s) = std::str::from_utf8(data) {
        // Either Ok or Err is acceptable; a panic is not.
        let _ = QueueName::new(s.to_string());
    }
    // For non-UTF-8 input the lossy conversion replaces invalid sequences with
    // U+FFFD, which is non-ASCII and will always be rejected by QueueName.
    // We still call it to confirm the rejection path does not panic.
    let lossy = String::from_utf8_lossy(data).into_owned();
    let _ = QueueName::new(lossy);
});
