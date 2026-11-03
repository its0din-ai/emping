/// Escape control characters before printing text to a terminal.
///
/// Interface names and error messages are normally plain ASCII, but an interface
/// name can contain escape characters on some platforms. Keep diagnostics readable
/// while preventing ANSI/terminal control injection.
pub fn sanitize(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            '\x1b' => output.push_str("\\x1b"),
            value
                if value.is_control()
                    || matches!(
                        value,
                        '\u{200b}'..='\u{200f}'
                            | '\u{2028}'..='\u{202e}'
                            | '\u{2060}'..='\u{2069}'
                    ) =>
            {
                use std::fmt::Write;
                let _ = write!(output, "\\u{{{:x}}}", value as u32);
            }
            value => output.push(value),
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::sanitize;

    #[test]
    fn leaves_normal_interface_names_alone() {
        assert_eq!(sanitize("eth0"), "eth0");
        assert_eq!(sanitize("en0-ü"), "en0-ü");
    }

    #[test]
    fn escapes_ansi_sequences() {
        assert_eq!(sanitize("eth0\x1b[2J"), "eth0\\x1b[2J");
        assert_eq!(sanitize("\u{9b}31m"), "\\u{9b}31m");
    }

    #[test]
    fn escapes_control_characters_and_backslashes() {
        assert_eq!(sanitize("a\nb\rc\td"), "a\\nb\\rc\\td");
        assert_eq!(sanitize("a\\b"), "a\\\\b");
    }

    #[test]
    fn escapes_bidi_controls() {
        let text = format!("eth{}0", '\u{202e}');
        assert_eq!(sanitize(&text), "eth\\u{202e}0");
    }
}
