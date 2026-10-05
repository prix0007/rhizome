//! Every string that came from the network passes through here.

pub const MAX_LEN: usize = 255;

/// Invisible formatting characters that can reorder or hide text (bidi
/// overrides/isolates, zero-width characters, BOM, line/paragraph separators).
fn is_invisible_format(c: char) -> bool {
    matches!(c,
        '\u{00ad}'                      // soft hyphen
        | '\u{061c}'                    // Arabic letter mark
        | '\u{115f}' | '\u{1160}'       // Hangul choseong/jungseong fillers
        | '\u{17b4}' | '\u{17b5}'       // Khmer inherent vowels
        | '\u{180b}'..='\u{180f}'       // Mongolian free variation selectors / vowel separator
        | '\u{200b}'..='\u{200f}'       // zero-width and directional marks
        | '\u{2028}'..='\u{202e}'       // separators and bidi embeddings/overrides
        | '\u{2060}'..='\u{206f}'       // word joiner, invisible operators, bidi isolates
        | '\u{3164}'                    // Hangul filler
        | '\u{feff}'                    // BOM / zero-width no-break space
        | '\u{ffa0}'                    // halfwidth Hangul filler
        | '\u{fff9}'..='\u{fffb}'       // interlinear annotation
        | '\u{1d173}'..='\u{1d17a}'     // musical symbol formatting
        | '\u{e0000}'..='\u{e007f}'     // tag characters
    )
}

/// Strip control and invisible-format characters, trim, and cap at 255 characters.
pub fn sanitize(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_control() && !is_invisible_format(*c))
        .collect();
    cleaned.trim().chars().take(MAX_LEN).collect()
}

/// Like `sanitize`, for free text that may span lines: each line is cleaned
/// and trimmed, `\r\n`/`\r` become `\n`, runs of blank lines collapse to one,
/// and leading/trailing blank lines are dropped. Capped at `max_chars`.
pub fn sanitize_multiline(s: &str, max_chars: usize) -> String {
    let normalised = s.replace("\r\n", "\n").replace('\r', "\n");
    let mut lines: Vec<String> = Vec::new();
    for line in normalised.split('\n') {
        let clean = sanitize_line(line);
        // collapse runs of blank lines and drop leading ones
        if clean.is_empty() && lines.last().is_none_or(|l| l.is_empty()) {
            continue;
        }
        lines.push(clean);
    }
    while lines.last().is_some_and(|l| l.is_empty()) {
        lines.pop();
    }
    lines.join("\n").chars().take(max_chars).collect()
}

/// `sanitize` without the length cap.
fn sanitize_line(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_control() && !is_invisible_format(*c))
        .collect();
    cleaned.trim().to_string()
}

/// Lossy UTF-8 decode, then `sanitize`.
pub fn sanitize_bytes(b: &[u8]) -> String {
    sanitize(&String::from_utf8_lossy(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_characters_are_stripped() {
        assert_eq!(sanitize("a\0b\x07c\x1b[31md\r\ne\tf"), "abc[31mdef");
    }

    #[test]
    fn bidi_and_zero_width_characters_are_stripped() {
        assert_eq!(
            sanitize("ab\u{202e}cd\u{200b}e\u{feff}f\u{2066}g"),
            "abcdefg"
        );
    }

    #[test]
    fn all_listed_invisible_and_bidi_characters_are_stripped() {
        for c in [
            '\u{00ad}',
            '\u{061c}',
            '\u{115f}',
            '\u{1160}',
            '\u{17b4}',
            '\u{17b5}',
            '\u{180e}',
            '\u{200b}',
            '\u{200e}',
            '\u{200f}',
            '\u{202a}',
            '\u{202e}',
            '\u{2060}',
            '\u{2064}',
            '\u{2066}',
            '\u{2069}',
            '\u{206a}',
            '\u{206f}',
            '\u{3164}',
            '\u{feff}',
            '\u{ffa0}',
            '\u{fff9}',
            '\u{fffa}',
            '\u{fffb}',
            '\u{e0001}',
            '\u{e0020}',
            '\u{e007f}',
        ] {
            let s = format!("a{c}b");
            assert_eq!(sanitize(&s), "ab", "U+{:04X}", c as u32);
        }
        assert_eq!(
            sanitize("caf\u{e9} \u{1f4fa} \u{4e1c}\u{4eac}"),
            "caf\u{e9} \u{1f4fa} \u{4e1c}\u{4eac}"
        );
    }

    #[test]
    fn multiline_keeps_line_breaks_but_cleans_each_line() {
        assert_eq!(
            sanitize_multiline("a\r\nb\rc\n\n\n\nd", 500),
            "a\nb\nc\n\nd"
        );
        assert_eq!(
            sanitize_multiline("\n\n  hi \x1b[0m \u{202e}there\u{0}\n\n", 500),
            "hi [0m there"
        );
        assert_eq!(sanitize_multiline("", 500), "");
        assert_eq!(
            sanitize_multiline("é".repeat(600).as_str(), 500)
                .chars()
                .count(),
            500
        );
        assert_eq!(sanitize_multiline("a\tb", 500), "ab");
    }

    #[test]
    fn length_is_capped_in_characters_not_bytes() {
        let long = "é".repeat(1000);
        let out = sanitize(&long);
        assert_eq!(out.chars().count(), MAX_LEN);
        assert!(out.chars().all(|c| c == 'é'));
    }

    #[test]
    fn unicode_and_emoji_survive() {
        assert_eq!(
            sanitize("Wohnzimmer-Büro 📺 東京"),
            "Wohnzimmer-Büro 📺 東京"
        );
    }

    #[test]
    fn html_and_sql_metacharacters_are_kept_verbatim_for_later_escaping() {
        assert_eq!(sanitize("<b>'); DROP TABLE x;--"), "<b>'); DROP TABLE x;--");
    }

    #[test]
    fn surrounding_whitespace_is_trimmed_and_empty_stays_empty() {
        assert_eq!(sanitize("  hi  "), "hi");
        assert_eq!(sanitize(""), "");
        assert_eq!(sanitize("\0\0"), "");
    }

    #[test]
    fn invalid_utf8_is_handled_lossily() {
        let out = sanitize_bytes(&[b'o', b'k', 0xff, 0xfe, b'!']);
        assert!(out.starts_with("ok") && out.ends_with('!'));
        assert!(out.contains('\u{fffd}'));
    }
}
