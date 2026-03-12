use std::borrow::Cow;

/// Percent-encode a small set of characters that commonly appear unencoded in
/// example URLs (like shell expansion snippets) and are rejected by strict URI
/// parsers.
///
/// Returns Cow to avoid allocation if no changes are needed.
pub fn encode_problematic_path_chars(input: &str) -> Cow<'_, str> {
    // Fast path: scan first
    if !input.chars().any(|c| matches!(c, '$' | '(' | ')' | ' ')) {
        return Cow::Borrowed(input);
    }

    let mut out = String::with_capacity(input.len() + 16);
    for ch in input.chars() {
        match ch {
            '$' => out.push_str("%24"),
            '(' => out.push_str("%28"),
            ')' => out.push_str("%29"),
            ' ' => out.push_str("%20"),
            _ => out.push(ch),
        }
    }
    Cow::Owned(out)
}
