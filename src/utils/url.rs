/// Percent-encode a small set of characters that commonly appear unencoded in
/// example URLs (like shell expansion snippets) and are rejected by strict URI
/// parsers. This purposely only encodes a small set of known-problematic
/// characters so we don't double-encode existing percent-encoded values.
pub fn encode_problematic_path_chars(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '$' => out.push_str("%24"),
            '(' => out.push_str("%28"),
            ')' => out.push_str("%29"),
            ' ' => out.push_str("%20"),
            _ => out.push(ch),
        }
    }
    out
}
