pub(super) fn matches_pattern(path: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return path == pattern;
    }

    if !parts[0].is_empty() && !path.starts_with(parts[0]) {
        return false;
    }

    if let Some(last) = parts.last()
        && !last.is_empty()
        && !path.ends_with(last)
    {
        return false;
    }

    let mut search_start = parts[0].len();
    for part in &parts[1..parts.len() - 1] {
        if !part.is_empty() {
            if let Some(pos) = path[search_start..].find(part) {
                search_start += pos + part.len();
            } else {
                return false;
            }
        }
    }

    true
}
