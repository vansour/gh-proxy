pub(super) fn extract_shared_max_age(cache_control: &str) -> Option<u64> {
    extract_cache_directive(cache_control, "s-maxage")
        .or_else(|| extract_cache_directive(cache_control, "max-age"))
}

pub(super) fn has_cache_control_directive(cache_control: &str, directive: &str) -> bool {
    cache_control.split(',').any(|part| {
        let token = part.trim();
        token.eq_ignore_ascii_case(directive)
            || token
                .split_once('=')
                .map(|(name, _)| name.trim().eq_ignore_ascii_case(directive))
                .unwrap_or(false)
    })
}

pub(super) fn extract_cache_directive(cache_control: &str, directive: &str) -> Option<u64> {
    cache_control.split(',').find_map(|part| {
        let (name, value) = part.trim().split_once('=')?;
        if !name.trim().eq_ignore_ascii_case(directive) {
            return None;
        }

        value.trim().trim_matches('"').parse().ok()
    })
}
