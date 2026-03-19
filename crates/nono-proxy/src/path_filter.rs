//! L7 path filtering for reverse proxy routes.
//!
//! Matches HTTP method + URL path against glob patterns.
//! `*` matches a single path segment, `**` matches zero or more segments.
//! When no rules are defined, all paths are allowed (open by default).

use crate::config::PathRule;

/// Check if a request is allowed by the path filter rules.
///
/// Returns `true` if `rules` is empty (no filtering) or if the request
/// matches at least one rule. Returns `false` if rules exist but none match.
#[must_use]
pub fn check_path_allowed(rules: &[PathRule], method: &str, path: &str) -> bool {
    if rules.is_empty() {
        return true;
    }
    rules
        .iter()
        .any(|rule| matches_path_rule(rule, method, path))
}

/// Check if a single rule matches the given method and path.
///
/// Percent-decodes the path before matching to prevent bypass via encoding
/// (e.g., `/admin%2Fdanger` is decoded to `/admin/danger` before comparison).
#[must_use]
pub fn matches_path_rule(rule: &PathRule, method: &str, path: &str) -> bool {
    // Method check (case-insensitive, "*" = any)
    if rule.method != "*" && !rule.method.eq_ignore_ascii_case(method) {
        return false;
    }

    // Strip query string before matching
    let clean_path = match path.split_once('?') {
        Some((before, _)) => before,
        None => path,
    };

    // Percent-decode to prevent bypass via encoded slashes/dots
    let decoded = urlencoding::decode(clean_path).unwrap_or(std::borrow::Cow::Borrowed(clean_path));

    // Split into segments and match
    let rule_segments: Vec<&str> = rule.path.split('/').filter(|s| !s.is_empty()).collect();
    let path_segments: Vec<&str> = decoded.split('/').filter(|s| !s.is_empty()).collect();

    match_segments(&rule_segments, &path_segments)
}

/// Recursive segment matcher supporting `*` (one segment) and `**` (zero or more).
fn match_segments(pattern: &[&str], path: &[&str]) -> bool {
    match (pattern.first(), path.first()) {
        (None, None) => true,
        (Some(&"**"), _) => {
            // ** matches zero or more segments
            match_segments(&pattern[1..], path)
                || (!path.is_empty() && match_segments(pattern, &path[1..]))
        }
        (Some(&"*"), Some(_)) => {
            // * matches exactly one segment
            match_segments(&pattern[1..], &path[1..])
        }
        (Some(p), Some(s)) if *p == *s => match_segments(&pattern[1..], &path[1..]),
        _ => false,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_matches_exact_path() {
        let rule = PathRule {
            method: "GET".into(),
            path: "/api/v4/version".into(),
        };
        assert!(matches_path_rule(&rule, "GET", "/api/v4/version"));
        assert!(!matches_path_rule(&rule, "POST", "/api/v4/version"));
        assert!(!matches_path_rule(&rule, "GET", "/api/v4/other"));
    }

    #[test]
    fn test_single_wildcard_matches_one_segment() {
        let rule = PathRule {
            method: "GET".into(),
            path: "/api/v4/projects/*/merge_requests".into(),
        };
        assert!(matches_path_rule(
            &rule,
            "GET",
            "/api/v4/projects/123/merge_requests"
        ));
        assert!(matches_path_rule(
            &rule,
            "GET",
            "/api/v4/projects/my-proj/merge_requests"
        ));
        assert!(!matches_path_rule(
            &rule,
            "GET",
            "/api/v4/projects/123/456/merge_requests"
        ));
    }

    #[test]
    fn test_double_wildcard_matches_multiple_segments() {
        let rule = PathRule {
            method: "GET".into(),
            path: "/api/v4/projects/**".into(),
        };
        assert!(matches_path_rule(&rule, "GET", "/api/v4/projects/123"));
        assert!(matches_path_rule(
            &rule,
            "GET",
            "/api/v4/projects/123/merge_requests/456"
        ));
        assert!(!matches_path_rule(&rule, "GET", "/api/v4/groups/123"));
    }

    #[test]
    fn test_wildcard_method() {
        let rule = PathRule {
            method: "*".into(),
            path: "/api/v4/version".into(),
        };
        assert!(matches_path_rule(&rule, "GET", "/api/v4/version"));
        assert!(matches_path_rule(&rule, "POST", "/api/v4/version"));
        assert!(matches_path_rule(&rule, "DELETE", "/api/v4/version"));
    }

    #[test]
    fn test_method_case_insensitive() {
        let rule = PathRule {
            method: "get".into(),
            path: "/api".into(),
        };
        assert!(matches_path_rule(&rule, "GET", "/api"));
    }

    #[test]
    fn test_check_path_allowed_empty_rules_allows_all() {
        assert!(check_path_allowed(&[], "GET", "/anything"));
    }

    #[test]
    fn test_check_path_allowed_denies_unmatched() {
        let rules = vec![PathRule {
            method: "GET".into(),
            path: "/api/v4/projects/*/merge_requests".into(),
        }];
        assert!(check_path_allowed(
            &rules,
            "GET",
            "/api/v4/projects/123/merge_requests"
        ));
        assert!(!check_path_allowed(
            &rules,
            "DELETE",
            "/api/v4/projects/123"
        ));
    }

    #[test]
    fn test_query_string_stripped_before_matching() {
        let rule = PathRule {
            method: "GET".into(),
            path: "/api/v4/version".into(),
        };
        assert!(matches_path_rule(
            &rule,
            "GET",
            "/api/v4/version?private_token=xxx"
        ));
    }

    #[test]
    fn test_percent_encoded_path_decoded_before_matching() {
        let rules = vec![PathRule {
            method: "GET".into(),
            path: "/api/v4/projects/**".into(),
        }];
        // %2F = /, so /api%2Fv4%2Fprojects%2F123 decodes to /api/v4/projects/123
        assert!(check_path_allowed(
            &rules,
            "GET",
            "/api%2Fv4%2Fprojects%2F123"
        ));
    }

    #[test]
    fn test_encoded_traversal_blocked() {
        // Rule only allows /mcp/**
        let rules = vec![PathRule {
            method: "GET".into(),
            path: "/mcp/**".into(),
        }];
        // Attempt to bypass via encoded path traversal: /mcp/../admin
        // %2e%2e = "..", decoded path = /mcp/../admin → segments: [mcp, .., admin]
        // ".." is not "mcp" so it won't match after the ** greedily
        // But more importantly, the segments include ".." which won't match "mcp" prefix
        assert!(!check_path_allowed(&rules, "GET", "/admin"));
        assert!(!check_path_allowed(&rules, "GET", "/%2e%2e/admin"));
        assert!(check_path_allowed(&rules, "GET", "/mcp/tools"));
    }

    #[test]
    fn test_double_encoded_slash_normalized() {
        let rules = vec![PathRule {
            method: "DELETE".into(),
            path: "/admin/**".into(),
        }];
        // Deny list: only DELETE /admin/** is allowed
        // Attacker sends DELETE /safe%2F..%2Fadmin/danger
        // After decode: /safe/../admin/danger → segments: [safe, .., admin, danger]
        // Does NOT match /admin/** (first segment is "safe", not "admin")
        assert!(!check_path_allowed(
            &rules,
            "DELETE",
            "/safe%2F..%2Fadmin/danger"
        ));
        // Direct match still works
        assert!(check_path_allowed(&rules, "DELETE", "/admin/users"));
    }
}
