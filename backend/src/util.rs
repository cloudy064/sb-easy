//! Small shared helpers.

/// Percent-encode a string for safe use as a URL query-parameter value.
/// Encodes everything outside the RFC 3986 "unreserved" set.
pub fn encode_query_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unreserved_chars_pass_through() {
        assert_eq!(encode_query_component("Aa0-_.~"), "Aa0-_.~");
    }

    #[test]
    fn special_chars_are_percent_encoded() {
        assert_eq!(encode_query_component("a b"), "a%20b");
        assert_eq!(encode_query_component("a/b?c=d&e"), "a%2Fb%3Fc%3Dd%26e");
        assert_eq!(encode_query_component("100%"), "100%25");
    }

    #[test]
    fn utf8_is_encoded_per_byte() {
        // "中" is 3 UTF-8 bytes, each percent-encoded.
        assert_eq!(encode_query_component("中"), "%E4%B8%AD");
    }
}
