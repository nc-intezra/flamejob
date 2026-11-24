//! Pure directory helpers: SID formatting, LDAP filter/DN escaping, bind-error
//! decoding and the empty-password guard. None of this touches the network, so
//! it is all exercised by unit tests in CI (which has no directory server).

/// Format a binary `objectSid`/`tokenGroups` value as the canonical string form
/// `S-1-5-21-…-<rid>`. Returns `None` if the buffer is malformed.
///
/// Layout (MS-DTYP SID): byte 0 revision, byte 1 sub-authority count N,
/// bytes 2..8 the 48-bit identifier authority (big-endian), then N 32-bit
/// sub-authorities (little-endian).
pub fn format_sid(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 8 {
        return None;
    }
    let revision = bytes[0];
    let sub_count = bytes[1] as usize;
    if bytes.len() != 8 + sub_count * 4 {
        return None;
    }
    // 48-bit identifier authority, big-endian.
    let mut authority: u64 = 0;
    for &b in &bytes[2..8] {
        authority = (authority << 8) | b as u64;
    }
    let mut out = format!("S-{revision}-{authority}");
    let mut idx = 8;
    for _ in 0..sub_count {
        let sa = u32::from_le_bytes([bytes[idx], bytes[idx + 1], bytes[idx + 2], bytes[idx + 3]]);
        out.push_str(&format!("-{sa}"));
        idx += 4;
    }
    Some(out)
}

/// Escape a user-supplied string for safe interpolation into an LDAP search
/// filter, per RFC 4515. Prevents LDAP injection; `ldap3` does not parameterize
/// filters, so this is the application's responsibility.
pub fn escape_filter(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        match b {
            b'*' => out.push_str("\\2a"),
            b'(' => out.push_str("\\28"),
            b')' => out.push_str("\\29"),
            b'\\' => out.push_str("\\5c"),
            0 => out.push_str("\\00"),
            _ => out.push(b as char),
        }
    }
    out
}

/// Escape a raw byte value (e.g. a binary `objectSid`) for use as an LDAP filter
/// assertion value: every byte becomes a `\XX` hex escape. (Used by the
/// group-search-by-SID path landing in PR2; kept here with its tests.)
#[allow(dead_code)]
pub fn escape_filter_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);
    for b in bytes {
        out.push_str(&format!("\\{b:02x}"));
    }
    out
}

/// Escape a value for use in a distinguished-name component, per RFC 4514.
/// (Used by DN-building paths in a later increment; kept here with its tests.)
#[allow(dead_code)]
pub fn escape_dn_value(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let chars: Vec<char> = input.chars().collect();
    for (i, &c) in chars.iter().enumerate() {
        let leading = i == 0;
        let trailing = i == chars.len() - 1;
        match c {
            '"' | '+' | ',' | ';' | '<' | '>' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            '#' if leading => {
                out.push('\\');
                out.push(c);
            }
            ' ' if leading || trailing => {
                out.push('\\');
                out.push(c);
            }
            '\0' => out.push_str("\\00"),
            _ => out.push(c),
        }
    }
    out
}

/// A login password that is empty or whitespace-only must be rejected *before*
/// any bind: AD can treat a non-empty DN with an empty password as a successful
/// "unauthenticated bind". Returns true if the password is acceptable to attempt.
pub fn password_is_bindable(password: &str) -> bool {
    !password.trim().is_empty()
}

/// Decode an LDAP bind failure into operator-facing text. AD reports the real
/// reason as a `data <hex>` sub-code inside the result-49 diagnostic message;
/// `sub_code` is that hex token (e.g. "52e") when present.
pub fn describe_bind_error(result_code: u32, sub_code: Option<&str>) -> String {
    if result_code == 49 {
        let detail = match sub_code.map(|s| s.to_ascii_lowercase()) {
            Some(ref s) if s == "52e" => "invalid credentials",
            Some(ref s) if s == "525" => "no such user",
            Some(ref s) if s == "530" => "not permitted to sign in at this time",
            Some(ref s) if s == "531" => "not permitted to sign in from this workstation",
            Some(ref s) if s == "532" => "password expired",
            Some(ref s) if s == "533" => "account disabled",
            Some(ref s) if s == "701" => "account expired",
            Some(ref s) if s == "773" => "password must be reset",
            Some(ref s) if s == "775" => "account locked out",
            _ => "invalid credentials",
        };
        return detail.to_string();
    }
    format!("bind failed (LDAP result {result_code})")
}

/// Extract the AD `data <hex>` sub-code from a result-49 diagnostic message,
/// e.g. "... data 52e, v2580" -> "52e".
pub fn extract_ad_sub_code(diagnostic: &str) -> Option<String> {
    let lower = diagnostic.to_ascii_lowercase();
    let after = lower.split("data ").nth(1)?;
    let token: String = after
        .chars()
        .take_while(|c| c.is_ascii_hexdigit())
        .collect();
    (!token.is_empty()).then_some(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sid_well_known_and_domain() {
        // S-1-5-18 (Local System): rev 1, 1 sub-authority, authority 5, sub 18.
        let bytes = [0x01, 0x01, 0, 0, 0, 0, 0, 0x05, 0x12, 0, 0, 0];
        assert_eq!(format_sid(&bytes).as_deref(), Some("S-1-5-18"));

        // A domain group RID: S-1-5-21-1-2-3-1104.
        let mut b = vec![0x01, 0x05, 0, 0, 0, 0, 0, 0x05];
        for sa in [21u32, 1, 2, 3, 1104] {
            b.extend_from_slice(&sa.to_le_bytes());
        }
        assert_eq!(format_sid(&b).as_deref(), Some("S-1-5-21-1-2-3-1104"));
    }

    #[test]
    fn sid_rejects_malformed() {
        assert_eq!(format_sid(&[0x01, 0x01, 0, 0, 0, 0, 0, 0x05]), None); // count says 1 sub, none present
        assert_eq!(format_sid(&[]), None);
        assert_eq!(
            format_sid(&[0x01, 0x00, 0, 0, 0, 0, 0, 0x05]),
            Some("S-1-5".into())
        );
    }

    #[test]
    fn filter_escaping_blocks_injection() {
        // The classic injection attempt must be neutralised.
        assert_eq!(escape_filter("*)(uid=*"), "\\2a\\29\\28uid=\\2a");
        assert_eq!(escape_filter("a\\b"), "a\\5cb");
        assert_eq!(escape_filter("plain.user"), "plain.user");
    }

    #[test]
    fn filter_bytes_escaping() {
        assert_eq!(escape_filter_bytes(&[0x01, 0x05, 0xff]), "\\01\\05\\ff");
    }

    #[test]
    fn dn_escaping() {
        assert_eq!(escape_dn_value("Smith, John"), "Smith\\, John");
        assert_eq!(escape_dn_value(" lead"), "\\ lead");
        assert_eq!(escape_dn_value("#hash"), "\\#hash");
    }

    #[test]
    fn empty_password_guard() {
        assert!(!password_is_bindable(""));
        assert!(!password_is_bindable("   "));
        assert!(!password_is_bindable("\t\n"));
        assert!(password_is_bindable("hunter2"));
    }

    #[test]
    fn bind_error_decoding() {
        assert_eq!(describe_bind_error(49, Some("533")), "account disabled");
        assert_eq!(describe_bind_error(49, Some("775")), "account locked out");
        assert_eq!(describe_bind_error(49, Some("52e")), "invalid credentials");
        assert_eq!(describe_bind_error(49, None), "invalid credentials");
        assert!(describe_bind_error(53, None).contains("result 53"));
    }

    #[test]
    fn ad_sub_code_extraction() {
        assert_eq!(
            extract_ad_sub_code("80090308: LdapErr: DSID-0C09, comment: AcceptSecurityContext error, data 52e, v2580")
                .as_deref(),
            Some("52e")
        );
        assert_eq!(extract_ad_sub_code("no code here"), None);
    }
}
