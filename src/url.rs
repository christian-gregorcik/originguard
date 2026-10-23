//! A small URL splitter.
//!
//! This is not a general URL library. It extracts the parts the rest of the
//! crate reasons about: scheme, host, port and path. Everything else in a URL
//! is irrelevant to origin, cookie and policy decisions, so it is skipped
//! rather than modelled.

use std::fmt;

/// The parts of a URL that origin and policy decisions depend on.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Url {
    scheme: String,
    host: String,
    port: Option<u16>,
    path: String,
}

/// Why a URL could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UrlError {
    /// The string had no `scheme:` prefix.
    MissingScheme,
    /// The scheme contained a character a scheme may not contain.
    BadScheme,
    /// The authority was empty, so there is no host.
    MissingHost,
    /// The host contained a character a host may not contain.
    BadHost,
    /// The port was not a number, or did not fit in 16 bits.
    BadPort,
    /// An IPv6 literal was opened with `[` and never closed.
    UnterminatedIpv6,
}

impl fmt::Display for UrlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            UrlError::MissingScheme => "the URL has no scheme",
            UrlError::BadScheme => "the scheme contains an invalid character",
            UrlError::MissingHost => "the URL has no host",
            UrlError::BadHost => "the host contains an invalid character",
            UrlError::BadPort => "the port is not a number in 1..=65535",
            UrlError::UnterminatedIpv6 => "the IPv6 literal is missing a closing bracket",
        };
        f.write_str(text)
    }
}

impl std::error::Error for UrlError {}

/// The port a scheme uses when the URL does not name one.
pub fn default_port(scheme: &str) -> Option<u16> {
    match scheme {
        "http" | "ws" => Some(80),
        "https" | "wss" => Some(443),
        "ftp" => Some(21),
        _ => None,
    }
}

/// Schemes whose URLs carry a host, and so can form a tuple origin.
pub fn is_network_scheme(scheme: &str) -> bool {
    matches!(scheme, "http" | "https" | "ws" | "wss" | "ftp")
}

impl Url {
    /// Reads a URL string.
    ///
    /// The host is lowercased and a single trailing dot is removed, so
    /// `HTTPS://Example.COM./` and `https://example.com/` read the same.
    pub fn parse(input: &str) -> Result<Url, UrlError> {
        let input = input.trim();
        let colon = input.find(':').ok_or(UrlError::MissingScheme)?;
        if colon == 0 {
            return Err(UrlError::MissingScheme);
        }
        let scheme_raw = &input[..colon];
        if !is_valid_scheme(scheme_raw) {
            return Err(UrlError::BadScheme);
        }
        let scheme = scheme_raw.to_ascii_lowercase();

        let mut rest = &input[colon + 1..];
        if let Some(stripped) = rest.strip_prefix("//") {
            rest = stripped;
        }

        // The authority ends at the first `/`, `?` or `#`.
        let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = &rest[..authority_end];
        let path_raw = &rest[authority_end..];

        // Drop any userinfo. The last `@` wins, because a password may
        // legally contain one.
        let authority = match authority.rfind('@') {
            Some(at) => &authority[at + 1..],
            None => authority,
        };
        if authority.is_empty() {
            return Err(UrlError::MissingHost);
        }

        let (host_raw, port_raw) = split_host_port(authority)?;
        if host_raw.is_empty() {
            return Err(UrlError::MissingHost);
        }
        let host = normalise_host(host_raw)?;

        let port = match port_raw {
            None => None,
            Some("") => None,
            Some(digits) => {
                let value: u32 = digits.parse().map_err(|_| UrlError::BadPort)?;
                if value == 0 || value > u32::from(u16::MAX) {
                    return Err(UrlError::BadPort);
                }
                Some(value as u16)
            }
        };

        let path = if path_raw.is_empty() {
            "/".to_string()
        } else {
            let end = path_raw.find(['?', '#']).unwrap_or(path_raw.len());
            let p = &path_raw[..end];
            if p.is_empty() {
                "/".to_string()
            } else {
                p.to_string()
            }
        };

        Ok(Url {
            scheme,
            host,
            port,
            path,
        })
    }

    /// The scheme, lowercased, without the trailing colon.
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// The host, lowercased, without brackets around an IPv6 literal.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port the URL named, if it named one.
    pub fn explicit_port(&self) -> Option<u16> {
        self.port
    }

    /// The port in use: the one the URL named, else the scheme's default.
    pub fn port(&self) -> Option<u16> {
        self.port.or_else(|| default_port(&self.scheme))
    }

    /// The path, always starting with `/`, without query or fragment.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Whether the host is an IP address rather than a name.
    pub fn host_is_ip(&self) -> bool {
        host_is_ip(&self.host)
    }
}

impl fmt::Display for Url {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        write!(f, "{}://{}", self.scheme, host)?;
        if let Some(port) = self.port {
            write!(f, ":{port}")?;
        }
        f.write_str(&self.path)
    }
}

fn is_valid_scheme(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
}

fn split_host_port(authority: &str) -> Result<(&str, Option<&str>), UrlError> {
    if let Some(after_open) = authority.strip_prefix('[') {
        let close = after_open.find(']').ok_or(UrlError::UnterminatedIpv6)?;
        let host = &after_open[..close];
        let remainder = &after_open[close + 1..];
        return match remainder.strip_prefix(':') {
            Some(port) => Ok((host, Some(port))),
            None if remainder.is_empty() => Ok((host, None)),
            None => Err(UrlError::BadHost),
        };
    }
    match authority.rfind(':') {
        Some(idx) => Ok((&authority[..idx], Some(&authority[idx + 1..]))),
        None => Ok((authority, None)),
    }
}

fn normalise_host(host: &str) -> Result<String, UrlError> {
    let mut host = host.to_ascii_lowercase();
    // A single trailing dot marks the root of the DNS tree and does not
    // change which host is meant.
    if host.len() > 1 && host.ends_with('.') {
        host.pop();
    }
    if host.is_empty() {
        return Err(UrlError::MissingHost);
    }
    let ok = host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '%'));
    if !ok {
        return Err(UrlError::BadHost);
    }
    Ok(host)
}

/// Whether a host string is an IPv4 or IPv6 literal rather than a name.
pub fn host_is_ip(host: &str) -> bool {
    if host.contains(':') {
        return true;
    }
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| {
        !p.is_empty()
            && p.len() <= 3
            && p.chars().all(|c| c.is_ascii_digit())
            && p.parse::<u16>().is_ok_and(|n| n <= 255)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_usual_parts() {
        let u = Url::parse("https://example.com/a/b?q=1#frag").unwrap();
        assert_eq!(u.scheme(), "https");
        assert_eq!(u.host(), "example.com");
        assert_eq!(u.explicit_port(), None);
        assert_eq!(u.port(), Some(443));
        assert_eq!(u.path(), "/a/b");
    }

    #[test]
    fn lowercases_scheme_and_host() {
        let u = Url::parse("HTTPS://Example.COM/").unwrap();
        assert_eq!(u.scheme(), "https");
        assert_eq!(u.host(), "example.com");
    }

    #[test]
    fn drops_one_trailing_dot_on_the_host() {
        let u = Url::parse("https://example.com./").unwrap();
        assert_eq!(u.host(), "example.com");
    }

    #[test]
    fn keeps_an_explicit_port() {
        let u = Url::parse("https://example.com:8443/").unwrap();
        assert_eq!(u.explicit_port(), Some(8443));
        assert_eq!(u.port(), Some(8443));
    }

    #[test]
    fn drops_userinfo() {
        let u = Url::parse("https://user:pa@ss@example.com/x").unwrap();
        assert_eq!(u.host(), "example.com");
        assert_eq!(u.path(), "/x");
    }

    #[test]
    fn reads_ipv6_literals() {
        let u = Url::parse("http://[2001:db8::1]:8080/p").unwrap();
        assert_eq!(u.host(), "2001:db8::1");
        assert_eq!(u.port(), Some(8080));
        assert!(u.host_is_ip());
    }

    #[test]
    fn ipv6_without_a_port() {
        let u = Url::parse("http://[::1]/").unwrap();
        assert_eq!(u.host(), "::1");
        assert_eq!(u.port(), Some(80));
    }

    #[test]
    fn empty_path_becomes_slash() {
        assert_eq!(Url::parse("https://example.com").unwrap().path(), "/");
        assert_eq!(Url::parse("https://example.com?q").unwrap().path(), "/");
    }

    #[test]
    fn rejects_what_it_should() {
        assert_eq!(Url::parse("example.com"), Err(UrlError::MissingScheme));
        assert_eq!(Url::parse(":///x"), Err(UrlError::MissingScheme));
        assert_eq!(Url::parse("9http://example.com"), Err(UrlError::BadScheme));
        assert_eq!(Url::parse("https:///path"), Err(UrlError::MissingHost));
        assert_eq!(Url::parse("https://example.com:0/"), Err(UrlError::BadPort));
        assert_eq!(
            Url::parse("https://example.com:70000/"),
            Err(UrlError::BadPort)
        );
        assert_eq!(
            Url::parse("https://example.com:ab/"),
            Err(UrlError::BadPort)
        );
        assert_eq!(Url::parse("http://[::1/"), Err(UrlError::UnterminatedIpv6));
    }

    #[test]
    fn round_trips_through_display() {
        for text in [
            "https://example.com/",
            "http://[2001:db8::1]:8080/p",
            "https://example.com:8443/a",
        ] {
            let u = Url::parse(text).unwrap();
            assert_eq!(u.to_string(), text);
        }
    }

    #[test]
    fn recognises_ip_hosts() {
        assert!(host_is_ip("127.0.0.1"));
        assert!(host_is_ip("255.255.255.255"));
        assert!(host_is_ip("::1"));
        assert!(!host_is_ip("256.1.1.1"));
        assert!(!host_is_ip("example.com"));
        assert!(!host_is_ip("1.2.3"));
        assert!(!host_is_ip("01.2.3.4444"));
    }
}
