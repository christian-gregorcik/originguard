//! Origins and the same-origin policy.
//!
//! An origin is a scheme, a host and a port. Two URLs are same-origin when
//! all three match. `https://example.com/a` and `https://example.com:443/b`
//! are same-origin because 443 is the default port for https;
//! `http://example.com/` is not, because the scheme differs.
//!
//! Some URLs have no tuple origin at all. A `data:` URL, a sandboxed frame
//! or a `blob:` with no inner URL gets an opaque origin, which is
//! same-origin with nothing, not even another opaque origin. That is what
//! origin isolation rests on, so it is modelled here rather than approximated
//! with `None`.

use crate::url::{is_network_scheme, Url};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_OPAQUE_ID: AtomicU64 = AtomicU64::new(1);

/// The origin of a URL or a document.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Origin {
    /// A scheme, host and port that can be compared with another.
    Tuple {
        /// The scheme, lowercased.
        scheme: String,
        /// The host, lowercased.
        host: String,
        /// The port in use, including the scheme default.
        port: Option<u16>,
    },
    /// An origin that is same-origin with nothing, including itself.
    ///
    /// The identifier distinguishes one opaque origin from another so that
    /// two sandboxed frames are not accidentally treated as the same.
    Opaque(u64),
}

impl Origin {
    /// The origin of a URL.
    ///
    /// URLs whose scheme carries no host, such as `data:` and `about:`, get
    /// a fresh opaque origin.
    pub fn of(url: &Url) -> Origin {
        if !is_network_scheme(url.scheme()) {
            return Origin::new_opaque();
        }
        Origin::Tuple {
            scheme: url.scheme().to_string(),
            host: url.host().to_string(),
            port: url.port(),
        }
    }

    /// A fresh opaque origin, distinct from every other origin.
    pub fn new_opaque() -> Origin {
        Origin::Opaque(NEXT_OPAQUE_ID.fetch_add(1, Ordering::Relaxed))
    }

    /// Whether this origin is opaque.
    pub fn is_opaque(&self) -> bool {
        matches!(self, Origin::Opaque(_))
    }

    /// The scheme, for a tuple origin.
    pub fn scheme(&self) -> Option<&str> {
        match self {
            Origin::Tuple { scheme, .. } => Some(scheme),
            Origin::Opaque(_) => None,
        }
    }

    /// The host, for a tuple origin.
    pub fn host(&self) -> Option<&str> {
        match self {
            Origin::Tuple { host, .. } => Some(host),
            Origin::Opaque(_) => None,
        }
    }

    /// The port, for a tuple origin.
    pub fn port(&self) -> Option<u16> {
        match self {
            Origin::Tuple { port, .. } => *port,
            Origin::Opaque(_) => None,
        }
    }

    /// Whether two origins are the same origin.
    ///
    /// An opaque origin is same-origin with nothing, including a copy of
    /// itself, because sameness here means "the same document", not "equal
    /// values".
    pub fn same_origin(&self, other: &Origin) -> bool {
        match (self, other) {
            (Origin::Opaque(_), _) | (_, Origin::Opaque(_)) => false,
            (a, b) => a == b,
        }
    }

    /// The value an `Origin:` request header would carry.
    ///
    /// Opaque origins serialise as `null`, which is what a sandboxed frame
    /// sends.
    pub fn serialize(&self) -> String {
        match self {
            Origin::Opaque(_) => "null".to_string(),
            Origin::Tuple { scheme, host, port } => {
                let host = if host.contains(':') {
                    format!("[{host}]")
                } else {
                    host.clone()
                };
                match (port, crate::url::default_port(scheme)) {
                    (Some(p), Some(d)) if *p == d => format!("{scheme}://{host}"),
                    (Some(p), _) => format!("{scheme}://{host}:{p}"),
                    (None, _) => format!("{scheme}://{host}"),
                }
            }
        }
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.serialize())
    }
}

/// Whether two URLs are same-origin.
pub fn same_origin(a: &Url, b: &Url) -> bool {
    Origin::of(a).same_origin(&Origin::of(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn identical_urls_are_same_origin() {
        assert!(same_origin(
            &u("https://example.com/a"),
            &u("https://example.com/b")
        ));
    }

    #[test]
    fn the_default_port_is_the_same_port() {
        assert!(same_origin(
            &u("https://example.com/a"),
            &u("https://example.com:443/b")
        ));
        assert!(same_origin(
            &u("http://example.com/"),
            &u("http://example.com:80/")
        ));
    }

    #[test]
    fn scheme_host_and_port_must_all_match() {
        assert!(!same_origin(
            &u("https://example.com/"),
            &u("http://example.com/")
        ));
        assert!(!same_origin(
            &u("https://example.com/"),
            &u("https://www.example.com/")
        ));
        assert!(!same_origin(
            &u("https://example.com/"),
            &u("https://example.com:8443/")
        ));
    }

    #[test]
    fn subdomains_are_not_the_same_origin() {
        assert!(!same_origin(
            &u("https://a.example.com/"),
            &u("https://b.example.com/")
        ));
    }

    #[test]
    fn opaque_origins_match_nothing() {
        let a = Origin::new_opaque();
        let b = a.clone();
        assert!(!a.same_origin(&b));
        assert!(!a.same_origin(&Origin::of(&u("https://example.com/"))));
        assert!(a.is_opaque());
    }

    #[test]
    fn every_opaque_origin_is_distinct() {
        let a = Origin::new_opaque();
        let b = Origin::new_opaque();
        assert_ne!(a, b);
    }

    #[test]
    fn schemes_without_a_host_get_an_opaque_origin() {
        let o = Origin::of(&u("data:text/html,hello"));
        assert!(o.is_opaque());
        assert_eq!(o.serialize(), "null");
    }

    #[test]
    fn serialises_the_way_the_header_does() {
        assert_eq!(
            Origin::of(&u("https://example.com/a")).serialize(),
            "https://example.com"
        );
        assert_eq!(
            Origin::of(&u("https://example.com:8443/a")).serialize(),
            "https://example.com:8443"
        );
        assert_eq!(
            Origin::of(&u("http://[::1]:8080/")).serialize(),
            "http://[::1]:8080"
        );
    }

    #[test]
    fn exposes_its_parts() {
        let o = Origin::of(&u("https://example.com:8443/"));
        assert_eq!(o.scheme(), Some("https"));
        assert_eq!(o.host(), Some("example.com"));
        assert_eq!(o.port(), Some(8443));

        let opaque = Origin::new_opaque();
        assert_eq!(opaque.scheme(), None);
        assert_eq!(opaque.host(), None);
        assert_eq!(opaque.port(), None);
    }
}
