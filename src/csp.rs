//! Content-Security-Policy: parsing a policy and deciding what it allows.
//!
//! A policy is a list of directives, each with a list of source expressions.
//! The question a browser asks is always the same: this document has this
//! policy, it is about to load this URL for this purpose, is that allowed?
//!
//! The rules that make the answer non-obvious are all here: the fallback
//! chain from `script-src-elem` through `script-src` to `default-src`, the
//! wildcard and scheme matching in a host source, the upgrade that lets an
//! `http:` source match an `https:` URL, and nonces and hashes for inline
//! content.

use crate::origin::Origin;
use crate::url::Url;
use std::collections::BTreeMap;
use std::fmt;

/// One source expression inside a directive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// `'none'`: nothing matches, and nothing else in the list counts.
    None,
    /// `'self'`: the document's own origin.
    SelfOrigin,
    /// `'unsafe-inline'`: inline script or style may run.
    UnsafeInline,
    /// `'unsafe-eval'`: `eval` and friends may run.
    UnsafeEval,
    /// `'strict-dynamic'`: trust propagates from a nonced or hashed script.
    StrictDynamic,
    /// `'nonce-...'`: inline content carrying this nonce may run.
    Nonce(String),
    /// `'sha256-...'` and friends: inline content with this hash may run.
    Hash { algorithm: String, value: String },
    /// `https:`: any URL with this scheme.
    Scheme(String),
    /// A host expression, possibly with scheme, wildcard, port and path.
    Host(HostSource),
    /// `*`: any URL with a network scheme.
    Wildcard,
    /// Something the parser did not recognise, kept so it can be reported.
    Unknown(String),
}

/// A host source expression such as `https://*.example.com:443/assets/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostSource {
    /// The scheme, if the expression named one.
    pub scheme: Option<String>,
    /// The host, without a leading `*.`.
    pub host: String,
    /// Whether the expression began with `*.`, covering subdomains.
    pub wildcard_subdomain: bool,
    /// The port: `Some(None)` is `:*`, `Some(Some(n))` is a number.
    pub port: Option<Option<u16>>,
    /// The path prefix, if the expression named one.
    pub path: Option<String>,
}

/// A parsed Content-Security-Policy.
#[derive(Debug, Clone, Default)]
pub struct Policy {
    directives: BTreeMap<String, Vec<Source>>,
    /// Directive names that appeared more than once, which browsers ignore
    /// after the first.
    pub duplicates: Vec<String>,
}

/// What kind of load is being checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A `<script src>` element.
    ScriptElement,
    /// A script-like load that is not an element, such as a worker import.
    Script,
    /// A `<link rel=stylesheet>` or `@import`.
    StyleElement,
    /// A style-like load.
    Style,
    /// An image.
    Image,
    /// A font.
    Font,
    /// `fetch`, `XMLHttpRequest`, `EventSource`, a WebSocket.
    Connect,
    /// A frame or iframe.
    Frame,
    /// Anything else, which falls straight back to `default-src`.
    Other,
}

impl Kind {
    /// The directives to try, most specific first.
    pub fn fallback_chain(self) -> &'static [&'static str] {
        match self {
            Kind::ScriptElement => &["script-src-elem", "script-src", "default-src"],
            Kind::Script => &["script-src", "default-src"],
            Kind::StyleElement => &["style-src-elem", "style-src", "default-src"],
            Kind::Style => &["style-src", "default-src"],
            Kind::Image => &["img-src", "default-src"],
            Kind::Font => &["font-src", "default-src"],
            Kind::Connect => &["connect-src", "default-src"],
            // frame-src falls back to child-src before default-src.
            Kind::Frame => &["frame-src", "child-src", "default-src"],
            Kind::Other => &["default-src"],
        }
    }
}

/// The verdict on one load.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The policy has nothing to say, so the load proceeds.
    NoPolicy,
    /// A directive matched and allows the load.
    Allowed {
        /// Which directive decided.
        directive: String,
    },
    /// A directive matched and blocks the load.
    Blocked {
        /// Which directive decided.
        directive: String,
    },
}

impl Decision {
    /// Whether the load proceeds.
    pub fn is_allowed(&self) -> bool {
        !matches!(self, Decision::Blocked { .. })
    }
}

impl Policy {
    /// Reads one `Content-Security-Policy` header value.
    ///
    /// A directive that appears twice is kept as its first occurrence, which
    /// is what browsers do, and its name is recorded in `duplicates`.
    pub fn parse(header: &str) -> Policy {
        let mut policy = Policy::default();
        for raw in header.split(';') {
            let raw = raw.trim();
            if raw.is_empty() {
                continue;
            }
            let mut tokens = raw.split_whitespace();
            let name = match tokens.next() {
                Some(n) => n.to_ascii_lowercase(),
                None => continue,
            };
            if policy.directives.contains_key(&name) {
                policy.duplicates.push(name);
                continue;
            }
            let sources: Vec<Source> = tokens.map(parse_source).collect();
            policy.directives.insert(name, sources);
        }
        policy
    }

    /// The source list of a directive, if the policy names it.
    pub fn directive(&self, name: &str) -> Option<&[Source]> {
        self.directives.get(name).map(|v| v.as_slice())
    }

    /// Every directive name in the policy, in order.
    pub fn directive_names(&self) -> impl Iterator<Item = &str> {
        self.directives.keys().map(|s| s.as_str())
    }

    /// Whether the policy says anything at all.
    pub fn is_empty(&self) -> bool {
        self.directives.is_empty()
    }

    /// Whether the policy allows loading `url` for `kind` in `document`.
    pub fn allows(&self, kind: Kind, url: &Url, document: &Origin) -> Decision {
        let Some((name, sources)) = self.effective(kind) else {
            return Decision::NoPolicy;
        };
        let allowed = sources.iter().any(|s| source_matches(s, url, document));
        if allowed {
            Decision::Allowed {
                directive: name.to_string(),
            }
        } else {
            Decision::Blocked {
                directive: name.to_string(),
            }
        }
    }

    /// Whether inline content with this nonce may run.
    pub fn allows_inline_with_nonce(&self, kind: Kind, nonce: &str) -> Decision {
        self.inline_decision(kind, |s| matches!(s, Source::Nonce(n) if n == nonce))
    }

    /// Whether inline content with this hash may run.
    ///
    /// `algorithm` is `sha256`, `sha384` or `sha512`; `value` is the base64
    /// digest as it appears in the policy.
    pub fn allows_inline_with_hash(&self, kind: Kind, algorithm: &str, value: &str) -> Decision {
        self.inline_decision(kind, |s| {
            matches!(s, Source::Hash { algorithm: a, value: v }
                if a.eq_ignore_ascii_case(algorithm) && v == value)
        })
    }

    /// Whether unadorned inline content may run.
    ///
    /// A nonce or hash in the same directive turns `'unsafe-inline'` off,
    /// which is the rule that makes a nonce worth using.
    pub fn allows_unsafe_inline(&self, kind: Kind) -> Decision {
        let Some((name, sources)) = self.effective(kind) else {
            return Decision::NoPolicy;
        };
        let has_nonce_or_hash = sources
            .iter()
            .any(|s| matches!(s, Source::Nonce(_) | Source::Hash { .. }));
        let allowed =
            !has_nonce_or_hash && sources.iter().any(|s| matches!(s, Source::UnsafeInline));
        decide(name, allowed)
    }

    /// Whether `eval` may run.
    pub fn allows_eval(&self, kind: Kind) -> Decision {
        self.inline_decision(kind, |s| matches!(s, Source::UnsafeEval))
    }

    fn inline_decision(&self, kind: Kind, pred: impl Fn(&Source) -> bool) -> Decision {
        let Some((name, sources)) = self.effective(kind) else {
            return Decision::NoPolicy;
        };
        decide(name, sources.iter().any(pred))
    }

    /// The directive that governs `kind`, following the fallback chain.
    pub fn effective(&self, kind: Kind) -> Option<(&str, &[Source])> {
        for name in kind.fallback_chain() {
            if let Some((k, v)) = self.directives.get_key_value(*name) {
                return Some((k.as_str(), v.as_slice()));
            }
        }
        None
    }
}

fn decide(name: &str, allowed: bool) -> Decision {
    if allowed {
        Decision::Allowed {
            directive: name.to_string(),
        }
    } else {
        Decision::Blocked {
            directive: name.to_string(),
        }
    }
}

impl fmt::Display for Policy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for (name, sources) in &self.directives {
            if !first {
                f.write_str("; ")?;
            }
            first = false;
            f.write_str(name)?;
            for s in sources {
                write!(f, " {s}")?;
            }
        }
        Ok(())
    }
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Source::None => f.write_str("'none'"),
            Source::SelfOrigin => f.write_str("'self'"),
            Source::UnsafeInline => f.write_str("'unsafe-inline'"),
            Source::UnsafeEval => f.write_str("'unsafe-eval'"),
            Source::StrictDynamic => f.write_str("'strict-dynamic'"),
            Source::Nonce(n) => write!(f, "'nonce-{n}'"),
            Source::Hash { algorithm, value } => write!(f, "'{algorithm}-{value}'"),
            Source::Scheme(s) => write!(f, "{s}:"),
            Source::Wildcard => f.write_str("*"),
            Source::Unknown(s) => f.write_str(s),
            Source::Host(h) => {
                if let Some(scheme) = &h.scheme {
                    write!(f, "{scheme}://")?;
                }
                if h.wildcard_subdomain {
                    f.write_str("*.")?;
                }
                f.write_str(&h.host)?;
                match h.port {
                    Some(Some(p)) => write!(f, ":{p}")?,
                    Some(None) => f.write_str(":*")?,
                    None => {}
                }
                if let Some(p) = &h.path {
                    f.write_str(p)?;
                }
                Ok(())
            }
        }
    }
}

/// Reads one source expression.
pub fn parse_source(token: &str) -> Source {
    let lower = token.to_ascii_lowercase();
    if token.starts_with('\'') && token.ends_with('\'') && token.len() >= 2 {
        let inner = &token[1..token.len() - 1];
        let inner_lower = inner.to_ascii_lowercase();
        return match inner_lower.as_str() {
            "none" => Source::None,
            "self" => Source::SelfOrigin,
            "unsafe-inline" => Source::UnsafeInline,
            "unsafe-eval" => Source::UnsafeEval,
            "strict-dynamic" => Source::StrictDynamic,
            _ => {
                if let Some(value) = inner.strip_prefix("nonce-") {
                    Source::Nonce(value.to_string())
                } else if let Some(value) = inner.strip_prefix("sha256-") {
                    Source::Hash {
                        algorithm: "sha256".into(),
                        value: value.to_string(),
                    }
                } else if let Some(value) = inner.strip_prefix("sha384-") {
                    Source::Hash {
                        algorithm: "sha384".into(),
                        value: value.to_string(),
                    }
                } else if let Some(value) = inner.strip_prefix("sha512-") {
                    Source::Hash {
                        algorithm: "sha512".into(),
                        value: value.to_string(),
                    }
                } else {
                    Source::Unknown(token.to_string())
                }
            }
        };
    }

    if token == "*" {
        return Source::Wildcard;
    }

    // `https:` with nothing after the colon is a scheme source.
    if let Some(scheme) = lower.strip_suffix(':') {
        if !scheme.is_empty() && is_scheme_token(scheme) {
            return Source::Scheme(scheme.to_string());
        }
    }

    parse_host_source(token)
        .map(Source::Host)
        .unwrap_or_else(|| Source::Unknown(token.to_string()))
}

fn is_scheme_token(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

fn parse_host_source(token: &str) -> Option<HostSource> {
    let mut rest = token;
    let mut scheme = None;
    if let Some(idx) = rest.find("://") {
        let s = &rest[..idx];
        if !is_scheme_token(&s.to_ascii_lowercase()) {
            return None;
        }
        scheme = Some(s.to_ascii_lowercase());
        rest = &rest[idx + 3..];
    }

    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], Some(rest[i..].to_string())),
        None => (rest, None),
    };
    if hostport.is_empty() {
        return None;
    }

    let (host_raw, port) = match hostport.rfind(':') {
        Some(i) => {
            let p = &hostport[i + 1..];
            let parsed = if p == "*" {
                Some(None)
            } else {
                Some(Some(p.parse::<u16>().ok()?))
            };
            (&hostport[..i], parsed)
        }
        None => (hostport, None),
    };

    let (wildcard_subdomain, host) = match host_raw.strip_prefix("*.") {
        Some(h) => (true, h),
        None => (false, host_raw),
    };
    if host.is_empty() || host.contains('*') {
        return None;
    }

    Some(HostSource {
        scheme,
        host: host.to_ascii_lowercase(),
        wildcard_subdomain,
        port,
        path,
    })
}

/// Whether a scheme in a source expression covers a URL's scheme.
///
/// An `http:` source also covers `https:`, and `ws:` covers `wss:`, so a
/// policy written before a site moved to TLS does not block it afterwards.
pub fn scheme_matches(source_scheme: &str, url_scheme: &str) -> bool {
    if source_scheme == url_scheme {
        return true;
    }
    matches!(
        (source_scheme, url_scheme),
        ("http", "https") | ("ws", "wss") | ("http", "wss") | ("http", "ws")
    )
}

fn host_matches(source: &HostSource, url: &Url) -> bool {
    let url_host = url.host();
    if source.wildcard_subdomain {
        if !url_host.ends_with(&format!(".{}", source.host)) {
            return false;
        }
    } else if url_host != source.host {
        return false;
    }
    true
}

fn port_matches(source: &HostSource, url: &Url) -> bool {
    match source.port {
        Some(None) => true,
        Some(Some(p)) => url.port() == Some(p),
        None => {
            // No port in the source: the URL must sit on the default port of
            // its own scheme. The source's scheme does not enter into it, so
            // `http://example.com` still covers `https://example.com` on 443.
            match (url.port(), crate::url::default_port(url.scheme())) {
                (Some(a), Some(b)) => a == b,
                _ => false,
            }
        }
    }
}

fn path_matches(source: &HostSource, url: &Url) -> bool {
    let Some(prefix) = &source.path else {
        return true;
    };
    if prefix == "/" {
        return true;
    }
    if prefix.ends_with('/') {
        return url.path().starts_with(prefix.as_str());
    }
    // A path with no trailing slash matches exactly.
    url.path() == prefix
}

/// Whether one source expression covers a URL.
pub fn source_matches(source: &Source, url: &Url, document: &Origin) -> bool {
    match source {
        Source::None => false,
        Source::UnsafeInline | Source::UnsafeEval | Source::StrictDynamic => false,
        Source::Nonce(_) | Source::Hash { .. } => false,
        Source::Unknown(_) => false,
        Source::Wildcard => crate::url::is_network_scheme(url.scheme()),
        Source::Scheme(s) => scheme_matches(s, url.scheme()),
        Source::SelfOrigin => Origin::of(url).same_origin(document),
        Source::Host(h) => {
            if let Some(scheme) = &h.scheme {
                if !scheme_matches(scheme, url.scheme()) {
                    return false;
                }
            } else if let Some(doc_scheme) = document.scheme() {
                if !scheme_matches(doc_scheme, url.scheme()) {
                    return false;
                }
            }
            host_matches(h, url) && port_matches(h, url) && path_matches(h, url)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    fn doc(s: &str) -> Origin {
        Origin::of(&u(s))
    }

    #[test]
    fn parses_directives_and_sources() {
        let p = Policy::parse("default-src 'self'; script-src 'self' https://cdn.example.com");
        assert_eq!(p.directive("default-src"), Some(&[Source::SelfOrigin][..]));
        let script = p.directive("script-src").unwrap();
        assert_eq!(script.len(), 2);
        assert_eq!(script[0], Source::SelfOrigin);
        assert!(matches!(&script[1], Source::Host(h) if h.host == "cdn.example.com"));
    }

    #[test]
    fn keeps_the_first_of_a_duplicated_directive() {
        let p = Policy::parse("script-src 'self'; script-src *");
        assert_eq!(p.directive("script-src"), Some(&[Source::SelfOrigin][..]));
        assert_eq!(p.duplicates, vec!["script-src".to_string()]);
    }

    #[test]
    fn self_means_the_document_origin() {
        let p = Policy::parse("img-src 'self'");
        let d = doc("https://example.com/page");
        assert!(p
            .allows(Kind::Image, &u("https://example.com/a.png"), &d)
            .is_allowed());
        assert!(!p
            .allows(Kind::Image, &u("https://other.com/a.png"), &d)
            .is_allowed());
        // Different port is a different origin.
        assert!(!p
            .allows(Kind::Image, &u("https://example.com:8443/a.png"), &d)
            .is_allowed());
    }

    #[test]
    fn none_blocks_everything() {
        let p = Policy::parse("default-src 'none'");
        let d = doc("https://example.com/");
        assert_eq!(
            p.allows(Kind::Image, &u("https://example.com/a.png"), &d),
            Decision::Blocked {
                directive: "default-src".into()
            }
        );
    }

    #[test]
    fn a_missing_directive_means_no_opinion() {
        let p = Policy::parse("img-src 'self'");
        let d = doc("https://example.com/");
        assert_eq!(
            p.allows(Kind::Script, &u("https://cdn.example.com/x.js"), &d),
            Decision::NoPolicy
        );
    }

    #[test]
    fn script_element_falls_back_through_script_src_to_default_src() {
        let d = doc("https://example.com/");
        let url = u("https://cdn.example.com/x.js");

        let only_default = Policy::parse("default-src https://cdn.example.com");
        assert_eq!(
            only_default.allows(Kind::ScriptElement, &url, &d),
            Decision::Allowed {
                directive: "default-src".into()
            }
        );

        let with_script = Policy::parse("default-src 'none'; script-src https://cdn.example.com");
        assert_eq!(
            with_script.allows(Kind::ScriptElement, &url, &d),
            Decision::Allowed {
                directive: "script-src".into()
            }
        );

        let with_elem = Policy::parse(
            "default-src 'none'; script-src https://cdn.example.com; script-src-elem 'none'",
        );
        assert_eq!(
            with_elem.allows(Kind::ScriptElement, &url, &d),
            Decision::Blocked {
                directive: "script-src-elem".into()
            }
        );
    }

    #[test]
    fn frames_fall_back_through_child_src() {
        let d = doc("https://example.com/");
        let url = u("https://frames.example.net/a");
        let p = Policy::parse("default-src 'none'; child-src https://frames.example.net");
        assert_eq!(
            p.allows(Kind::Frame, &url, &d),
            Decision::Allowed {
                directive: "child-src".into()
            }
        );
    }

    #[test]
    fn wildcard_subdomains_do_not_match_the_bare_host() {
        let p = Policy::parse("img-src https://*.example.com");
        let d = doc("https://site.test/");
        assert!(p
            .allows(Kind::Image, &u("https://a.example.com/x.png"), &d)
            .is_allowed());
        assert!(p
            .allows(Kind::Image, &u("https://a.b.example.com/x.png"), &d)
            .is_allowed());
        assert!(!p
            .allows(Kind::Image, &u("https://example.com/x.png"), &d)
            .is_allowed());
        assert!(!p
            .allows(Kind::Image, &u("https://notexample.com/x.png"), &d)
            .is_allowed());
    }

    #[test]
    fn an_http_source_also_covers_https() {
        let p = Policy::parse("img-src http://example.com");
        let d = doc("https://site.test/");
        assert!(p
            .allows(Kind::Image, &u("https://example.com/x.png"), &d)
            .is_allowed());
        assert!(p
            .allows(Kind::Image, &u("http://example.com/x.png"), &d)
            .is_allowed());
    }

    #[test]
    fn an_https_source_does_not_cover_http() {
        let p = Policy::parse("img-src https://example.com");
        let d = doc("https://site.test/");
        assert!(!p
            .allows(Kind::Image, &u("http://example.com/x.png"), &d)
            .is_allowed());
    }

    #[test]
    fn scheme_sources_match_any_host() {
        let p = Policy::parse("img-src https:");
        let d = doc("https://site.test/");
        assert!(p
            .allows(Kind::Image, &u("https://anything.example/x.png"), &d)
            .is_allowed());
        assert!(!p
            .allows(Kind::Image, &u("http://anything.example/x.png"), &d)
            .is_allowed());
    }

    #[test]
    fn ports_must_match_unless_the_source_says_star() {
        let d = doc("https://site.test/");
        let exact = Policy::parse("img-src https://example.com:8443");
        assert!(exact
            .allows(Kind::Image, &u("https://example.com:8443/x"), &d)
            .is_allowed());
        assert!(!exact
            .allows(Kind::Image, &u("https://example.com/x"), &d)
            .is_allowed());

        let any = Policy::parse("img-src https://example.com:*");
        assert!(any
            .allows(Kind::Image, &u("https://example.com:8443/x"), &d)
            .is_allowed());
        assert!(any
            .allows(Kind::Image, &u("https://example.com/x"), &d)
            .is_allowed());

        let default = Policy::parse("img-src https://example.com");
        assert!(default
            .allows(Kind::Image, &u("https://example.com/x"), &d)
            .is_allowed());
        assert!(!default
            .allows(Kind::Image, &u("https://example.com:8443/x"), &d)
            .is_allowed());
    }

    #[test]
    fn a_path_ending_in_slash_is_a_prefix() {
        let d = doc("https://site.test/");
        let p = Policy::parse("img-src https://example.com/assets/");
        assert!(p
            .allows(Kind::Image, &u("https://example.com/assets/a.png"), &d)
            .is_allowed());
        assert!(p
            .allows(Kind::Image, &u("https://example.com/assets/deep/a.png"), &d)
            .is_allowed());
        assert!(!p
            .allows(Kind::Image, &u("https://example.com/other/a.png"), &d)
            .is_allowed());
    }

    #[test]
    fn a_path_without_a_slash_must_match_exactly() {
        let d = doc("https://site.test/");
        let p = Policy::parse("img-src https://example.com/a.png");
        assert!(p
            .allows(Kind::Image, &u("https://example.com/a.png"), &d)
            .is_allowed());
        assert!(!p
            .allows(Kind::Image, &u("https://example.com/a.png.evil"), &d)
            .is_allowed());
    }

    #[test]
    fn star_covers_network_schemes_only() {
        let d = doc("https://site.test/");
        let p = Policy::parse("img-src *");
        assert!(p
            .allows(Kind::Image, &u("https://anything.example/x"), &d)
            .is_allowed());
        assert!(!p
            .allows(Kind::Image, &u("data:image/png;base64,AA"), &d)
            .is_allowed());
    }

    #[test]
    fn a_nonce_lets_matching_inline_content_run() {
        let p = Policy::parse("script-src 'nonce-r4nd0m'");
        assert!(p
            .allows_inline_with_nonce(Kind::Script, "r4nd0m")
            .is_allowed());
        assert!(!p
            .allows_inline_with_nonce(Kind::Script, "other")
            .is_allowed());
    }

    #[test]
    fn a_nonce_disables_unsafe_inline() {
        let with_nonce = Policy::parse("script-src 'unsafe-inline' 'nonce-abc'");
        assert!(!with_nonce.allows_unsafe_inline(Kind::Script).is_allowed());

        let without = Policy::parse("script-src 'unsafe-inline'");
        assert!(without.allows_unsafe_inline(Kind::Script).is_allowed());
    }

    #[test]
    fn a_hash_lets_matching_inline_content_run() {
        let p = Policy::parse("script-src 'sha256-abc123='");
        assert!(p
            .allows_inline_with_hash(Kind::Script, "sha256", "abc123=")
            .is_allowed());
        assert!(!p
            .allows_inline_with_hash(Kind::Script, "sha256", "zzz")
            .is_allowed());
        assert!(!p
            .allows_inline_with_hash(Kind::Script, "sha512", "abc123=")
            .is_allowed());
    }

    #[test]
    fn eval_needs_unsafe_eval() {
        assert!(Policy::parse("script-src 'unsafe-eval'")
            .allows_eval(Kind::Script)
            .is_allowed());
        assert!(!Policy::parse("script-src 'self'")
            .allows_eval(Kind::Script)
            .is_allowed());
    }

    #[test]
    fn keyword_sources_never_match_a_url() {
        let d = doc("https://example.com/");
        let p = Policy::parse("img-src 'unsafe-inline' 'strict-dynamic'");
        assert!(!p
            .allows(Kind::Image, &u("https://example.com/a.png"), &d)
            .is_allowed());
    }

    #[test]
    fn unknown_tokens_are_kept_and_match_nothing() {
        let p = Policy::parse("img-src 'totally-made-up'");
        let sources = p.directive("img-src").unwrap();
        assert!(matches!(sources[0], Source::Unknown(_)));
        let d = doc("https://example.com/");
        assert!(!p
            .allows(Kind::Image, &u("https://example.com/a.png"), &d)
            .is_allowed());
    }

    #[test]
    fn round_trips_through_display() {
        let text = "default-src 'self'; img-src https://*.example.com:8443/assets/ data:";
        let p = Policy::parse(text);
        let rendered = p.to_string();
        let reparsed = Policy::parse(&rendered);
        assert_eq!(reparsed.to_string(), rendered);
        assert!(rendered.contains("https://*.example.com:8443/assets/"));
    }

    #[test]
    fn lists_what_it_holds() {
        let p = Policy::parse("default-src 'self'; img-src *");
        let names: Vec<&str> = p.directive_names().collect();
        assert_eq!(names, vec!["default-src", "img-src"]);
        assert!(!p.is_empty());
        assert!(Policy::parse("").is_empty());
    }
}
