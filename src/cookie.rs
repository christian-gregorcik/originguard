//! Cookie attributes, name prefixes, `SameSite` and storage partitioning.
//!
//! A cookie is only as safe as the rules that decide when it is sent back.
//! This module reads a `Set-Cookie` value into its attributes, rejects the
//! ones the name prefixes forbid, and answers the question a browser asks on
//! every request: given this cookie, this request and the site at the top of
//! the tab, is the cookie sent?

use crate::site::{PublicSuffixList, Site};
use crate::url::{host_is_ip, Url};
use std::fmt;

/// The `SameSite` attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SameSite {
    /// Sent only when the request is same-site.
    Strict,
    /// Sent same-site, and cross-site only on a top-level safe navigation.
    Lax,
    /// Sent cross-site. Requires `Secure`.
    None,
}

impl fmt::Display for SameSite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SameSite::Strict => "Strict",
            SameSite::Lax => "Lax",
            SameSite::None => "None",
        })
    }
}

/// How a request was made, which decides whether a `Lax` cookie travels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestKind {
    /// A top-level navigation with a safe method, such as clicking a link.
    TopLevelNavigationSafeMethod,
    /// A top-level navigation with an unsafe method, such as a POSTed form.
    TopLevelNavigationUnsafeMethod,
    /// A subresource: an image, a script, a fetch, a frame.
    Subresource,
}

/// Why a cookie was rejected when it was set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CookieError {
    /// The `Set-Cookie` value had no `name=value` pair.
    Malformed,
    /// `__Secure-` requires the `Secure` attribute and a secure origin.
    SecurePrefixViolated,
    /// `__Host-` requires `Secure`, `Path=/`, a secure origin and no `Domain`.
    HostPrefixViolated,
    /// `SameSite=None` requires the `Secure` attribute.
    SameSiteNoneWithoutSecure,
    /// `Domain` named a host the setting origin may not set cookies for.
    DomainNotAllowed,
}

impl fmt::Display for CookieError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            CookieError::Malformed => "the Set-Cookie value has no name=value pair",
            CookieError::SecurePrefixViolated => {
                "a __Secure- cookie needs the Secure attribute on a secure origin"
            }
            CookieError::HostPrefixViolated => {
                "a __Host- cookie needs Secure, Path=/, a secure origin and no Domain"
            }
            CookieError::SameSiteNoneWithoutSecure => "SameSite=None needs the Secure attribute",
            CookieError::DomainNotAllowed => {
                "the Domain attribute names a host this origin may not set cookies for"
            }
        };
        f.write_str(text)
    }
}

impl std::error::Error for CookieError {}

/// A cookie as it is stored after being accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cookie {
    /// The cookie name.
    pub name: String,
    /// The cookie value, as written.
    pub value: String,
    /// The host the cookie is scoped to.
    pub domain: String,
    /// Whether the scope covers subdomains of `domain`.
    pub host_only: bool,
    /// The path prefix the cookie is scoped to.
    pub path: String,
    /// Whether the cookie is only sent over a secure scheme.
    pub secure: bool,
    /// Whether script may read the cookie.
    pub http_only: bool,
    /// The `SameSite` attribute in force.
    pub same_site: SameSite,
    /// The top-level site this cookie is partitioned under, if any.
    pub partition_key: Option<Site>,
}

/// The context a cookie is set or read in.
#[derive(Debug, Clone)]
pub struct Context<'a> {
    /// The URL the request is for.
    pub request: &'a Url,
    /// The URL at the top of the tab.
    pub top_level: &'a Url,
    /// How the request was made.
    pub kind: RequestKind,
}

fn is_secure_scheme(scheme: &str) -> bool {
    matches!(scheme, "https" | "wss")
}

/// Whether a request origin may set a cookie for `domain`.
///
/// The request host must equal the domain or be a subdomain of it, and the
/// domain must not be a public suffix, which is what stops one site setting
/// a cookie for all of `.co.uk`.
pub fn domain_allowed(list: &PublicSuffixList, request_host: &str, domain: &str) -> bool {
    let domain = domain.trim_start_matches('.').to_ascii_lowercase();
    if domain.is_empty() {
        return false;
    }
    if host_is_ip(&domain) {
        return request_host == domain;
    }
    // The domain is itself a public suffix, or has none. (`is_none_or` says
    // this more directly but is only stable since 1.82, above this crate's
    // minimum.)
    match list.public_suffix(&domain) {
        Some(suffix) if suffix.len() != domain.len() => {}
        _ => return false,
    }
    if request_host == domain {
        return true;
    }
    request_host.ends_with(&format!(".{domain}"))
}

/// Reads a `Set-Cookie` value and decides whether it may be stored.
///
/// `partitioned` asks for the cookie to be keyed to the top-level site, which
/// is what stops one site reading a cookie another site set in the same
/// third-party frame.
pub fn parse_set_cookie(
    list: &PublicSuffixList,
    header: &str,
    ctx: &Context<'_>,
    partitioned: bool,
) -> Result<Cookie, CookieError> {
    let mut parts = header.split(';');
    let pair = parts.next().ok_or(CookieError::Malformed)?;
    let eq = pair.find('=').ok_or(CookieError::Malformed)?;
    let name = pair[..eq].trim().to_string();
    let value = pair[eq + 1..].trim().to_string();
    if name.is_empty() {
        return Err(CookieError::Malformed);
    }

    let mut domain_attr: Option<String> = None;
    let mut path_attr: Option<String> = None;
    let mut secure = false;
    let mut http_only = false;
    let mut same_site: Option<SameSite> = None;

    for attr in parts {
        let attr = attr.trim();
        if attr.is_empty() {
            continue;
        }
        let (key, val) = match attr.find('=') {
            Some(i) => (attr[..i].trim(), attr[i + 1..].trim()),
            None => (attr, ""),
        };
        match key.to_ascii_lowercase().as_str() {
            "domain" => domain_attr = Some(val.to_ascii_lowercase()),
            "path" => path_attr = Some(val.to_string()),
            "secure" => secure = true,
            "httponly" => http_only = true,
            "samesite" => {
                same_site = match val.to_ascii_lowercase().as_str() {
                    "strict" => Some(SameSite::Strict),
                    "none" => Some(SameSite::None),
                    _ => Some(SameSite::Lax),
                }
            }
            _ => {}
        }
    }

    // No SameSite attribute means Lax, which is what browsers now default to.
    let same_site = same_site.unwrap_or(SameSite::Lax);
    let request_secure = is_secure_scheme(ctx.request.scheme());

    if same_site == SameSite::None && !secure {
        return Err(CookieError::SameSiteNoneWithoutSecure);
    }

    if name.starts_with("__Secure-") && (!secure || !request_secure) {
        return Err(CookieError::SecurePrefixViolated);
    }
    if name.starts_with("__Host-") {
        let path_is_root = path_attr.as_deref() == Some("/");
        if !secure || !request_secure || domain_attr.is_some() || !path_is_root {
            return Err(CookieError::HostPrefixViolated);
        }
    }

    let (domain, host_only) = match &domain_attr {
        None => (ctx.request.host().to_string(), true),
        Some(d) => {
            if !domain_allowed(list, ctx.request.host(), d) {
                return Err(CookieError::DomainNotAllowed);
            }
            (d.trim_start_matches('.').to_string(), false)
        }
    };

    let path = match path_attr {
        Some(p) if p.starts_with('/') => p,
        _ => default_path(ctx.request.path()),
    };

    let partition_key = if partitioned {
        Some(list.site(ctx.top_level))
    } else {
        None
    };

    Ok(Cookie {
        name,
        value,
        domain,
        host_only,
        path,
        secure,
        http_only,
        same_site,
        partition_key,
    })
}

/// The default path of a cookie set from `request_path`.
///
/// Everything after the last `/` is dropped, so a cookie set from
/// `/a/b/c.html` defaults to `/a/b`.
pub fn default_path(request_path: &str) -> String {
    if !request_path.starts_with('/') {
        return "/".to_string();
    }
    match request_path.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(idx) => request_path[..idx].to_string(),
    }
}

/// Whether a stored path covers a request path.
pub fn path_matches(cookie_path: &str, request_path: &str) -> bool {
    if cookie_path == request_path {
        return true;
    }
    if !request_path.starts_with(cookie_path) {
        return false;
    }
    cookie_path.ends_with('/') || request_path.as_bytes().get(cookie_path.len()) == Some(&b'/')
}

/// Whether a stored domain covers a request host.
pub fn domain_matches(cookie: &Cookie, request_host: &str) -> bool {
    if cookie.host_only {
        return cookie.domain == request_host;
    }
    request_host == cookie.domain || request_host.ends_with(&format!(".{}", cookie.domain))
}

/// Why a cookie was not attached to a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Blocked {
    /// The host did not match the cookie's domain.
    Domain,
    /// The path did not match the cookie's path.
    Path,
    /// The cookie is `Secure` and the request was not.
    Insecure,
    /// `SameSite=Strict` and the request was cross-site.
    SameSiteStrict,
    /// `SameSite=Lax` and the request was a cross-site subresource or an
    /// unsafe-method navigation.
    SameSiteLax,
    /// The cookie is partitioned under a different top-level site.
    Partition,
}

impl fmt::Display for Blocked {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Blocked::Domain => f.write_str("the cookie's domain does not cover this host"),
            Blocked::Path => f.write_str("the cookie's path does not cover this path"),
            Blocked::Insecure => f.write_str("the cookie is Secure and this request is not"),
            Blocked::SameSiteStrict => {
                f.write_str("SameSite=Strict, and this request crosses a site boundary")
            }
            Blocked::SameSiteLax => f.write_str(
                "SameSite=Lax, and this is a cross-site request that is not a top-level navigation",
            ),
            Blocked::Partition => {
                f.write_str("the cookie is partitioned under a different top-level site")
            }
        }
    }
}

/// Whether a stored cookie is sent on this request, and why not if it is not.
pub fn should_send(
    list: &PublicSuffixList,
    cookie: &Cookie,
    ctx: &Context<'_>,
) -> Result<(), Blocked> {
    if !domain_matches(cookie, ctx.request.host()) {
        return Err(Blocked::Domain);
    }
    if !path_matches(&cookie.path, ctx.request.path()) {
        return Err(Blocked::Path);
    }
    if cookie.secure && !is_secure_scheme(ctx.request.scheme()) {
        return Err(Blocked::Insecure);
    }

    if let Some(key) = &cookie.partition_key {
        if *key != list.site(ctx.top_level) {
            return Err(Blocked::Partition);
        }
    }

    let same_site = list.same_site(ctx.request, ctx.top_level);
    if same_site {
        return Ok(());
    }

    match cookie.same_site {
        SameSite::None => Ok(()),
        SameSite::Strict => Err(Blocked::SameSiteStrict),
        SameSite::Lax => match ctx.kind {
            RequestKind::TopLevelNavigationSafeMethod => Ok(()),
            _ => Err(Blocked::SameSiteLax),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    fn list() -> PublicSuffixList {
        PublicSuffixList::embedded()
    }

    fn ctx<'a>(request: &'a Url, top: &'a Url, kind: RequestKind) -> Context<'a> {
        Context {
            request,
            top_level: top,
            kind,
        }
    }

    #[test]
    fn reads_name_value_and_attributes() {
        let r = u("https://example.com/a/b");
        let c = parse_set_cookie(
            &list(),
            "sid=abc123; Path=/; Secure; HttpOnly; SameSite=Strict",
            &ctx(&r, &r, RequestKind::Subresource),
            false,
        )
        .unwrap();
        assert_eq!(c.name, "sid");
        assert_eq!(c.value, "abc123");
        assert_eq!(c.path, "/");
        assert!(c.secure);
        assert!(c.http_only);
        assert_eq!(c.same_site, SameSite::Strict);
        assert!(c.host_only);
        assert_eq!(c.domain, "example.com");
    }

    #[test]
    fn missing_samesite_defaults_to_lax() {
        let r = u("https://example.com/");
        let c = parse_set_cookie(
            &list(),
            "a=1",
            &ctx(&r, &r, RequestKind::Subresource),
            false,
        )
        .unwrap();
        assert_eq!(c.same_site, SameSite::Lax);
    }

    #[test]
    fn samesite_none_needs_secure() {
        let r = u("https://example.com/");
        let err = parse_set_cookie(
            &list(),
            "a=1; SameSite=None",
            &ctx(&r, &r, RequestKind::Subresource),
            false,
        )
        .unwrap_err();
        assert_eq!(err, CookieError::SameSiteNoneWithoutSecure);

        assert!(parse_set_cookie(
            &list(),
            "a=1; SameSite=None; Secure",
            &ctx(&r, &r, RequestKind::Subresource),
            false
        )
        .is_ok());
    }

    #[test]
    fn secure_prefix_is_enforced() {
        let https = u("https://example.com/");
        let http = u("http://example.com/");
        assert!(parse_set_cookie(
            &list(),
            "__Secure-a=1; Secure",
            &ctx(&https, &https, RequestKind::Subresource),
            false
        )
        .is_ok());
        assert_eq!(
            parse_set_cookie(
                &list(),
                "__Secure-a=1",
                &ctx(&https, &https, RequestKind::Subresource),
                false
            )
            .unwrap_err(),
            CookieError::SecurePrefixViolated
        );
        assert_eq!(
            parse_set_cookie(
                &list(),
                "__Secure-a=1; Secure",
                &ctx(&http, &http, RequestKind::Subresource),
                false
            )
            .unwrap_err(),
            CookieError::SecurePrefixViolated
        );
    }

    #[test]
    fn host_prefix_is_enforced() {
        let r = u("https://example.com/a");
        let good = "__Host-a=1; Secure; Path=/";
        assert!(
            parse_set_cookie(&list(), good, &ctx(&r, &r, RequestKind::Subresource), false).is_ok()
        );

        for bad in [
            "__Host-a=1; Secure",                             // no Path=/
            "__Host-a=1; Path=/",                             // no Secure
            "__Host-a=1; Secure; Path=/a",                    // wrong path
            "__Host-a=1; Secure; Path=/; Domain=example.com", // has Domain
        ] {
            assert_eq!(
                parse_set_cookie(&list(), bad, &ctx(&r, &r, RequestKind::Subresource), false)
                    .unwrap_err(),
                CookieError::HostPrefixViolated,
                "expected {bad} to be rejected"
            );
        }
    }

    #[test]
    fn a_site_cannot_set_a_cookie_on_a_public_suffix() {
        let l = list();
        assert!(!domain_allowed(&l, "example.co.uk", "co.uk"));
        assert!(!domain_allowed(&l, "example.com", "com"));
        assert!(domain_allowed(&l, "a.example.com", "example.com"));
        assert!(domain_allowed(&l, "example.com", "example.com"));
        assert!(!domain_allowed(&l, "example.com", "other.com"));
    }

    #[test]
    fn domain_attribute_widens_the_scope_to_subdomains() {
        let r = u("https://a.example.com/");
        let c = parse_set_cookie(
            &list(),
            "a=1; Domain=example.com",
            &ctx(&r, &r, RequestKind::Subresource),
            false,
        )
        .unwrap();
        assert!(!c.host_only);
        assert!(domain_matches(&c, "b.example.com"));
        assert!(domain_matches(&c, "example.com"));
        assert!(!domain_matches(&c, "example.org"));
    }

    #[test]
    fn default_path_drops_the_last_segment() {
        assert_eq!(default_path("/a/b/c.html"), "/a/b");
        assert_eq!(default_path("/a"), "/");
        assert_eq!(default_path("/"), "/");
        assert_eq!(default_path("noslash"), "/");
    }

    #[test]
    fn path_matching_respects_segment_boundaries() {
        assert!(path_matches("/a", "/a"));
        assert!(path_matches("/a", "/a/b"));
        assert!(path_matches("/a/", "/a/b"));
        assert!(!path_matches("/a", "/ab"));
        assert!(!path_matches("/a/b", "/a"));
    }

    #[test]
    fn strict_cookies_stay_home() {
        let l = list();
        let r = u("https://example.com/");
        let same = u("https://www.example.com/");
        let other = u("https://attacker.com/");
        let c = parse_set_cookie(
            &l,
            "a=1; Secure; SameSite=Strict",
            &ctx(&r, &r, RequestKind::Subresource),
            false,
        )
        .unwrap();

        assert!(should_send(&l, &c, &ctx(&r, &same, RequestKind::Subresource)).is_ok());
        assert_eq!(
            should_send(
                &l,
                &c,
                &ctx(&r, &other, RequestKind::TopLevelNavigationSafeMethod)
            ),
            Err(Blocked::SameSiteStrict)
        );
    }

    #[test]
    fn lax_cookies_travel_on_a_top_level_click_only() {
        let l = list();
        let r = u("https://example.com/");
        let other = u("https://attacker.com/");
        let c = parse_set_cookie(&l, "a=1", &ctx(&r, &r, RequestKind::Subresource), false).unwrap();

        assert!(should_send(
            &l,
            &c,
            &ctx(&r, &other, RequestKind::TopLevelNavigationSafeMethod)
        )
        .is_ok());
        assert_eq!(
            should_send(&l, &c, &ctx(&r, &other, RequestKind::Subresource)),
            Err(Blocked::SameSiteLax)
        );
        assert_eq!(
            should_send(
                &l,
                &c,
                &ctx(&r, &other, RequestKind::TopLevelNavigationUnsafeMethod)
            ),
            Err(Blocked::SameSiteLax)
        );
    }

    #[test]
    fn none_cookies_travel_everywhere() {
        let l = list();
        let r = u("https://tracker.example/");
        let other = u("https://news.example.com/");
        let c = parse_set_cookie(
            &l,
            "a=1; Secure; SameSite=None",
            &ctx(&r, &r, RequestKind::Subresource),
            false,
        )
        .unwrap();
        assert!(should_send(&l, &c, &ctx(&r, &other, RequestKind::Subresource)).is_ok());
    }

    #[test]
    fn partitioning_keeps_one_top_level_site_out_of_another() {
        let l = list();
        let third_party = u("https://tracker.example/pixel");
        let site_a = u("https://news.example.com/");
        let site_b = u("https://shop.example.org/");

        let c = parse_set_cookie(
            &l,
            "id=1; Secure; SameSite=None",
            &ctx(&third_party, &site_a, RequestKind::Subresource),
            true,
        )
        .unwrap();
        assert_eq!(
            c.partition_key.as_ref().unwrap().to_string(),
            "https://example.com"
        );

        assert!(should_send(
            &l,
            &c,
            &ctx(&third_party, &site_a, RequestKind::Subresource)
        )
        .is_ok());
        assert_eq!(
            should_send(
                &l,
                &c,
                &ctx(&third_party, &site_b, RequestKind::Subresource)
            ),
            Err(Blocked::Partition)
        );
    }

    #[test]
    fn secure_cookies_do_not_travel_over_http() {
        let l = list();
        let https = u("https://example.com/");
        let http = u("http://example.com/");
        let c = parse_set_cookie(
            &l,
            "a=1; Secure",
            &ctx(&https, &https, RequestKind::Subresource),
            false,
        )
        .unwrap();
        assert_eq!(
            should_send(&l, &c, &ctx(&http, &http, RequestKind::Subresource)),
            Err(Blocked::Insecure)
        );
    }

    #[test]
    fn malformed_headers_are_rejected() {
        let r = u("https://example.com/");
        let c = ctx(&r, &r, RequestKind::Subresource);
        assert_eq!(
            parse_set_cookie(&list(), "novalue", &c, false).unwrap_err(),
            CookieError::Malformed
        );
        assert_eq!(
            parse_set_cookie(&list(), "=novalue", &c, false).unwrap_err(),
            CookieError::Malformed
        );
    }
}
