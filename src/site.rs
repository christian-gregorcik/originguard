//! Public suffixes, registrable domains and sites.
//!
//! Two hosts belong to the same site when they share a registrable domain:
//! the public suffix plus one label. `a.example.co.uk` and `b.example.co.uk`
//! are the same site because `co.uk` is a public suffix and `example.co.uk`
//! is the registrable domain. `example.co.uk` and `other.co.uk` are not.
//!
//! The list of public suffixes is data, not code, so it is supplied rather
//! than hard-coded. [`PublicSuffixList::embedded`] carries a small set that
//! covers the common cases; [`PublicSuffixList::parse`] reads the full list
//! published at publicsuffix.org in its usual format.

use crate::url::{host_is_ip, Url};
use std::collections::HashSet;
use std::fmt;

/// A set of public suffix rules.
#[derive(Debug, Clone, Default)]
pub struct PublicSuffixList {
    /// Rules such as `com` and `co.uk`, stored as written.
    normal: HashSet<String>,
    /// Rules such as `*.ck`, stored as the part after the star.
    wildcard: HashSet<String>,
    /// Rules such as `!www.ck`, stored without the bang.
    exception: HashSet<String>,
}

impl PublicSuffixList {
    /// Reads rules in the publicsuffix.org format.
    ///
    /// Blank lines and `//` comments are skipped. Every other line is one
    /// rule. Unicode rules are kept as written; callers that need punycode
    /// should convert before calling.
    pub fn parse(text: &str) -> PublicSuffixList {
        let mut list = PublicSuffixList::default();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("//") {
                continue;
            }
            let rule = line.split_whitespace().next().unwrap_or("");
            if rule.is_empty() {
                continue;
            }
            let rule = rule.to_ascii_lowercase();
            if let Some(rest) = rule.strip_prefix('!') {
                list.exception.insert(rest.to_string());
            } else if let Some(rest) = rule.strip_prefix("*.") {
                list.wildcard.insert(rest.to_string());
            } else {
                list.normal.insert(rule);
            }
        }
        list
    }

    /// A small built-in list: the suffixes most traffic actually uses.
    ///
    /// It is a convenience, not a substitute for the published list. Load the
    /// full list with [`PublicSuffixList::parse`] when correctness across all
    /// of the public suffix space matters.
    pub fn embedded() -> PublicSuffixList {
        PublicSuffixList::parse(EMBEDDED_RULES)
    }

    /// How many rules the list holds.
    pub fn len(&self) -> usize {
        self.normal.len() + self.wildcard.len() + self.exception.len()
    }

    /// Whether the list holds no rules at all.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The public suffix of a host, by the matching rules of the list.
    ///
    /// Returns `None` for an IP address, which has no public suffix. A host
    /// that matches no rule has its rightmost label as its suffix, which is
    /// what the specification calls the implicit `*` rule.
    pub fn public_suffix<'a>(&self, host: &'a str) -> Option<&'a str> {
        if host.is_empty() || host_is_ip(host) {
            return None;
        }
        if host.split('.').any(|l| l.is_empty()) {
            return None;
        }
        let total = host.split('.').count();

        // Walk the candidate suffixes from the right, each one a slice of
        // the host itself, so a lookup costs no allocation.
        let mut best_len = 1usize; // the implicit `*` rule
        let mut end = host.len();
        let mut candidate_len = 0usize;
        loop {
            let dot = host[..end].rfind('.');
            let start = match dot {
                Some(d) => d + 1,
                None => 0,
            };
            let candidate = &host[start..];
            candidate_len += 1;

            if self.exception.contains(candidate) {
                // An exception rule means the suffix is one label shorter
                // than the rule itself.
                best_len = candidate_len.saturating_sub(1).max(1);
                break;
            }
            if self.normal.contains(candidate) {
                best_len = best_len.max(candidate_len);
            }
            if self.wildcard.contains(candidate) {
                best_len = best_len.max(candidate_len + 1);
            }

            match dot {
                Some(d) => end = d,
                None => break,
            }
        }

        if best_len >= total {
            // The whole host is a public suffix.
            return Some(host);
        }
        let mut offset = 0;
        for _ in 0..total - best_len {
            // Every label walked past is followed by a dot, so this cannot
            // run off the end: the loop runs fewer times than there are
            // labels.
            offset += host[offset..].find('.').map(|i| i + 1)?;
        }
        Some(&host[offset..])
    }

    /// The registrable domain of a host: its public suffix plus one label.
    ///
    /// Returns `None` when the host is an IP address, or when the host is
    /// itself a public suffix and so has nothing registrable under it.
    pub fn registrable_domain<'a>(&self, host: &'a str) -> Option<&'a str> {
        let suffix = self.public_suffix(host)?;
        if suffix.len() == host.len() {
            return None;
        }
        let remainder = &host[..host.len() - suffix.len() - 1];
        let last_dot = remainder.rfind('.');
        let start = match last_dot {
            Some(idx) => idx + 1,
            None => 0,
        };
        Some(&host[start..])
    }

    /// The site of a URL: its scheme and registrable domain.
    ///
    /// This is the schemeful site used for `SameSite` cookies and for
    /// storage partitioning. A host with no registrable domain, such as an
    /// IP address or a bare public suffix, uses the host itself.
    pub fn site(&self, url: &Url) -> Site {
        let host = url.host();
        let registrable = self.registrable_domain(host).unwrap_or(host).to_string();
        Site {
            scheme: url.scheme().to_string(),
            registrable_domain: registrable,
        }
    }

    /// Whether two URLs belong to the same schemeful site.
    pub fn same_site(&self, a: &Url, b: &Url) -> bool {
        self.site(a) == self.site(b)
    }
}

/// A scheme and a registrable domain, compared as one unit.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Site {
    scheme: String,
    registrable_domain: String,
}

impl Site {
    /// The scheme half of the site.
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// The registrable domain half of the site.
    pub fn registrable_domain(&self) -> &str {
        &self.registrable_domain
    }
}

impl fmt::Display for Site {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}", self.scheme, self.registrable_domain)
    }
}

const EMBEDDED_RULES: &str = "\
// A small subset of publicsuffix.org, enough for the common cases.
com
org
net
edu
gov
int
mil
info
biz
io
dev
app
se
nu
no
dk
fi
de
fr
nl
es
it
pl
uk
co.uk
org.uk
ac.uk
gov.uk
me.uk
com.au
net.au
org.au
co.jp
or.jp
ne.jp
co.nz
com.br
co.za
com.tr
github.io
pages.dev
workers.dev
vercel.app
netlify.app
herokuapp.com
// Wildcard and exception, kept so the matching rules are exercised.
*.ck
!www.ck
";

#[cfg(test)]
mod tests {
    use super::*;

    fn list() -> PublicSuffixList {
        PublicSuffixList::embedded()
    }

    #[test]
    fn embedded_list_has_rules() {
        assert!(list().len() > 30);
        assert!(!list().is_empty());
    }

    #[test]
    fn finds_single_label_suffixes() {
        let l = list();
        assert_eq!(l.public_suffix("example.com"), Some("com"));
        assert_eq!(l.public_suffix("a.b.example.se"), Some("se"));
    }

    #[test]
    fn prefers_the_longest_matching_rule() {
        let l = list();
        assert_eq!(l.public_suffix("example.co.uk"), Some("co.uk"));
        assert_eq!(l.public_suffix("a.b.example.co.uk"), Some("co.uk"));
        assert_eq!(l.public_suffix("example.github.io"), Some("github.io"));
    }

    #[test]
    fn unknown_suffix_falls_back_to_the_last_label() {
        let l = list();
        assert_eq!(l.public_suffix("example.zzz"), Some("zzz"));
    }

    #[test]
    fn handles_wildcard_and_exception_rules() {
        let l = list();
        // `*.ck` makes `foo.ck` a suffix, so `bar.foo.ck` is registrable.
        assert_eq!(l.public_suffix("bar.foo.ck"), Some("foo.ck"));
        assert_eq!(l.registrable_domain("bar.foo.ck"), Some("bar.foo.ck"));
        // `!www.ck` pulls the suffix back to `ck`.
        assert_eq!(l.public_suffix("www.ck"), Some("ck"));
        assert_eq!(l.registrable_domain("www.ck"), Some("www.ck"));
    }

    #[test]
    fn registrable_domain_is_suffix_plus_one() {
        let l = list();
        assert_eq!(
            l.registrable_domain("a.b.example.co.uk"),
            Some("example.co.uk")
        );
        assert_eq!(l.registrable_domain("example.com"), Some("example.com"));
        assert_eq!(l.registrable_domain("www.example.com"), Some("example.com"));
    }

    #[test]
    fn a_bare_public_suffix_has_no_registrable_domain() {
        let l = list();
        assert_eq!(l.registrable_domain("com"), None);
        assert_eq!(l.registrable_domain("co.uk"), None);
    }

    #[test]
    fn ip_addresses_have_no_suffix() {
        let l = list();
        assert_eq!(l.public_suffix("127.0.0.1"), None);
        assert_eq!(l.registrable_domain("127.0.0.1"), None);
        assert_eq!(l.public_suffix("::1"), None);
    }

    #[test]
    fn malformed_hosts_are_rejected() {
        let l = list();
        assert_eq!(l.public_suffix(""), None);
        assert_eq!(l.public_suffix("a..b"), None);
    }

    #[test]
    fn site_pairs_scheme_with_registrable_domain() {
        let l = list();
        let a = Url::parse("https://a.example.co.uk/x").unwrap();
        let b = Url::parse("https://b.example.co.uk/y").unwrap();
        let c = Url::parse("http://b.example.co.uk/y").unwrap();
        let d = Url::parse("https://other.co.uk/y").unwrap();

        assert!(l.same_site(&a, &b));
        // Schemeful same-site: http and https are different sites.
        assert!(!l.same_site(&a, &c));
        assert!(!l.same_site(&a, &d));
        assert_eq!(l.site(&a).to_string(), "https://example.co.uk");
        assert_eq!(l.site(&a).scheme(), "https");
        assert_eq!(l.site(&a).registrable_domain(), "example.co.uk");
    }

    #[test]
    fn ip_hosts_use_the_host_as_the_site() {
        let l = list();
        let a = Url::parse("http://127.0.0.1:8080/x").unwrap();
        let b = Url::parse("http://127.0.0.1:9090/y").unwrap();
        assert!(l.same_site(&a, &b));
        assert_eq!(l.site(&a).registrable_domain(), "127.0.0.1");
    }

    #[test]
    fn parses_the_published_format() {
        let l = PublicSuffixList::parse(
            "// comment\n\ncom\n*.example\n!exempt.example\nco.uk // trailing\n",
        );
        assert_eq!(l.public_suffix("a.com"), Some("com"));
        assert_eq!(l.public_suffix("a.b.example"), Some("b.example"));
        assert_eq!(l.public_suffix("exempt.example"), Some("example"));
        assert_eq!(l.public_suffix("x.co.uk"), Some("co.uk"));
    }
}
