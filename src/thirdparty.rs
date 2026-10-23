//! First-party or third-party, and what a tracking blocker does about it.
//!
//! A request is third-party when its site differs from the site of the page
//! the person is looking at. That single comparison decides whether storage
//! is partitioned, whether a `SameSite=Lax` cookie travels, and whether a
//! tracking blocker gets a say at all.
//!
//! Two things make the real answer less simple than the comparison. The
//! first is that two different registrable domains can belong to one
//! company, and blocking a company's own analytics on its own site breaks
//! the site without helping anyone; an entity list records those
//! relationships. The second is that blocking is graded: a classifier puts
//! a site in a category, and the mode in force decides which categories are
//! blocked, which are only partitioned, and which travel untouched.

use crate::site::{PublicSuffixList, Site};
use crate::url::Url;
use std::collections::HashMap;

/// Whether a request stays inside the page's own site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Party {
    /// Same site as the top-level page.
    First,
    /// A different site that the entity list ties to the same owner.
    SameEntity,
    /// A different site, and a different owner.
    Third,
}

impl Party {
    /// Whether storage for this request has to be partitioned.
    ///
    /// Same-entity still counts as third-party for storage: shared ownership
    /// is a reason not to break a site, not a reason to hand out an
    /// unpartitioned cookie jar.
    pub fn is_cross_site(self) -> bool {
        !matches!(self, Party::First)
    }
}

/// What a classifier thinks a site is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Category {
    /// Measures how a site is used.
    Analytics,
    /// Selects or delivers advertising.
    Advertising,
    /// Social network buttons and embeds.
    Social,
    /// Builds a device identifier without storage.
    Fingerprinting,
    /// Mines currency in the visitor's browser.
    Cryptomining,
    /// Serves content the page needs, and tracks along the way.
    Content,
}

/// How much to block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Nothing is blocked.
    Off,
    /// The categories that break least when blocked.
    Standard,
    /// Everything on the list, content trackers included.
    Strict,
}

impl Mode {
    /// The categories this mode blocks outright.
    pub fn blocked_categories(self) -> &'static [Category] {
        match self {
            Mode::Off => &[],
            Mode::Standard => &[
                Category::Advertising,
                Category::Fingerprinting,
                Category::Cryptomining,
            ],
            Mode::Strict => &[
                Category::Advertising,
                Category::Analytics,
                Category::Social,
                Category::Fingerprinting,
                Category::Cryptomining,
                Category::Content,
            ],
        }
    }
}

/// What to do with one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Send it as it is.
    Allow,
    /// Send it, but give it storage keyed to this top-level site.
    Partition {
        /// The top-level site the storage is keyed to.
        top_level: Site,
    },
    /// Do not send it.
    Block {
        /// Why it was blocked.
        category: Category,
    },
}

impl Action {
    /// Whether the request is sent at all.
    pub fn is_sent(&self) -> bool {
        !matches!(self, Action::Block { .. })
    }
}

/// The decision, with enough detail to explain it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// Whether the request is first-party, same-entity or third-party.
    pub party: Party,
    /// The category the classifier gave the request's site, if any.
    pub category: Option<Category>,
    /// What to do.
    pub action: Action,
    /// Whether an exception the caller granted changed the outcome.
    pub exempted: bool,
}

/// A tracking classifier and the policy applied to what it finds.
#[derive(Debug, Clone)]
pub struct Blocker {
    suffixes: PublicSuffixList,
    categories: HashMap<String, Category>,
    /// Registrable domain to owning entity name.
    entities: HashMap<String, String>,
    /// Top-level registrable domains where blocking is turned off.
    exceptions: Vec<String>,
    mode: Mode,
}

impl Blocker {
    /// A blocker with no list entries, in the given mode.
    pub fn new(suffixes: PublicSuffixList, mode: Mode) -> Blocker {
        Blocker {
            suffixes,
            categories: HashMap::new(),
            entities: HashMap::new(),
            exceptions: Vec::new(),
            mode,
        }
    }

    /// The mode in force.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Changes the mode.
    pub fn set_mode(&mut self, mode: Mode) {
        self.mode = mode;
    }

    /// Records that a registrable domain belongs to a category.
    pub fn classify(&mut self, registrable_domain: &str, category: Category) -> &mut Self {
        self.categories
            .insert(registrable_domain.to_ascii_lowercase(), category);
        self
    }

    /// Records that a registrable domain belongs to an owning entity.
    pub fn own(&mut self, registrable_domain: &str, entity: &str) -> &mut Self {
        self.entities
            .insert(registrable_domain.to_ascii_lowercase(), entity.to_string());
        self
    }

    /// Turns blocking off for one top-level registrable domain.
    pub fn except(&mut self, top_level_registrable_domain: &str) -> &mut Self {
        self.exceptions
            .push(top_level_registrable_domain.to_ascii_lowercase());
        self
    }

    /// Reads a list in `domain category` form, one entry per line.
    ///
    /// Blank lines and lines beginning with `#` are skipped. An unreadable
    /// category name is skipped rather than guessed at, and the count of
    /// entries actually taken is returned.
    pub fn load_categories(&mut self, text: &str) -> usize {
        let mut taken = 0;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split_whitespace();
            let (Some(domain), Some(name)) = (parts.next(), parts.next()) else {
                continue;
            };
            let category = match name.to_ascii_lowercase().as_str() {
                "analytics" => Category::Analytics,
                "advertising" => Category::Advertising,
                "social" => Category::Social,
                "fingerprinting" => Category::Fingerprinting,
                "cryptomining" => Category::Cryptomining,
                "content" => Category::Content,
                _ => continue,
            };
            self.classify(domain, category);
            taken += 1;
        }
        taken
    }

    /// Reads an entity list in `domain entity` form, one entry per line.
    pub fn load_entities(&mut self, text: &str) -> usize {
        let mut taken = 0;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split_whitespace();
            let (Some(domain), Some(entity)) = (parts.next(), parts.next()) else {
                continue;
            };
            self.own(domain, entity);
            taken += 1;
        }
        taken
    }

    /// Whether a request to `url` from a page at `top_level` is first-party.
    pub fn party(&self, url: &Url, top_level: &Url) -> Party {
        let a = self.suffixes.registrable_domain(url.host());
        let b = self.suffixes.registrable_domain(top_level.host());
        match (a, b) {
            (Some(a), Some(b)) => {
                if a == b {
                    return Party::First;
                }
                match (self.entities.get(a), self.entities.get(b)) {
                    (Some(x), Some(y)) if x == y => Party::SameEntity,
                    _ => Party::Third,
                }
            }
            // A host with no registrable domain (an IP, or a bare public
            // suffix) is only first-party against the identical host.
            _ => {
                if url.host() == top_level.host() {
                    Party::First
                } else {
                    Party::Third
                }
            }
        }
    }

    /// The category the list gives `url`'s site, if any.
    pub fn category(&self, url: &Url) -> Option<Category> {
        let domain = self.suffixes.registrable_domain(url.host())?;
        self.categories.get(domain).copied()
    }

    /// What to do with a request to `url` from a page at `top_level`.
    pub fn decide(&self, url: &Url, top_level: &Url) -> Decision {
        let party = self.party(url, top_level);
        let category = self.category(url);

        // A first-party request is never a tracking request: the site is
        // already allowed to know what happens on itself.
        if party == Party::First {
            return Decision {
                party,
                category,
                action: Action::Allow,
                exempted: false,
            };
        }

        let top_site = self.suffixes.site(top_level);
        let exempted = self
            .suffixes
            .registrable_domain(top_level.host())
            .map(|d| self.exceptions.iter().any(|e| e.as_str() == d))
            .unwrap_or(false);

        let action = match category {
            Some(c) if !exempted && self.mode.blocked_categories().contains(&c) => {
                Action::Block { category: c }
            }
            // Everything else that crosses a site boundary still gets its
            // storage keyed to this page, which is what stops a tracker
            // recognising the same browser on the next site.
            _ => Action::Partition {
                top_level: top_site,
            },
        };

        Decision {
            party,
            category,
            action,
            exempted,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    fn blocker(mode: Mode) -> Blocker {
        Blocker::new(PublicSuffixList::embedded(), mode)
    }

    #[test]
    fn same_registrable_domain_is_first_party() {
        let b = blocker(Mode::Standard);
        assert_eq!(
            b.party(
                &u("https://img.example.com/a.png"),
                &u("https://www.example.com/")
            ),
            Party::First
        );
    }

    #[test]
    fn a_different_registrable_domain_is_third_party() {
        let b = blocker(Mode::Standard);
        assert_eq!(
            b.party(&u("https://tracker.test/px"), &u("https://example.com/")),
            Party::Third
        );
    }

    #[test]
    fn scheme_does_not_change_the_party() {
        // Party is about the site boundary, which is registrable-domain
        // based; schemeful same-site is a separate question in `site`.
        let b = blocker(Mode::Standard);
        assert_eq!(
            b.party(&u("http://example.com/a"), &u("https://example.com/")),
            Party::First
        );
    }

    #[test]
    fn the_entity_list_softens_but_does_not_erase_the_boundary() {
        let mut b = blocker(Mode::Standard);
        b.own("example.com", "Example Group")
            .own("example-cdn.net", "Example Group");
        let party = b.party(
            &u("https://a.example-cdn.net/x.js"),
            &u("https://example.com/"),
        );
        assert_eq!(party, Party::SameEntity);
        assert!(party.is_cross_site());
    }

    #[test]
    fn unrelated_owners_stay_third_party() {
        let mut b = blocker(Mode::Standard);
        b.own("example.com", "Example Group")
            .own("other.test", "Other Ltd");
        assert_eq!(
            b.party(&u("https://other.test/x.js"), &u("https://example.com/")),
            Party::Third
        );
    }

    #[test]
    fn an_ip_host_is_first_party_only_against_itself() {
        let b = blocker(Mode::Standard);
        assert_eq!(
            b.party(&u("http://127.0.0.1:8080/a"), &u("http://127.0.0.1:3000/")),
            Party::First
        );
        assert_eq!(
            b.party(&u("http://127.0.0.1/a"), &u("http://192.168.1.1/")),
            Party::Third
        );
    }

    #[test]
    fn standard_mode_blocks_advertising_and_partitions_analytics() {
        let mut b = blocker(Mode::Standard);
        b.classify("ads.test", Category::Advertising)
            .classify("metrics.test", Category::Analytics);

        let ad = b.decide(&u("https://ads.test/px"), &u("https://example.com/"));
        assert_eq!(
            ad.action,
            Action::Block {
                category: Category::Advertising
            }
        );
        assert!(!ad.action.is_sent());

        let metrics = b.decide(
            &u("https://metrics.test/collect"),
            &u("https://example.com/"),
        );
        assert!(metrics.action.is_sent());
        assert!(matches!(metrics.action, Action::Partition { .. }));
        assert_eq!(metrics.category, Some(Category::Analytics));
    }

    #[test]
    fn strict_mode_blocks_analytics_too() {
        let mut b = blocker(Mode::Strict);
        b.classify("metrics.test", Category::Analytics);
        let d = b.decide(
            &u("https://metrics.test/collect"),
            &u("https://example.com/"),
        );
        assert_eq!(
            d.action,
            Action::Block {
                category: Category::Analytics
            }
        );
    }

    #[test]
    fn off_blocks_nothing_but_still_partitions() {
        let mut b = blocker(Mode::Off);
        b.classify("ads.test", Category::Advertising);
        let d = b.decide(&u("https://ads.test/px"), &u("https://example.com/"));
        assert!(d.action.is_sent());
        assert!(matches!(d.action, Action::Partition { .. }));
    }

    #[test]
    fn a_first_party_request_is_never_blocked_even_when_listed() {
        let mut b = blocker(Mode::Strict);
        b.classify("example.com", Category::Analytics);
        let d = b.decide(
            &u("https://metrics.example.com/x"),
            &u("https://example.com/"),
        );
        assert_eq!(d.party, Party::First);
        assert_eq!(d.action, Action::Allow);
    }

    #[test]
    fn same_entity_is_still_blocked_when_the_category_is_blocked() {
        let mut b = blocker(Mode::Standard);
        b.own("example.com", "Example Group")
            .own("example-ads.test", "Example Group")
            .classify("example-ads.test", Category::Advertising);
        let d = b.decide(
            &u("https://example-ads.test/px"),
            &u("https://example.com/"),
        );
        assert_eq!(d.party, Party::SameEntity);
        assert_eq!(
            d.action,
            Action::Block {
                category: Category::Advertising
            }
        );
    }

    #[test]
    fn an_exception_turns_blocking_off_for_one_site() {
        let mut b = blocker(Mode::Standard);
        b.classify("ads.test", Category::Advertising)
            .except("example.com");

        let on_exempt = b.decide(&u("https://ads.test/px"), &u("https://example.com/"));
        assert!(on_exempt.exempted);
        assert!(on_exempt.action.is_sent());

        let elsewhere = b.decide(&u("https://ads.test/px"), &u("https://other.test/"));
        assert!(!elsewhere.exempted);
        assert!(!elsewhere.action.is_sent());
    }

    #[test]
    fn partitioning_is_keyed_to_the_top_level_site() {
        let b = blocker(Mode::Standard);
        let one = b.decide(&u("https://embed.test/w"), &u("https://a.example.com/"));
        let two = b.decide(&u("https://embed.test/w"), &u("https://other.test/"));
        let (Action::Partition { top_level: k1 }, Action::Partition { top_level: k2 }) =
            (&one.action, &two.action)
        else {
            panic!("expected both to be partitioned");
        };
        assert_ne!(k1, k2);
        assert_eq!(k1.registrable_domain(), "example.com");
    }

    #[test]
    fn reads_a_category_list_and_skips_what_it_cannot_read() {
        let mut b = blocker(Mode::Standard);
        let taken = b.load_categories(
            "# a comment\n\nads.test advertising\nmetrics.test analytics\nbroken.test nonsense\nnofield\n",
        );
        assert_eq!(taken, 2);
        assert_eq!(
            b.category(&u("https://ads.test/x")),
            Some(Category::Advertising)
        );
        assert_eq!(b.category(&u("https://broken.test/x")), None);
    }

    #[test]
    fn reads_an_entity_list() {
        let mut b = blocker(Mode::Standard);
        let taken = b.load_entities("# owners\nexample.com Example\nexample-cdn.net Example\n");
        assert_eq!(taken, 2);
        assert_eq!(
            b.party(&u("https://example-cdn.net/x"), &u("https://example.com/")),
            Party::SameEntity
        );
    }

    #[test]
    fn a_subdomain_inherits_its_sites_category() {
        let mut b = blocker(Mode::Standard);
        b.classify("ads.test", Category::Advertising);
        assert_eq!(
            b.category(&u("https://deep.sub.ads.test/px")),
            Some(Category::Advertising)
        );
    }

    #[test]
    fn an_unlisted_third_party_is_sent_but_partitioned() {
        let b = blocker(Mode::Standard);
        let d = b.decide(&u("https://fonts.test/f.woff2"), &u("https://example.com/"));
        assert_eq!(d.party, Party::Third);
        assert_eq!(d.category, None);
        assert!(matches!(d.action, Action::Partition { .. }));
    }
}
