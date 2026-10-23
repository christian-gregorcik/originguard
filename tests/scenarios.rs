//! Scenarios that cross module boundaries, written the way a browser meets
//! them: a page loads, a cookie is set, a request goes out, and several
//! rules have to agree on the answer.

use originguard::cookie::{self, Context, RequestKind, SameSite};
use originguard::csp::{Decision, Kind, Policy};
use originguard::origin::Origin;
use originguard::site::PublicSuffixList;
use originguard::thirdparty::{Action, Blocker, Category, Mode, Party};
use originguard::url::Url;

fn u(s: &str) -> Url {
    Url::parse(s).expect("the test URL should parse")
}

fn list() -> PublicSuffixList {
    PublicSuffixList::embedded()
}

/// A login cookie set on the apex domain travels to a subdomain, and the
/// same cookie is withheld from a cross-site image request.
#[test]
fn a_session_cookie_follows_subdomains_but_not_other_sites() {
    let list = list();
    let set_at = u("https://example.com/login");
    let set_ctx = Context {
        request: &set_at,
        top_level: &set_at,
        kind: RequestKind::TopLevelNavigationUnsafeMethod,
    };
    let session = cookie::parse_set_cookie(
        &list,
        "sid=abc; Domain=example.com; Path=/; Secure; HttpOnly; SameSite=Lax",
        &set_ctx,
        false,
    )
    .expect("the cookie should be accepted");

    assert_eq!(session.same_site, SameSite::Lax);
    assert!(!session.host_only);

    let api = u("https://api.example.com/me");
    let same_site = Context {
        request: &api,
        top_level: &u("https://www.example.com/dashboard"),
        kind: RequestKind::Subresource,
    };
    assert!(cookie::should_send(&list, &session, &same_site).is_ok());

    let cross = Context {
        request: &u("https://example.com/pixel.png"),
        top_level: &u("https://unrelated.test/article"),
        kind: RequestKind::Subresource,
    };
    assert!(cookie::should_send(&list, &session, &cross).is_err());
}

/// `__Host-` means what it says: apex only, no `Domain`, path `/`, Secure.
#[test]
fn the_host_prefix_refuses_a_domain_attribute() {
    let list = list();
    let at = u("https://example.com/");
    let ctx = Context {
        request: &at,
        top_level: &at,
        kind: RequestKind::TopLevelNavigationSafeMethod,
    };

    assert!(cookie::parse_set_cookie(&list, "__Host-a=1; Path=/; Secure", &ctx, false).is_ok());
    assert!(cookie::parse_set_cookie(
        &list,
        "__Host-a=1; Path=/; Secure; Domain=example.com",
        &ctx,
        false
    )
    .is_err());
    assert!(cookie::parse_set_cookie(&list, "__Host-a=1; Path=/x; Secure", &ctx, false).is_err());
    assert!(cookie::parse_set_cookie(&list, "__Host-a=1; Path=/", &ctx, false).is_err());
}

/// Nobody may set a cookie on a public suffix, which is what stops one site
/// under `.co.uk` writing a cookie every other one would send.
#[test]
fn a_public_suffix_cannot_hold_a_cookie() {
    let list = list();
    let at = u("https://example.co.uk/");
    let ctx = Context {
        request: &at,
        top_level: &at,
        kind: RequestKind::TopLevelNavigationSafeMethod,
    };
    assert!(cookie::parse_set_cookie(&list, "a=1; Domain=co.uk", &ctx, false).is_err());
    assert!(cookie::parse_set_cookie(&list, "a=1; Domain=example.co.uk", &ctx, false).is_ok());
}

/// A nonce-based policy is the one that actually holds: the nonce lets the
/// page's own inline script run, and `'unsafe-inline'` sitting beside it
/// stops being an escape hatch for an injected one.
#[test]
fn a_nonce_policy_survives_an_injected_inline_script() {
    let policy = Policy::parse(
        "default-src 'self'; script-src 'self' 'unsafe-inline' 'nonce-K1n9' https://cdn.example.com",
    );
    let document = Origin::of(&u("https://example.com/page"));

    assert!(policy
        .allows_inline_with_nonce(Kind::Script, "K1n9")
        .is_allowed());
    assert!(!policy
        .allows_inline_with_nonce(Kind::Script, "guessed")
        .is_allowed());
    assert!(!policy.allows_unsafe_inline(Kind::Script).is_allowed());

    assert!(policy
        .allows(
            Kind::ScriptElement,
            &u("https://cdn.example.com/app.js"),
            &document
        )
        .is_allowed());
    assert!(!policy
        .allows(Kind::ScriptElement, &u("https://evil.test/x.js"), &document)
        .is_allowed());
}

/// The fallback chain decides which directive answers, and the answer names
/// it, so a report says which line of the policy did the blocking.
#[test]
fn the_decision_names_the_directive_that_made_it() {
    let document = Origin::of(&u("https://example.com/"));
    let url = u("https://cdn.example.com/app.js");

    let policy = Policy::parse("default-src 'none'; script-src https://cdn.example.com");
    assert_eq!(
        policy.allows(Kind::ScriptElement, &url, &document),
        Decision::Allowed {
            directive: "script-src".into()
        }
    );

    let tighter = Policy::parse(
        "default-src 'none'; script-src https://cdn.example.com; script-src-elem 'self'",
    );
    assert_eq!(
        tighter.allows(Kind::ScriptElement, &url, &document),
        Decision::Blocked {
            directive: "script-src-elem".into()
        }
    );

    let silent = Policy::parse("img-src 'self'");
    assert_eq!(
        silent.allows(Kind::ScriptElement, &url, &document),
        Decision::NoPolicy
    );
}

/// An opaque origin is same-origin with nothing, including another opaque
/// one and itself seen twice, which is what a sandboxed frame relies on.
#[test]
fn two_sandboxed_frames_share_nothing() {
    let a = Origin::new_opaque();
    let b = Origin::new_opaque();
    assert!(!a.same_origin(&b));
    assert!(!a.same_origin(&Origin::new_opaque()));
    assert_eq!(a.serialize(), "null");

    let policy = Policy::parse("img-src 'self'");
    assert!(!policy
        .allows(Kind::Image, &u("https://example.com/a.png"), &a)
        .is_allowed());
}

/// The same embed on two different pages gets two different storage keys,
/// and that is the whole point of partitioning.
#[test]
fn one_embed_on_two_sites_gets_two_storage_keys() {
    let mut blocker = Blocker::new(list(), Mode::Standard);
    blocker.classify("ads.test", Category::Advertising);

    let on_a = blocker.decide(
        &u("https://widget.test/w.js"),
        &u("https://shop.example.com/"),
    );
    let on_b = blocker.decide(&u("https://widget.test/w.js"), &u("https://news.test/"));
    assert_eq!(on_a.party, Party::Third);
    let (Action::Partition { top_level: k1 }, Action::Partition { top_level: k2 }) =
        (&on_a.action, &on_b.action)
    else {
        panic!("an unlisted third party should be sent with partitioned storage");
    };
    assert_ne!(k1, k2);

    let ad = blocker.decide(&u("https://ads.test/px"), &u("https://news.test/"));
    assert!(!ad.action.is_sent());
}

/// Blocking a company's own measurement on its own site breaks the site, so
/// the entity list keeps it sent — while storage stays partitioned.
#[test]
fn the_entity_list_keeps_a_sites_own_second_domain_working() {
    let mut blocker = Blocker::new(list(), Mode::Strict);
    blocker
        .own("example.com", "Example Group")
        .own("example-static.test", "Example Group")
        .classify("example-static.test", Category::Content);

    let own_site = blocker.decide(
        &u("https://cdn.example-static.test/app.js"),
        &u("https://example.com/"),
    );
    assert_eq!(own_site.party, Party::SameEntity);
    // Strict mode blocks the Content category, and shared ownership does not
    // exempt it: the list records the relationship, the mode sets policy.
    assert!(!own_site.action.is_sent());

    blocker.set_mode(Mode::Standard);
    let relaxed = blocker.decide(
        &u("https://cdn.example-static.test/app.js"),
        &u("https://example.com/"),
    );
    assert!(relaxed.action.is_sent());
    assert!(relaxed.party.is_cross_site());
}

/// Site is schemeful: moving a page to TLS moves the site with it.
#[test]
fn http_and_https_are_different_sites() {
    let list = list();
    assert!(list.same_site(&u("https://a.example.com/"), &u("https://b.example.com/")));
    assert!(!list.same_site(&u("http://example.com/"), &u("https://example.com/")));
}

/// The three questions a browser asks about one cross-site tracking pixel,
/// answered together: who is it, may it load, and does it carry a cookie.
#[test]
fn one_tracking_pixel_through_all_three_rules() {
    let list = list();
    let page = u("https://example.com/article");
    let pixel = u("https://metrics.test/px.gif");

    let mut blocker = Blocker::new(list.clone(), Mode::Strict);
    blocker.classify("metrics.test", Category::Analytics);
    let decision = blocker.decide(&pixel, &page);
    assert_eq!(decision.party, Party::Third);
    assert!(!decision.action.is_sent());

    // Even with the blocker off, the page's own policy stops it.
    let policy = Policy::parse("default-src 'self'; img-src 'self' data:");
    assert!(!policy
        .allows(Kind::Image, &pixel, &Origin::of(&page))
        .is_allowed());

    // And even past both, a Lax cookie would not ride along.
    let set_at = u("https://metrics.test/");
    let set_ctx = Context {
        request: &set_at,
        top_level: &set_at,
        kind: RequestKind::TopLevelNavigationSafeMethod,
    };
    let id = cookie::parse_set_cookie(&list, "id=7; Secure; SameSite=Lax", &set_ctx, false)
        .expect("the cookie should be accepted on its own site");
    let send_ctx = Context {
        request: &pixel,
        top_level: &page,
        kind: RequestKind::Subresource,
    };
    assert!(cookie::should_send(&list, &id, &send_ctx).is_err());
}
