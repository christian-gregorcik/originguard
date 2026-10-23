//! Compiles the example in the README, so the README cannot drift from the
//! library without CI noticing.

use originguard::csp::{Kind, Policy};
use originguard::origin::Origin;
use originguard::url::Url;

fn main() {
    let policy =
        Policy::parse("default-src 'self'; script-src 'self' 'nonce-K1n9' 'unsafe-inline'");
    let document = Origin::of(&Url::parse("https://example.com/page").unwrap());

    // The nonce lets the page's own inline script run.
    assert!(policy
        .allows_inline_with_nonce(Kind::Script, "K1n9")
        .is_allowed());

    // And its presence turns off the 'unsafe-inline' beside it, so an injected
    // inline script does not run.
    assert!(!policy.allows_unsafe_inline(Kind::Script).is_allowed());

    let script = Url::parse("https://evil.test/x.js").unwrap();
    let blocked = policy.allows(Kind::ScriptElement, &script, &document);
    assert!(!blocked.is_allowed());

    println!("the README example holds");
}
