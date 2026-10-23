# originguard

Web origins, cookie scoping and Content-Security-Policy, implemented from the
specifications in Rust with no dependencies at all.

These are the rules a browser applies to every single request, and they are
the rules that decide whether a tracking pixel recognises you on the next
site. They are also easy to get subtly wrong: `http://example.com` and
`https://example.com` are the same origin for a cookie's `Domain` attribute
and different sites for `SameSite`, a portless CSP host-source matches the
default port of the *URL's* scheme rather than the source's, and a nonce in a
directive silently turns off `'unsafe-inline'` sitting right beside it.

This library answers those questions one at a time, with a test for each rule
and a command-line tool so any of them can be checked by hand.

```
$ originguard suffix www.example.co.uk
public suffix:      co.uk
registrable domain: example.co.uk

$ originguard csp "default-src 'self'" image https://cdn.example.com/a.png https://example.com/
blocked by default-src

$ originguard send "id=1; SameSite=Lax; Secure" https://example.com/ \
      https://example.com/a https://other.test/ subresource
not sent — SameSite=Lax, and this is a cross-site request that is not a top-level navigation

$ originguard party https://ads.test/px https://example.com/ ads.test=advertising
party:    Third
category: Advertising
action:   block (Advertising)
```

The exit status carries the answer, so the tool works inside a shell script:
`0` for yes, `1` for no, `2` when the input could not be read.

## What it covers

**`url`** — enough URL parsing to answer the questions below: scheme, host,
port and path, with host lowercasing, a trailing dot stripped, userinfo
dropped and IPv6 literals kept in their brackets. Not a general URL library,
and it does not pretend to be one.

**`origin`** — the scheme/host/port tuple, and opaque origins. An opaque
origin is same-origin with nothing, including a second opaque origin and
including itself seen twice, which is exactly what a sandboxed frame depends
on. Serialising one gives `null`.

**`site`** — public suffix rules, the registrable domain, and the schemeful
site used by `SameSite` and by storage partitioning. Longest matching normal
rule wins, a `*.` rule adds one label, a `!` exception pulls the suffix back
one label, and a host matching nothing falls back to its rightmost label.
A small built-in list of 47 rules ships with the crate; `PublicSuffixList::parse`
reads the full published list when correctness across the whole suffix space
matters.

**`cookie`** — `Set-Cookie` parsing with the checks that actually reject
things: a `Domain` that is a public suffix, a `__Host-` prefix with a `Domain`
attribute or a path other than `/`, a `__Secure-` prefix without `Secure`, and
`SameSite=None` without `Secure`. Then `should_send`, which applies domain and
path matching, the `Secure` requirement, `SameSite=Strict` and `Lax`, and the
partition key.

**`csp`** — a policy parser and evaluator. The fallback chain from
`script-src-elem` through `script-src` to `default-src`, and `frame-src`
through `child-src`. Source expressions: `'none'`, `'self'`, `'unsafe-inline'`,
`'unsafe-eval'`, `'strict-dynamic'`, nonces, `sha256`/`sha384`/`sha512`
hashes, scheme sources, `*`, and host sources with wildcard subdomains, ports
and path prefixes. A decision names the directive that made it, so a report
can say which line of the policy did the blocking.

**`thirdparty`** — first-party, same-entity or third-party, and what a
tracking blocker does about it: block, send with partitioned storage, or send
untouched, by category and by mode. Entity ownership is recorded so a site's
own second domain does not get broken, without that shared ownership handing
out an unpartitioned cookie jar.

## Using it

```rust
use originguard::csp::{Kind, Policy};
use originguard::origin::Origin;
use originguard::url::Url;

let policy = Policy::parse("default-src 'self'; script-src 'self' 'nonce-K1n9' 'unsafe-inline'");
let document = Origin::of(&Url::parse("https://example.com/page").unwrap());

// The nonce lets the page's own inline script run.
assert!(policy.allows_inline_with_nonce(Kind::Script, "K1n9").is_allowed());

// And its presence turns off the 'unsafe-inline' beside it, so an injected
// inline script does not run.
assert!(!policy.allows_unsafe_inline(Kind::Script).is_allowed());

let script = Url::parse("https://evil.test/x.js").unwrap();
let blocked = policy.allows(Kind::ScriptElement, &script, &document);
assert!(!blocked.is_allowed());
```

## Tests

97 tests: 87 against individual rules, 10 scenarios that cross module
boundaries the way a browser meets them — a session cookie following a
subdomain but not another site, two sandboxed frames sharing nothing, one
tracking pixel refused by the blocker, the policy and the cookie rules in
turn.

```
cargo test
cargo clippy --all-targets -- -D warnings
```

Both are clean, and CI runs them on every push.

## Measured

```
cargo run --release --example throughput
```

Fastest of five runs, 200 000 operations each, repeated four times and the
best taken per row:

| path | per operation |
| --- | --- |
| CSP decision against a parsed policy | 57 ns |
| registrable domain from a host | 218 ns |
| same-site comparison of two URLs | 396 ns |
| `Set-Cookie` parse and check | 422 ns |
| CSP parse, three directives | 617 ns |
| third-party decision | 804 ns |

Measured on a shared cloud container, where consecutive runs of the same
measurement differ by up to about 30%; these are the right order of magnitude
rather than precise figures. The example prints its own numbers on your
machine, which is the point of shipping it.

A suffix lookup allocates nothing: candidate suffixes are slices of the host
being tested, walked from the right.

## Not covered

Punycode conversion — pass hosts already in A-label form. CSP reporting
endpoints, `report-to` and the report body. `trusted-types` and
`require-trusted-types-for`. Cookie expiry and the cookie store itself: this
crate decides whether a cookie may be set and whether it travels, not where it
is kept.

## Licence

MIT.
