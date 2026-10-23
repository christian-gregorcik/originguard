//! Times the three hot paths, so the numbers in the README can be checked
//! rather than taken on trust.
//!
//! Run it with `cargo run --release --example throughput`.

use originguard::cookie::{self, Context, RequestKind};
use originguard::csp::{Kind, Policy};
use originguard::origin::Origin;
use originguard::site::PublicSuffixList;
use originguard::thirdparty::{Blocker, Category, Mode};
use originguard::url::Url;
use std::hint::black_box;
use std::time::Instant;

const ROUNDS: u32 = 200_000;
const REPEATS: u32 = 5;

/// Runs one measurement `REPEATS` times and reports the fastest.
///
/// The fastest run is the one least disturbed by whatever else the machine
/// was doing; on a shared container the slowest can be half the speed of the
/// fastest, so a single run is not a number worth quoting.
fn measure(label: &str, mut body: impl FnMut()) {
    let mut best = f64::INFINITY;
    for _ in 0..REPEATS {
        let start = Instant::now();
        body();
        let per = start.elapsed().as_secs_f64() / f64::from(ROUNDS);
        if per < best {
            best = per;
        }
    }
    println!(
        "{label:<34} {:>7.0} ns/op   {:>6.1} M ops/s",
        best * 1e9,
        1.0 / best / 1e6
    );
}

fn main() {
    let list = PublicSuffixList::embedded();
    println!("public suffix rules loaded: {}", list.len());
    println!("{ROUNDS} operations per run, fastest of {REPEATS} runs");
    println!();

    let hosts = [
        "www.example.com",
        "deep.sub.example.co.uk",
        "a.b.c.d.tracker.test",
        "localhost",
        "192.168.1.1",
    ];
    measure("registrable domain", || {
        for i in 0..ROUNDS {
            let host = hosts[(i as usize) % hosts.len()];
            black_box(list.registrable_domain(host));
        }
    });

    let policy = Policy::parse(
        "default-src 'self'; script-src 'self' 'nonce-K1n9' https://cdn.example.com; \
         img-src 'self' https://*.images.test data:; connect-src 'self' https://api.example.com",
    );
    let document = Origin::of(&Url::parse("https://example.com/page").unwrap());
    let targets: Vec<Url> = [
        "https://cdn.example.com/app.js",
        "https://evil.test/x.js",
        "https://a.images.test/p.png",
        "https://api.example.com/v1",
    ]
    .iter()
    .map(|s| Url::parse(s).unwrap())
    .collect();
    measure("CSP decision (parsed policy)", || {
        for i in 0..ROUNDS {
            let url = &targets[(i as usize) % targets.len()];
            black_box(policy.allows(Kind::ScriptElement, url, &document));
        }
    });

    let header = "default-src 'self'; script-src 'self' 'nonce-K1n9' https://cdn.example.com; \
                  img-src 'self' https://*.images.test data:";
    measure("CSP parse (3 directives)", || {
        for _ in 0..ROUNDS {
            black_box(Policy::parse(header));
        }
    });

    let mut blocker = Blocker::new(PublicSuffixList::embedded(), Mode::Standard);
    blocker
        .classify("ads.test", Category::Advertising)
        .classify("metrics.test", Category::Analytics);
    let page = Url::parse("https://example.com/article").unwrap();
    let requests: Vec<Url> = [
        "https://ads.test/px",
        "https://metrics.test/collect",
        "https://cdn.example.com/app.js",
        "https://fonts.test/f.woff2",
    ]
    .iter()
    .map(|s| Url::parse(s).unwrap())
    .collect();
    measure("third-party decision", || {
        for i in 0..ROUNDS {
            let url = &requests[(i as usize) % requests.len()];
            black_box(blocker.decide(url, &page));
        }
    });

    let at = Url::parse("https://example.com/login").unwrap();
    let ctx = Context {
        request: &at,
        top_level: &at,
        kind: RequestKind::TopLevelNavigationSafeMethod,
    };
    measure("Set-Cookie parse and check", || {
        for _ in 0..ROUNDS {
            black_box(cookie::parse_set_cookie(
                &list,
                "sid=abc; Domain=example.com; Path=/; Secure; HttpOnly; SameSite=Lax",
                &ctx,
                false,
            ))
            .ok();
        }
    });

    let a = Url::parse("https://a.example.com/one").unwrap();
    let b = Url::parse("https://b.example.com/two").unwrap();
    measure("same-site comparison", || {
        for _ in 0..ROUNDS {
            black_box(list.same_site(&a, &b));
        }
    });
}
