//! A command-line front end to the library, so every rule can be checked by
//! hand against a real URL.

use originguard::cookie::{self, Context, RequestKind};
use originguard::csp::{Kind, Policy};
use originguard::origin::Origin;
use originguard::site::PublicSuffixList;
use originguard::thirdparty::{Blocker, Category, Mode};
use originguard::url::Url;
use std::process::ExitCode;

const USAGE: &str = "\
originguard — web origin, cookie and CSP rules, checked from the command line

usage:
  originguard origin <url>
  originguard site <url>
  originguard same-origin <url> <url>
  originguard same-site <url> <url>
  originguard suffix <host>
  originguard csp <policy> <kind> <url> <document-url>
  originguard cookie <set-cookie> <request-url> <top-level-url>
  originguard send <set-cookie> <set-url> <request-url> <top-level-url> <kind>
  originguard party <url> <top-level-url> [<domain>=<category> ...]

kinds for csp:    script, script-element, style, style-element, image, font,
                  connect, frame, other
kinds for send:   navigation, post, subresource
categories:       analytics, advertising, social, fingerprinting,
                  cryptomining, content

exit status is 0 when the answer is yes or the input parsed, 1 when the
answer is no, and 2 when the input could not be read.
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args[0] == "-h" || args[0] == "--help" {
        print!("{USAGE}");
        return ExitCode::from(if args.is_empty() { 2 } else { 0 });
    }

    match run(&args) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(message) => {
            eprintln!("originguard: {message}");
            ExitCode::from(2)
        }
    }
}

fn run(args: &[String]) -> Result<bool, String> {
    let rest = &args[1..];
    match args[0].as_str() {
        "origin" => {
            let url = parse(need(rest, 0, "origin <url>")?)?;
            println!("{}", Origin::of(&url).serialize());
            Ok(true)
        }
        "site" => {
            let url = parse(need(rest, 0, "site <url>")?)?;
            let list = PublicSuffixList::embedded();
            println!("{}", list.site(&url));
            Ok(true)
        }
        "same-origin" => {
            let a = parse(need(rest, 0, "same-origin <url> <url>")?)?;
            let b = parse(need(rest, 1, "same-origin <url> <url>")?)?;
            let same = Origin::of(&a).same_origin(&Origin::of(&b));
            println!("{}", yes_no(same));
            Ok(same)
        }
        "same-site" => {
            let a = parse(need(rest, 0, "same-site <url> <url>")?)?;
            let b = parse(need(rest, 1, "same-site <url> <url>")?)?;
            let list = PublicSuffixList::embedded();
            let same = list.same_site(&a, &b);
            println!("{}", yes_no(same));
            Ok(same)
        }
        "suffix" => {
            let host = need(rest, 0, "suffix <host>")?;
            let list = PublicSuffixList::embedded();
            match (list.public_suffix(host), list.registrable_domain(host)) {
                (Some(s), Some(d)) => {
                    println!("public suffix:      {s}");
                    println!("registrable domain: {d}");
                    Ok(true)
                }
                (Some(s), None) => {
                    println!("public suffix:      {s}");
                    println!("registrable domain: none — the host is a public suffix");
                    Ok(false)
                }
                _ => {
                    println!("no public suffix — the host is an address, not a name");
                    Ok(false)
                }
            }
        }
        "csp" => {
            let policy = Policy::parse(need(rest, 0, "csp <policy> <kind> <url> <document>")?);
            let kind = csp_kind(need(rest, 1, "csp <policy> <kind> <url> <document>")?)?;
            let url = parse(need(rest, 2, "csp <policy> <kind> <url> <document>")?)?;
            let document = parse(need(rest, 3, "csp <policy> <kind> <url> <document>")?)?;
            let decision = policy.allows(kind, &url, &Origin::of(&document));
            match &decision {
                originguard::csp::Decision::NoPolicy => {
                    println!("allowed — the policy has no directive for this kind of load");
                }
                originguard::csp::Decision::Allowed { directive } => {
                    println!("allowed by {directive}");
                }
                originguard::csp::Decision::Blocked { directive } => {
                    println!("blocked by {directive}");
                }
            }
            if !policy.duplicates.is_empty() {
                eprintln!(
                    "note: these directives appear more than once and only the first counts: {}",
                    policy.duplicates.join(", ")
                );
            }
            Ok(decision.is_allowed())
        }
        "cookie" => {
            let header = need(rest, 0, "cookie <set-cookie> <request> <top-level>")?;
            let request = parse(need(rest, 1, "cookie <set-cookie> <request> <top-level>")?)?;
            let top_level = parse(need(rest, 2, "cookie <set-cookie> <request> <top-level>")?)?;
            let list = PublicSuffixList::embedded();
            let context = Context {
                request: &request,
                top_level: &top_level,
                kind: RequestKind::Subresource,
            };
            match cookie::parse_set_cookie(&list, header, &context, false) {
                Ok(c) => {
                    println!("name:      {}", c.name);
                    println!(
                        "domain:    {}{}",
                        c.domain,
                        if c.host_only { " (host only)" } else { "" }
                    );
                    println!("path:      {}", c.path);
                    println!("secure:    {}", c.secure);
                    println!("http only: {}", c.http_only);
                    println!("same site: {:?}", c.same_site);
                    match &c.partition_key {
                        Some(k) => println!("partition: {k}"),
                        None => println!("partition: none"),
                    }
                    Ok(true)
                }
                Err(e) => {
                    println!("rejected — {e}");
                    Ok(false)
                }
            }
        }
        "send" => {
            let header = need(
                rest,
                0,
                "send <set-cookie> <set-url> <request> <top-level> <kind>",
            )?;
            let set_url = parse(need(
                rest,
                1,
                "send <set-cookie> <set-url> <request> <top-level> <kind>",
            )?)?;
            let request = parse(need(
                rest,
                2,
                "send <set-cookie> <set-url> <request> <top-level> <kind>",
            )?)?;
            let top_level = parse(need(
                rest,
                3,
                "send <set-cookie> <set-url> <request> <top-level> <kind>",
            )?)?;
            let kind = request_kind(need(
                rest,
                4,
                "send <set-cookie> <set-url> <request> <top-level> <kind>",
            )?)?;
            let list = PublicSuffixList::embedded();
            let set_context = Context {
                request: &set_url,
                top_level: &set_url,
                kind: RequestKind::TopLevelNavigationSafeMethod,
            };
            let c = cookie::parse_set_cookie(&list, header, &set_context, false)
                .map_err(|e| format!("the cookie could not be set: {e}"))?;
            let send_context = Context {
                request: &request,
                top_level: &top_level,
                kind,
            };
            match cookie::should_send(&list, &c, &send_context) {
                Ok(()) => {
                    println!("sent");
                    Ok(true)
                }
                Err(blocked) => {
                    println!("not sent — {blocked}");
                    Ok(false)
                }
            }
        }
        "party" => {
            let url = parse(need(
                rest,
                0,
                "party <url> <top-level> [<domain>=<category>]",
            )?)?;
            let top_level = parse(need(
                rest,
                1,
                "party <url> <top-level> [<domain>=<category>]",
            )?)?;
            let mut blocker = Blocker::new(PublicSuffixList::embedded(), Mode::Standard);
            for pair in &rest[2.min(rest.len())..] {
                let (domain, name) = pair
                    .split_once('=')
                    .ok_or_else(|| format!("'{pair}' is not <domain>=<category>"))?;
                blocker.classify(domain, category(name)?);
            }
            let decision = blocker.decide(&url, &top_level);
            println!("party:    {:?}", decision.party);
            match decision.category {
                Some(c) => println!("category: {c:?}"),
                None => println!("category: not listed"),
            }
            match &decision.action {
                originguard::thirdparty::Action::Allow => println!("action:   allow"),
                originguard::thirdparty::Action::Partition { top_level } => {
                    println!("action:   send, storage keyed to {top_level}");
                }
                originguard::thirdparty::Action::Block { category } => {
                    println!("action:   block ({category:?})");
                }
            }
            Ok(decision.action.is_sent())
        }
        other => Err(format!("'{other}' is not a command; run with --help")),
    }
}

fn need<'a>(args: &'a [String], index: usize, form: &str) -> Result<&'a str, String> {
    args.get(index)
        .map(|s| s.as_str())
        .ok_or_else(|| format!("missing argument {}; the form is: {form}", index + 1))
}

fn parse(text: &str) -> Result<Url, String> {
    Url::parse(text).map_err(|e| format!("{text}: {e}"))
}

fn yes_no(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no"
    }
}

fn csp_kind(name: &str) -> Result<Kind, String> {
    Ok(match name {
        "script" => Kind::Script,
        "script-element" => Kind::ScriptElement,
        "style" => Kind::Style,
        "style-element" => Kind::StyleElement,
        "image" | "img" => Kind::Image,
        "font" => Kind::Font,
        "connect" => Kind::Connect,
        "frame" => Kind::Frame,
        "other" => Kind::Other,
        _ => return Err(format!("'{name}' is not a kind of load; run with --help")),
    })
}

fn request_kind(name: &str) -> Result<RequestKind, String> {
    Ok(match name {
        "navigation" | "nav" => RequestKind::TopLevelNavigationSafeMethod,
        "post" => RequestKind::TopLevelNavigationUnsafeMethod,
        "subresource" | "sub" => RequestKind::Subresource,
        _ => {
            return Err(format!(
                "'{name}' is not a kind of request; run with --help"
            ))
        }
    })
}

fn category(name: &str) -> Result<Category, String> {
    Ok(match name {
        "analytics" => Category::Analytics,
        "advertising" => Category::Advertising,
        "social" => Category::Social,
        "fingerprinting" => Category::Fingerprinting,
        "cryptomining" => Category::Cryptomining,
        "content" => Category::Content,
        _ => return Err(format!("'{name}' is not a category; run with --help")),
    })
}
