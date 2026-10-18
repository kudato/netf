//! Diagnostics fail before output files and before any network work.
mod common;
use common::World;

#[test]
fn misspellings_point_at_the_fragment_and_suggest_without_executing() {
    for (args, fragment, suggestion) in [
        (vec!["net.countri: XA"], "net.countri", "net.country"),
        (vec!["--limt", "20", "as.asn: 64498"], "--limt", "--limit"),
        (
            vec!["--fields", "match,net.hodler", "ip: 192.0.2.1"],
            "net.hodler",
            "net.holder",
        ),
    ] {
        let world = World::new();
        let mut args = args;
        args.extend(["-f", "result.txt"]);
        let (out, lines) = world.run(&args);
        assert_eq!(out.code, 2, "{lines:?}");
        assert!(out.stdout.is_empty());
        let diagnostic = lines.join("\n");
        assert!(
            diagnostic.contains(fragment) && diagnostic.contains(suggestion),
            "{diagnostic}"
        );
        assert!(
            diagnostic.contains(&"^".repeat(fragment.len())),
            "{diagnostic}"
        );
        assert!(diagnostic.contains("Did you mean"), "{diagnostic}");
        assert!(!diagnostic.contains('\x1b'));
        assert!(world.transport.requests().is_empty());
        assert!(!world.home.path().join("result.txt").exists());
        assert!(!world.home.path().join(".result.txt.lock").exists());
    }
}

#[test]
fn unicode_multiline_long_queries_and_unclosed_quotes_have_readable_locations() {
    for query in [
        "as.name: 日本 and net.countri: XA".into(),
        "as.asn: 64498 and\nnet.countri: XA".into(),
        format!("as.name: {} and net.countri: XA", "x".repeat(300)),
        "net.org: \"Example 日本".into(),
        "as.asn: 64498 and".into(),
        "as.asn: wrong".into(),
    ] {
        let world = World::new();
        let (out, lines) = world.run(&[&query]);
        assert_eq!(out.code, 2);
        let error = lines.join("\n");
        assert!(error.contains('\n') && error.contains('^'), "{error}");
        assert!(!error.contains('\x1b'));
        if query.starts_with("as.name: 日本") {
            assert!(
                error.contains(&format!("\n  {}{}\n", " ".repeat(18), "^".repeat(11))),
                "{error}"
            );
        }
        assert!(world.transport.requests().is_empty());
    }
}
