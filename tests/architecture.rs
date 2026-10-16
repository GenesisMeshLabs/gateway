//! The layer rules of `docs/architecture.md`, enforced over the source.
//!
//! A module may use modules in its own layer or a lower one. On top of that:
//! the trust library uses none of the gateway's frameworks, storage uses no
//! HTTP framework, and handlers do not reach storage. Today's exceptions are
//! listed in `ALLOWED`; the tests fail when a new one appears and when a
//! listed one is gone, so the list only shrinks.
//!
//! The source is read as text: comments, string and character literals and
//! `#[cfg(test)]` items are removed, then every `crate::` and `super::` path
//! (including `use` groups), every use of a listed external crate, and the
//! storage handles `cfg.durable` and `cfg.distributed_quota` are collected.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// The layers, lowest first. The same table is in `docs/architecture.md`.
const LAYERS: &[(&str, &[&str])] = &[
    ("foundation", &["error", "time"]),
    ("primitives", &["canonical", "crypto"]),
    ("documents", &["models", "admin_auth", "federation"]),
    ("evaluation", &["trust"]),
    (
        "gateway policy",
        &[
            "gateway::error",
            "gateway::security",
            "gateway::oidc",
            "gateway::tls",
        ],
    ),
    ("gateway storage", &["gateway::durable", "gateway::quota"]),
    ("gateway composition", &["gateway::config"]),
    (
        "gateway background",
        &["gateway::sync", "gateway::audit_delivery"],
    ),
    ("shared state", &["gateway::AppState"]),
    ("request pipeline", &["gateway::runtime"]),
    (
        "handlers",
        &[
            "gateway::handlers",
            "gateway::services",
            "gateway::ui",
            "gateway::mesh",
        ],
    ),
    ("router", &["gateway"]),
];

/// Layers 1 to 4 are the trust library.
const TRUST_LIBRARY_LAYERS: usize = 4;
const STORAGE_LAYER: &str = "gateway storage";
const HANDLER_LAYER: &str = "handlers";

/// Crates the trust library must not use.
const GATEWAY_CRATES: &[&str] = &[
    "axum",
    "axum_server",
    "tower",
    "tower_http",
    "tokio",
    "reqwest",
    "rusqlite",
    "redis",
    "jsonwebtoken",
    "rustls",
];
/// Crates storage must not use.
const HTTP_CRATES: &[&str] = &["axum", "axum_server", "tower", "tower_http", "reqwest"];
/// Crates that are storage, for the handler rule.
const STORAGE_CRATES: &[&str] = &["rusqlite", "redis"];

/// Today's exceptions: (module, what it uses, why). Remove an entry when the
/// edge is gone; never add one without the Maintainer's review.
const ALLOWED: &[(&str, &str, &str)] = &[
    (
        "federation",
        "crate reqwest",
        "fetches signed authority documents over HTTPS",
    ),
    (
        "gateway::handlers",
        "gateway::durable",
        "auth refuses with 503 while the state file is unhealthy; /api reports durable state",
    ),
    (
        "gateway::handlers",
        "gateway::quota",
        "auth admits clients against the shared Redis quota; /api reports it",
    ),
];

fn src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// The module a source file defines, or `None` for the crate root and the
/// binaries, which may use anything.
fn module_of(relative: &str) -> Option<String> {
    let relative = relative.replace('\\', "/");
    if relative == "lib.rs" || relative == "main.rs" || relative.starts_with("bin/") {
        return None;
    }
    if relative == "gateway/mod.rs" {
        return Some("gateway".into());
    }
    let stem = relative.strip_suffix(".rs")?;
    Some(stem.replace('/', "::"))
}

fn source_files() -> Vec<(String, String)> {
    fn walk(dir: &Path, base: &Path, out: &mut Vec<(String, String)>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, base, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let relative = path
                    .strip_prefix(base)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push((relative, std::fs::read_to_string(&path).unwrap()));
            }
        }
    }
    let mut out = Vec::new();
    walk(&src(), &src(), &mut out);
    out.sort();
    out
}

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// The source without comments, with every string and character literal
/// emptied, so neither can hide or fake a path or a brace.
fn strip(source: &str) -> String {
    let s: Vec<char> = source.chars().collect();
    let at = |i: usize| s.get(i).copied();
    let mut out = String::with_capacity(source.len());
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        let prev_ident = i > 0 && is_ident(s[i - 1]);
        if c == '/' && at(i + 1) == Some('/') {
            while i < s.len() && s[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if c == '/' && at(i + 1) == Some('*') {
            let mut depth = 0;
            while i < s.len() {
                if s[i] == '/' && at(i + 1) == Some('*') {
                    depth += 1;
                    i += 2;
                } else if s[i] == '*' && at(i + 1) == Some('/') {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    i += 1;
                }
            }
            out.push(' ');
            continue;
        }
        if !prev_ident && (c == 'r' || (c == 'b' && at(i + 1) == Some('r'))) {
            let mut j = i + if c == 'r' { 1 } else { 2 };
            let mut hashes = 0;
            while at(j) == Some('#') {
                hashes += 1;
                j += 1;
            }
            if at(j) == Some('"') {
                j += 1;
                loop {
                    if j >= s.len() {
                        break;
                    }
                    if s[j] == '"' && (1..=hashes).all(|k| at(j + k) == Some('#')) {
                        j += 1 + hashes;
                        break;
                    }
                    j += 1;
                }
                out.push_str("\"\"");
                i = j;
                continue;
            }
        }
        if c == '"' {
            let mut j = i + 1;
            while j < s.len() && s[j] != '"' {
                j += if s[j] == '\\' { 2 } else { 1 };
            }
            out.push_str("\"\"");
            i = j + 1;
            continue;
        }
        if c == '\'' {
            if at(i + 1) == Some('\\') {
                // Skip the escaped character, so '\'' ends at its last quote.
                let mut j = i + 3;
                while j < s.len() && s[j] != '\'' {
                    j += 1;
                }
                out.push_str("' '");
                i = j + 1;
                continue;
            }
            if at(i + 2) == Some('\'') {
                out.push_str("' '");
                i += 3;
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

/// Index of the brace that closes the one at `open`.
fn matching_brace(s: &[char], open: usize) -> usize {
    let mut depth = 0;
    for (i, &c) in s.iter().enumerate().skip(open) {
        if c == '{' {
            depth += 1;
        } else if c == '}' {
            depth -= 1;
            if depth == 0 {
                return i;
            }
        }
    }
    s.len() - 1
}

/// Remove every `#[cfg(test)]` item: test code may use any layer.
fn without_tests(stripped: &str) -> String {
    let mut s: Vec<char> = stripped.chars().collect();
    let marker: Vec<char> = "#[cfg(test)]".chars().collect();
    while let Some(start) = s.windows(marker.len()).position(|w| w == marker) {
        let mut end = start + marker.len();
        while end < s.len() && s[end] != '{' && s[end] != ';' {
            end += 1;
        }
        if end < s.len() && s[end] == '{' {
            end = matching_brace(&s, end);
        }
        s.drain(start..(end + 1).min(s.len()));
    }
    s.into_iter().collect()
}

/// Spans of inline (non-test) modules such as `mod py_datetime { .. }`: a
/// `super::` inside one refers to the file's own module.
fn inline_modules(s: &[char]) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut i = 0;
    while i + 3 < s.len() {
        let keyword = s[i..i + 3] == ['m', 'o', 'd']
            && (i == 0 || !is_ident(s[i - 1]))
            && s[i + 3].is_whitespace();
        if keyword {
            let mut j = i + 3;
            while j < s.len() && (s[j].is_whitespace() || is_ident(s[j])) {
                j += 1;
            }
            if j < s.len() && s[j] == '{' {
                spans.push((j, matching_brace(s, j)));
            }
        }
        i += 1;
    }
    spans
}

fn skip_ws(s: &[char], i: &mut usize) {
    while *i < s.len() && s[*i].is_whitespace() {
        *i += 1;
    }
}

fn ident(s: &[char], i: &mut usize) -> String {
    let start = *i;
    while *i < s.len() && is_ident(s[*i]) {
        *i += 1;
    }
    s[start..*i].iter().collect()
}

/// Parse a path or `use` tree after `crate::` or `super::`: every path it
/// names, as segments (`{a::b, c}` gives `[a, b]` and `[c]`; a glob gives an
/// empty path).
fn tree(s: &[char], i: &mut usize) -> Vec<Vec<String>> {
    skip_ws(s, i);
    if *i < s.len() && s[*i] == '{' {
        *i += 1;
        let mut paths = Vec::new();
        loop {
            skip_ws(s, i);
            if *i >= s.len() {
                break;
            }
            if s[*i] == '}' {
                *i += 1;
                break;
            }
            if s[*i] == ',' {
                *i += 1;
                continue;
            }
            let before = *i;
            paths.extend(tree(s, i));
            if *i == before {
                *i += 1;
            }
        }
        return paths;
    }
    if *i < s.len() && s[*i] == '*' {
        *i += 1;
        return vec![vec![]];
    }
    let head = ident(s, i);
    if head.is_empty() {
        return vec![vec![]];
    }
    let mut j = *i;
    skip_ws(s, &mut j);
    if s.get(j) == Some(&':') && s.get(j + 1) == Some(&':') {
        *i = j + 2;
        return tree(s, i)
            .into_iter()
            .map(|mut rest| {
                rest.insert(0, head.clone());
                rest
            })
            .collect();
    }
    // `name as alias`
    let mut k = j;
    if ident(s, &mut k) == "as" {
        skip_ws(s, &mut k);
        ident(s, &mut k);
        *i = k;
    }
    vec![vec![head]]
}

/// Every path that follows `keyword::` (`crate` or `super`) at a path start,
/// with its position.
fn paths_after(s: &[char], keyword: &str) -> Vec<(usize, Vec<String>)> {
    let key: Vec<char> = format!("{keyword}::").chars().collect();
    let mut found = Vec::new();
    let mut i = 0;
    while i + key.len() <= s.len() {
        let starts_path = i == 0 || !(is_ident(s[i - 1]) || s[i - 1] == ':');
        if starts_path && s[i..i + key.len()] == key[..] {
            let mut j = i + key.len();
            for path in tree(s, &mut j) {
                found.push((i, path));
            }
            i = j.max(i + 1);
        } else {
            i += 1;
        }
    }
    found
}

/// Items re-exported by `pub use` in a module file, mapped to the module
/// that defines them.
fn reexports(source: &str) -> BTreeMap<String, String> {
    let s: Vec<char> = without_tests(&strip(source)).chars().collect();
    let key: Vec<char> = "pub use ".chars().collect();
    let mut map = BTreeMap::new();
    let mut i = 0;
    while i + key.len() <= s.len() {
        if s[i..i + key.len()] == key[..] {
            let mut j = i + key.len();
            for path in tree(&s, &mut j) {
                if let [module, .., item] = path.as_slice() {
                    map.insert(item.clone(), module.clone());
                }
            }
            i = j;
        } else {
            i += 1;
        }
    }
    map
}

struct Resolver {
    root_modules: BTreeSet<String>,
    gateway_modules: BTreeSet<String>,
    root_reexports: BTreeMap<String, String>,
    gateway_reexports: BTreeMap<String, String>,
}

impl Resolver {
    fn new(files: &[(String, String)]) -> Self {
        let mut root_modules = BTreeSet::new();
        let mut gateway_modules = BTreeSet::new();
        let mut root_reexports = BTreeMap::new();
        let mut gateway_reexports = BTreeMap::new();
        for (relative, source) in files {
            match module_of(relative) {
                Some(m) if m == "gateway" => {
                    root_modules.insert(m);
                    gateway_reexports = reexports(source);
                }
                Some(m) => match m.strip_prefix("gateway::") {
                    Some(sub) => {
                        gateway_modules.insert(sub.to_owned());
                    }
                    None => {
                        root_modules.insert(m);
                    }
                },
                None if relative == "lib.rs" => root_reexports = reexports(source),
                None => {}
            }
        }
        Self {
            root_modules,
            gateway_modules,
            root_reexports,
            gateway_reexports,
        }
    }

    /// The module a path from the crate root names.
    fn resolve_root(&self, path: &[String]) -> Option<String> {
        let head = path.first()?;
        if head == "gateway" {
            return Some(self.resolve_gateway(&path[1..]));
        }
        if self.root_modules.contains(head) {
            return Some(head.clone());
        }
        if let Some(module) = self.root_reexports.get(head) {
            return Some(module.clone());
        }
        panic!("cannot resolve crate::{}", path.join("::"));
    }

    /// The module a path inside `gateway` names.
    fn resolve_gateway(&self, path: &[String]) -> String {
        match path.first() {
            Some(head) if self.gateway_modules.contains(head) => format!("gateway::{head}"),
            Some(head) if head == "AppState" => "gateway::AppState".into(),
            Some(head) => match self.gateway_reexports.get(head) {
                Some(module) => format!("gateway::{module}"),
                None => "gateway".into(),
            },
            None => "gateway".into(),
        }
    }
}

/// Everything each module uses: other modules, `crate <name>` for listed
/// external crates, and storage reached through the configuration handles.
fn dependencies() -> BTreeMap<String, BTreeSet<String>> {
    let files = source_files();
    let resolver = Resolver::new(&files);
    let crates: BTreeSet<&str> = GATEWAY_CRATES
        .iter()
        .chain(HTTP_CRATES)
        .chain(STORAGE_CRATES)
        .copied()
        .collect();
    let mut graph: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (relative, source) in &files {
        let Some(module) = module_of(relative) else {
            continue;
        };
        let text: Vec<char> = without_tests(&strip(source)).chars().collect();
        let nested = inline_modules(&text);
        let in_nested = |pos: usize| nested.iter().any(|&(a, b)| a < pos && pos < b);
        let uses = graph.entry(module.clone()).or_default();
        let mut add = |target: String| {
            if target != module {
                uses.insert(target);
            }
        };
        for (_, path) in paths_after(&text, "crate") {
            if !path.is_empty() {
                if let Some(target) = resolver.resolve_root(&path) {
                    add(target);
                }
            }
        }
        for (pos, path) in paths_after(&text, "super") {
            if in_nested(pos) || path.is_empty() {
                continue;
            }
            if module.starts_with("gateway::") {
                add(resolver.resolve_gateway(&path));
            } else if let Some(target) = resolver.resolve_root(&path) {
                add(target);
            }
        }
        for name in &crates {
            if !paths_after(&text, name).is_empty() {
                add(format!("crate {name}"));
            }
        }
        let text: String = text.iter().collect();
        for (field, storage) in [
            (".durable", "gateway::durable"),
            (".distributed_quota", "gateway::quota"),
        ] {
            let found = text.match_indices(field).any(|(at, _)| {
                !text[at + field.len()..]
                    .chars()
                    .next()
                    .is_some_and(is_ident)
            });
            if found {
                add(storage.into());
            }
        }
    }
    graph
}

fn layer_of(module: &str) -> Option<usize> {
    LAYERS
        .iter()
        .position(|(_, modules)| modules.contains(&module))
}

fn layer_named(name: &str) -> usize {
    LAYERS.iter().position(|(n, _)| *n == name).unwrap()
}

/// Every edge that breaks a rule, as (module, what it uses).
fn violations() -> BTreeSet<(String, String)> {
    let storage = layer_named(STORAGE_LAYER);
    let handlers = layer_named(HANDLER_LAYER);
    let mut found = BTreeSet::new();
    for (module, uses) in dependencies() {
        let Some(layer) = layer_of(&module) else {
            continue;
        };
        for target in uses {
            let broken = if let Some(name) = target.strip_prefix("crate ") {
                (layer < TRUST_LIBRARY_LAYERS && GATEWAY_CRATES.contains(&name))
                    || (layer == storage && HTTP_CRATES.contains(&name))
                    || (layer == handlers && STORAGE_CRATES.contains(&name))
            } else {
                let target_layer =
                    layer_of(&target).unwrap_or_else(|| panic!("{target} has no layer"));
                target_layer > layer || (layer == handlers && target_layer == storage)
            };
            if broken {
                found.insert((module.clone(), target));
            }
        }
    }
    found
}

fn allowed() -> BTreeSet<(String, String)> {
    ALLOWED
        .iter()
        .map(|(module, target, _)| ((*module).to_owned(), (*target).to_owned()))
        .collect()
}

#[test]
fn every_module_has_exactly_one_layer() {
    let mut seen = BTreeSet::new();
    for (_, modules) in LAYERS {
        for module in *modules {
            assert!(seen.insert(*module), "{module} is in two layers");
        }
    }
    let files: BTreeSet<String> = source_files()
        .iter()
        .filter_map(|(relative, _)| module_of(relative))
        .collect();
    for module in &files {
        assert!(
            layer_of(module).is_some(),
            "{module} has no layer: add it to LAYERS here and to the table in docs/architecture.md"
        );
    }
    for module in seen {
        assert!(
            module == "gateway::AppState" || files.contains(module),
            "LAYERS lists {module}, which has no source file"
        );
    }
}

#[test]
fn no_module_breaks_a_layer_rule_beyond_the_allowlist() {
    let new: Vec<_> = violations().difference(&allowed()).cloned().collect();
    assert!(
        new.is_empty(),
        "new layer violations (module, what it uses): {new:?}. Move the code to the \
         right layer (docs/architecture.md); the allowlist only shrinks."
    );
}

#[test]
fn every_allowed_exception_still_exists() {
    let gone: Vec<_> = allowed().difference(&violations()).cloned().collect();
    assert!(
        gone.is_empty(),
        "these exceptions are gone; remove them from ALLOWED: {gone:?}"
    );
}

/// The reader finds edges that are known to exist, and ignores test code,
/// so a broken reader cannot pass the rules by seeing nothing.
#[test]
fn the_source_reader_sees_known_edges() {
    let graph = dependencies();
    for (module, target) in [
        ("models", "canonical"),
        ("models", "time"),
        ("trust", "models"),
        ("admin_auth", "crypto"),
        ("federation", "crate reqwest"),
        ("gateway::security", "trust"),
        ("gateway::durable", "gateway::security"),
        ("gateway::config", "gateway::quota"),
        ("gateway::audit_delivery", "gateway::durable"),
        ("gateway::runtime", "gateway::AppState"),
        ("gateway::runtime", "gateway::error"),
        ("gateway::handlers", "gateway::runtime"),
        ("gateway::handlers", "gateway::durable"),
        ("gateway::services", "crypto"),
        ("gateway::mesh", "admin_auth"),
        ("gateway::ui", "crate axum"),
    ] {
        assert!(
            graph[module].contains(target),
            "{module} -> {target} not found: {:?}",
            graph[module]
        );
    }
    // Only tests use these; test code is not checked.
    assert!(!graph["gateway::runtime"].contains("gateway"));
    assert!(!graph["gateway::sync"].contains("crypto"));
}

#[test]
fn the_source_reader_handles_groups_literals_and_test_items() {
    let source = r##"
        use crate::{a::{b, c::D}, e as f, g::*};
        // crate::commented::out
        /* crate::block::comment */
        const S: &str = "crate::in_a_string {";
        const R: &str = r#"super::raw "quoted" }"#;
        const C: char = '{';
        const Q: char = '\'';
        fn f<'a>(x: &'a str) -> &'a str { crate::h::call(x) }
        mod inner { use super::*; fn k() { super::own(); } }
        #[cfg(test)]
        mod tests { use crate::test_only; }
        #[cfg(test)]
        use crate::test_import;
        fn after() { crate::i::j(); }
    "##;
    let text: Vec<char> = without_tests(&strip(source)).chars().collect();
    let heads: Vec<String> = paths_after(&text, "crate")
        .into_iter()
        .map(|(_, p)| p.join("::"))
        .collect();
    assert_eq!(heads, ["a::b", "a::c::D", "e", "g", "h::call", "i::j"]);
    let nested = inline_modules(&text);
    assert!(paths_after(&text, "super")
        .iter()
        .all(|(pos, _)| nested.iter().any(|&(a, b)| a < *pos && *pos < b)));
}
