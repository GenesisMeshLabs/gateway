//! Invariants over the whole generated authority catalog (`ui/services.json`).
//!
//! The catalog is regenerated from the core for every core feature. These
//! checks turn its security properties into test failures instead of
//! something a reviewer has to spot in a regenerated JSON diff.

use std::collections::BTreeSet;

use genesis_mesh::gateway::security::DEMO_SERVICE_GROUPS;
use serde_json::Value;

/// Every authority operation a public demo client can reach, as
/// (operation ID, method, upstream path). A demo client is limited to
/// `DEMO_SERVICE_GROUPS` and never reaches an operator (`admin`) operation,
/// so this is the set of non-admin operations in those groups. Each one must
/// be a read or a verification: the demo token is published.
///
/// When this test fails, a regenerated catalog changed what the published
/// token can do. Add the operation here only after checking it is a read or
/// a verification; otherwise move it to an operator operation or out of the
/// demo groups in the catalog generator.
const DEMO_ALLOWED_OPERATIONS: &[(&str, &str, &str)] = &[
    // agreement
    ("agreement-verify-route", "POST", "/agreements/verify"),
    // attestations
    (
        "attestations-get-attestation",
        "GET",
        "/attestations/{attestation_id}",
    ),
    (
        "attestations-get-recognition-policy",
        "GET",
        "/recognition-policy",
    ),
    ("attestations-list-attestations", "GET", "/attestations"),
    (
        "attestations-sovereign-revocation-feed",
        "GET",
        "/sovereign-revocation-feed",
    ),
    (
        "attestations-verify-attestation",
        "POST",
        "/attestations/verify",
    ),
    // boundary
    ("boundary-verify", "POST", "/boundary/verify"),
    // boundary_policy
    (
        "boundary_policy-verify-policy",
        "POST",
        "/boundary-policies/verify",
    ),
    // consensus
    ("consensus-verify", "POST", "/consensus/verify"),
    // data_usage
    ("data_usage-get-policy", "GET", "/data-usage/policy"),
    ("data_usage-verify", "POST", "/data-usage/verify"),
    // disclosure
    ("disclosure-prove", "POST", "/disclosure/prove"),
    ("disclosure-verify", "POST", "/disclosure/verify"),
    // evidence
    ("evidence-verify", "POST", "/trust-evidence/verify"),
    // network
    ("crl-get-crl", "GET", "/crl"),
    ("health-health", "GET", "/health"),
    ("health-readyz", "GET", "/readyz"),
    ("key_history-key-history", "GET", "/na/key-history"),
    ("public-atlas-json", "GET", "/atlas.json"),
    ("public-dashboard-json", "GET", "/dashboard.json"),
    ("public-get-genesis", "GET", "/genesis"),
    ("public-get-policy", "GET", "/policy"),
    ("public-sovereign-metadata", "GET", "/sovereign.json"),
    // treaties
    ("treaties-connectome-json", "GET", "/connectome.json"),
    (
        "treaties-connectome-trust-path",
        "GET",
        "/connectome/trust-path",
    ),
    (
        "treaties-get-treaty",
        "GET",
        "/recognition-treaties/{treaty_id}",
    ),
    ("treaties-list-treaties", "GET", "/recognition-treaties"),
    ("treaties-recognition-graph", "GET", "/recognition-graph"),
    (
        "treaties-verify-attestation-with-treaty-route",
        "POST",
        "/attestations/verify-with-treaty",
    ),
    (
        "treaties-verify-treaty",
        "POST",
        "/recognition-treaties/verify",
    ),
];

fn catalog() -> Vec<Value> {
    let operations: Vec<Value> =
        serde_json::from_str(include_str!("../ui/services.json")).expect("service catalog");
    assert!(!operations.is_empty(), "the catalog has no operations");
    operations
}

fn text<'a>(operation: &'a Value, field: &str) -> &'a str {
    operation[field]
        .as_str()
        .unwrap_or_else(|| panic!("{operation}: {field} is not a string"))
}

#[test]
fn the_demo_token_reaches_only_the_allowed_read_and_verify_operations() {
    let reachable: BTreeSet<(String, String, String)> = catalog()
        .iter()
        .filter(|o| DEMO_SERVICE_GROUPS.contains(&text(o, "group")))
        .filter(|o| o["admin"] != Value::Bool(true))
        .map(|o| {
            (
                text(o, "id").to_owned(),
                text(o, "method").to_owned(),
                text(o, "upstream_path").to_owned(),
            )
        })
        .collect();
    let allowed: BTreeSet<(String, String, String)> = DEMO_ALLOWED_OPERATIONS
        .iter()
        .map(|(id, method, path)| ((*id).into(), (*method).into(), (*path).into()))
        .collect();
    assert_eq!(
        allowed.len(),
        DEMO_ALLOWED_OPERATIONS.len(),
        "duplicate entries in DEMO_ALLOWED_OPERATIONS"
    );
    let gained: Vec<_> = reachable.difference(&allowed).collect();
    let lost: Vec<_> = allowed.difference(&reachable).collect();
    assert!(
        gained.is_empty() && lost.is_empty(),
        "the public demo token's reach changed.\n  newly reachable: {gained:?}\n  no longer reachable: {lost:?}\n\
         Review each newly reachable operation: only reads and verifications may be in a demo group without `admin`."
    );
}

#[test]
fn every_demo_service_group_exists_in_the_catalog() {
    let groups: BTreeSet<String> = catalog()
        .iter()
        .map(|o| text(o, "group").to_owned())
        .collect();
    for group in DEMO_SERVICE_GROUPS {
        assert!(
            groups.contains(group),
            "demo service group {group} is not in the catalog"
        );
    }
}

#[test]
fn every_admin_path_is_an_operator_operation() {
    let operations = catalog();
    let admin_paths = operations
        .iter()
        .filter(|o| text(o, "upstream_path").starts_with("/admin/"))
        .count();
    assert!(
        admin_paths > 0,
        "no /admin/ path matched; the check is void"
    );
    for operation in &operations {
        if text(operation, "upstream_path").starts_with("/admin/") {
            assert_eq!(
                operation["admin"],
                Value::Bool(true),
                "{} forwards {} without operator authorization",
                text(operation, "id"),
                text(operation, "upstream_path")
            );
        }
    }
}

#[test]
fn operation_ids_are_unique() {
    let operations = catalog();
    let ids: BTreeSet<&str> = operations.iter().map(|o| text(o, "id")).collect();
    assert_eq!(ids.len(), operations.len(), "duplicate operation IDs");
}
