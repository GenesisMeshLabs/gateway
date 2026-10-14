"""Regenerate the reviewed authority operation catalog from the reference source.

Run from this repository. Review the resulting allowlist before deployment.
This is a development tool; deployed gateways never discover arbitrary routes.

    python tests/reference/build_service_catalog.py [--core PATH] [--check]

``--check`` writes nothing and fails when the committed catalog or OpenAPI
document differs from what the core source produces (CI runs it against core
main, so a new core route cannot go unreviewed). A route left out on purpose
is listed in ``NOT_FORWARDED`` with its reason; the run fails when the core
no longer has one of them.
"""
import argparse
import ast
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
parser.add_argument("--core", type=Path, default=ROOT.parent / "genesismesh", help="genesismesh checkout")
parser.add_argument("--check", action="store_true", help="fail on drift instead of writing")
args = parser.parse_args()
SOURCE = args.core
EXCLUDE = {"/", "/favicon.svg", "/favicon.ico", "/operator-console-static/logo.svg",
           "/operator-console-static/styles.css", "/operator-console-static/console.js",
           "/dashboard", "/api-reference", "/cli-reference", "/atlas", "/connectome",
           "/metrics", "/healthz", "/swagger.json", "/surfaces"}
# Authority routes the gateway deliberately does not forward, with the reason.
# An audit pack (1.5.0) is one answer of up to 50,000 entries with everything
# they cite, often 50 MB or more: the gateway would hold it in memory several
# times over, past its 10-second authority timeout (the CLI waits 120 s). An
# auditor runs `genesis-mesh audit pack` against the authority instead.
NOT_FORWARDED = {"/admin/evidence/audit-pack": "audit pack: an unpaged bulk export of up to 50,000 entries"}
# Query parameters the core reads in its service layer rather than the route,
# on the GET operation of the path (the grant list shares its path with issuance).
SERVICE_QUERY = {
    "/admin/evidence": ["after_sequence", "attestation_id", "capability", "decision_id", "entry_kind",
                        "limit", "outcome", "resource_id", "since", "until", "vendor_id"],
    "/admin/evidence/export": ["limit", "since_sequence"],
    "/admin/grants": ["before", "bearer_key_id", "limit", "status"],
}
# Responses that are not a JSON document, forwarded as text within their own limit.
RESPONSE_FORMATS = {"/admin/evidence/export": {"response": "ndjson", "max_response_bytes": 8 * 1024 * 1024}}
# JSON responses that may exceed the default 2 MiB: a due-queue page (up to 500
# states, each with its pending review), one subject's every review and record,
# a resource's changes (up to 10,000, each with its remediation from 1.4.0), and
# (1.6.0) a page of up to 500 grant summaries of up to 16 capabilities each, and
# a signed grant, issued or read, whose envelope holds up to 64 parameters of up
# to 256 values each.
RESPONSE_LIMITS = {path: {"max_response_bytes": 8 * 1024 * 1024} for path in [
    "/admin/evidence/remediations", "/admin/evidence/remediations/{subject_id}",
    "/admin/evidence/changes/{resource_id}", "/admin/grants", "/admin/grants/{grant_id}"]}
# The remediation routes (1.4.0) are evidence-store operations: a client scoped
# to the store reaches them, as controllers submit their remediation records there.
# The key history (1.5.0) is public network metadata, read like the genesis block.
# Pre-issued grants (1.6.0) are evidence-store operations: a grant, its uses and
# its revocation are store records, its bearer is a registered executor key, and
# holders submit their time-token requests and uses there, as controllers submit
# execution evidence. Issuing and revoking need a privileged operator signature,
# reading a read-tier one; the authority checks the tier.
GROUPS = {"public": "network", "health": "network", "crl": "network", "admin": "administration",
          "remediation": "evidence_store", "key_history": "network", "grants": "evidence_store"}
# Routes whose group is not their file's: recording a succession replaces the
# NA's signing key, so only clients scoped to administration may forward it.
PATH_GROUPS = {"/admin/na/succession": "administration"}
examples = {}
doc = (SOURCE / "docs/api/trust-http.md").read_text(encoding="utf-8")
for section in re.split(r"(?=### `)", doc):
    heading = re.match(r"### `(POST|GET) ([^`]+)`", section)
    sample = re.search(r"```json\s*(.*?)\s*```", section, re.S)
    if heading and sample:
        try:
            examples[heading[2]] = json.loads(sample[1])
        except json.JSONDecodeError:
            pass
examples.update({
    "/admin/policy": {"min_client_version": "0.56.0", "allowed_ports": [443, 8443], "allowed_services": [], "routing": {}},
    "/attestations/verify": {"attestation": {}, "recognition_policy": {"local_sovereign_id": "authority-a", "recognized_issuers": [{"sovereign_id": "authority-a", "public_keys": ["PASTE_AUTHORITY_PUBLIC_KEY"], "allowed_roles": ["role:client"]}]}},
    "/agents": {"agent_id": "gateway-demo-agent", "node_public_key": "PASTE_NODE_PUBLIC_KEY", "network_name": "authority-a", "capabilities": ["read"], "endpoint": {"host": "agent.example.org", "port": 443, "scheme": "wss"}, "registered_at": "NOW", "metadata": {}, "expires_at": "FUTURE_TIMESTAMP", "signatures": []},
    "/agents/{node_public_key}": {"version": "1", "signed_at": "NOW", "signature": "PASTE_NODE_SIGNATURE"},
    "/admin/recognition-treaties": {"subject_sovereign_id": "authority-b", "subject_public_keys": ["PASTE_AUTHORITY_PUBLIC_KEY"], "scope": {"allowed_roles": ["role:client"]}, "validity_hours": 1},
    "/recognition-treaties/verify": {"treaty": {}, "issuer_public_keys": []},
    "/attestations/verify-with-treaty": {"attestation": {}, "treaty": {}, "issuer_public_keys": []},
    "/admin/sovereign-revocation-feeds/import": {"feed": {}, "issuer_public_keys": ["PASTE_AUTHORITY_PUBLIC_KEY"]},
    "/admin/attestations": {"subject_id": "gateway-demo-subject", "roles": ["role:client"], "validity_hours": 1},
    "/admin/invite": {"roles": ["role:client"], "max_validity_hours": 1, "token_expiry_hours": 1},
    "/admin/recognition-policy": {"recognition_policy": {"local_sovereign_id": "authority-a", "recognized_issuers": []}},
    "/join": {"invite_token": "PASTE_INVITE_TOKEN", "node_public_key": "PASTE_NODE_PUBLIC_KEY", "timestamp": "NOW", "nonce": "UNIQUE_NONCE", "signature": "PASTE_NODE_SIGNATURE"},
    "/heartbeat": {"cert_id": "PASTE_CERTIFICATE_ID", "status": "active", "node_public_key": "PASTE_NODE_PUBLIC_KEY", "timestamp": "NOW", "nonce": "UNIQUE_NONCE", "signature": "PASTE_NODE_SIGNATURE"},
    "/renew": {"cert_id": "PASTE_CERTIFICATE_ID", "validity_hours": 1, "node_public_key": "PASTE_NODE_PUBLIC_KEY", "timestamp": "NOW", "nonce": "UNIQUE_NONCE", "signature": "PASTE_NODE_SIGNATURE"},
    "/admin/revoke": {"cert_id": "PASTE_CERTIFICATE_ID", "reason": "cessation_of_operation"},
    "/admin/policy/rollback": {"policy_id": "PASTE_POLICY_ID"},
    "/admin/boundary-policies/validate": {"policy_id": "transfer-limits", "valid_from": "2026-10-01T00:00:00Z", "valid_until": "2027-10-01T00:00:00Z", "selector": {"capabilities": ["payments.*"]}, "gates": [{"gate_id": "app", "gate_type": "attestation_claim.v1", "order": 0, "config": {"path": "request_parameters.app_id", "claim": "apps"}}]},
    "/admin/boundary-policies/{policy_id}/activate": {"version": 1},
    "/admin/boundary-policies/{policy_id}/deactivate": {"version": 1},
    "/boundary-policies/verify": {"policy": {}, "issuer_public_keys": []},
    "/evidence/execution": {"evidence": {}},
    "/admin/evidence/executor-keys": {"key_id": "controller-1", "public_key": "PASTE_EXECUTOR_PUBLIC_KEY", "executor_sovereign_id": "controller-1"},
    # through_sequence (1.5.0): the last entry an archive covers; the placeholder is refused unedited.
    "/admin/evidence/retention/apply": {"older_than_days": 365, "through_sequence": "PASTE_ARCHIVED_THROUGH_SEQUENCE"},
    "/admin/evidence/archives": {"manifest": {}, "location": "PASTE_ARCHIVE_LOCATION"},
    "/admin/na/succession": {"succession": {}},
    "/evidence/remediations": {"record": {}},
    "/admin/evidence/remediations/{subject_id}/notified": {"channel": "email"},
    "/admin/evidence/reviews": {"subject_kind": "judgement", "subject_id": "PASTE_JUDGEMENT_ID", "justification": "Why a second holder should review this change"},
    "/admin/evidence/reviews/{review_id}/decide": {"verdict": "uphold", "note": "Reviewed with the change owner"},
    # Pre-issued grants (1.6.0): the bearer and the basis are placeholders the authority refuses unedited.
    "/admin/grants": {"bearer_key_id": "PASTE_EXECUTOR_KEY_ID", "capabilities": ["secret.manage"],
                      "attestation_id": "PASTE_ATTESTATION_ID", "valid_from": "2026-06-01T08:00:00Z",
                      "valid_until": "2026-06-01T12:00:00Z", "max_uses": 3, "max_uses_per_time_token": 2,
                      "parameter_envelope": {"region": {"one_of": ["eu-west", "eu-north"]}}},
    "/admin/grants/{grant_id}/revoke": {"reason": "The device holding the grant was lost"},
    "/grants/time-tokens": {"request": {}},
    "/evidence/grant-executions": {"evidence": {}},
})
operations = []
left_out = set()
for file in sorted((SOURCE / "genesis_mesh/na_service/routes").glob("*.py")):
    tree = ast.parse(file.read_text(encoding="utf-8"))
    for function in ast.walk(tree):
        if not isinstance(function, ast.FunctionDef):
            continue
        for dec in function.decorator_list:
            if not isinstance(dec, ast.Call) or not isinstance(dec.func, ast.Attribute) or dec.func.attr != "route":
                continue
            path = ast.literal_eval(dec.args[0])
            if path in EXCLUDE:
                continue
            if path in NOT_FORWARDED:
                left_out.add(path)
                continue
            methods = next((ast.literal_eval(k.value) for k in dec.keywords if k.arg == "methods"), ["GET"])
            parameters = re.findall(r"<(?:path:)?([^>]+)>", path)
            path = re.sub(r"<(?:path:)?([^>]+)>", r"{\1}", path)
            route_query = set(re.findall(r'request\.args\.get\(["\']([^"\']+)', ast.get_source_segment(file.read_text(encoding="utf-8"), function)))
            for method in methods:
                query = sorted(route_query | set(SERVICE_QUERY.get(path, []) if method == "GET" else []))
                body = examples.get(path, {"reason": "cessation_of_operation"} if path.endswith("/revoke") else {})
                operations.append({"id": file.stem + "-" + function.name.replace("_", "-"),
                    "group": PATH_GROUPS.get(path, GROUPS.get(file.stem, file.stem)), "name": function.name.removesuffix("_route").replace("_", " ").capitalize(),
                    "description": (ast.get_docstring(function) or "Genesis Mesh authority operation.").splitlines()[0],
                    "method": method, "upstream_path": path, "admin": path.startswith("/admin/") or path == "/nodes",
                    "parameters": parameters, "query": query, "body": body if method != "GET" else None,
                    **RESPONSE_FORMATS.get(path, {}), **RESPONSE_LIMITS.get(path, {})})
assert len({o["id"] for o in operations}) == len(operations)
assert left_out == set(NOT_FORWARDED), f"routes left out that the core no longer has: {set(NOT_FORWARDED) - left_out}"
outputs = {ROOT / "ui/services.json": json.dumps(operations, indent=2) + "\n"}

spec_path = ROOT / "ui/openapi.json"
spec = json.loads(spec_path.read_text(encoding="utf-8"))
spec["paths"] = {k: v for k, v in spec["paths"].items() if "/services/" not in k}
spec["paths"]["/v1/services"] = {"get": {"summary": "List authority service operations", "responses": {"200": {"description": "Service catalog"}}}}
for op in operations:
    parameters = [{"name": "network", "in": "path", "required": True, "schema": {"type": "string"}}]
    parameters += [{"name": p, "in": "query", "required": p in op["parameters"], "schema": {"type": "string"}} for p in op["parameters"] + op["query"]]
    if op["admin"]:
        parameters += [{"name": h, "in": "header", "required": True, "schema": {"type": "string"}} for h in ["X-Admin-Key-Id", "X-Admin-Timestamp", "X-Admin-Nonce", "X-Admin-Signature"]]
    entry = {"operationId": op["id"], "summary": op["name"], "description": op["description"] + " Upstream: " + op["upstream_path"],
             "tags": [op["group"]], "security": [{"bearerAuth": []}], "parameters": parameters,
             "responses": {str(n): {"description": description} for n, description in [(200,"Authority response"),(201,"Created"),(400,"Invalid input"),(401,"Authentication required"),(403,"Scope denied"),(404,"Not found"),(429,"Rate limit exceeded"),(502,"Authority unavailable or invalid response")]}}
    if op["body"] is not None:
        entry["requestBody"] = {"required": True, "content": {"application/json": {"schema": {"type": "object"}, "example": op["body"]}}}
    spec["paths"]["/v1/networks/{network}/services/" + op["id"]] = {op["method"].lower(): entry}
outputs[spec_path] = json.dumps(spec, indent=2) + "\n"
drift = [p.relative_to(ROOT).as_posix() for p, text in outputs.items() if p.read_text(encoding="utf-8") != text]
if args.check:
    if drift:
        sys.exit(f"Catalog drift from the core: regenerate {', '.join(drift)} with "
                 "tests/reference/build_service_catalog.py and review the new operations.")
    print(f"Catalog matches the core: {len(operations)} reviewed operations, {len(left_out)} route(s) not forwarded")
else:
    for path, text in outputs.items():
        # LF on every platform, as the repository stores them.
        path.write_text(text, encoding="utf-8", newline="\n")
    print(f"Generated {len(operations)} reviewed operations; not forwarded: "
          + ", ".join(f"{p} ({why})" for p, why in sorted(NOT_FORWARDED.items())))
