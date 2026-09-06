"""Regenerate the reviewed authority operation catalog from the reference source.

Run from this repository. Review the resulting allowlist before deployment.
This is a development tool; deployed gateways never discover arbitrary routes.
"""
import ast
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT.parent / "genesismesh"
EXCLUDE = {"/", "/favicon.svg", "/favicon.ico", "/operator-console-static/logo.svg",
           "/operator-console-static/styles.css", "/operator-console-static/console.js",
           "/dashboard", "/api-reference", "/cli-reference", "/atlas", "/connectome",
           "/metrics", "/healthz", "/swagger.json"}
GROUPS = {"public": "network", "health": "network", "crl": "network", "admin": "administration"}
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
})
operations = []
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
            methods = next((ast.literal_eval(k.value) for k in dec.keywords if k.arg == "methods"), ["GET"])
            parameters = re.findall(r"<(?:path:)?([^>]+)>", path)
            path = re.sub(r"<(?:path:)?([^>]+)>", r"{\1}", path)
            query = sorted(set(re.findall(r'request\.args\.get\(["\']([^"\']+)', ast.get_source_segment(file.read_text(encoding="utf-8"), function))))
            for method in methods:
                body = examples.get(path, {"reason": "cessation_of_operation"} if path.endswith("/revoke") else {})
                operations.append({"id": file.stem + "-" + function.name.replace("_", "-"),
                    "group": GROUPS.get(file.stem, file.stem), "name": function.name.removesuffix("_route").replace("_", " ").capitalize(),
                    "description": (ast.get_docstring(function) or "Genesis Mesh authority operation.").splitlines()[0],
                    "method": method, "upstream_path": path, "admin": path.startswith("/admin/") or path == "/nodes",
                    "parameters": parameters, "query": query, "body": body if method != "GET" else None})
assert len({o["id"] for o in operations}) == len(operations)
(ROOT / "ui/services.json").write_text(json.dumps(operations, indent=2) + "\n", encoding="utf-8")
print(f"Generated {len(operations)} reviewed operations")

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
spec_path.write_text(json.dumps(spec, indent=2) + "\n", encoding="utf-8")
