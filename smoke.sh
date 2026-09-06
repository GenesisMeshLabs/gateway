#!/usr/bin/env bash
# End-to-end check against a running gateway.
# Usage: BASE=http://localhost:8080 [TOKEN=secret] bash smoke.sh
set -euo pipefail

BASE="${BASE:-http://localhost:8080}"
AUTH=()
[ -n "${TOKEN:-}" ] && AUTH=(-H "Authorization: Bearer ${TOKEN}")

echo "# health"
curl -fsS "$BASE/health"; echo

echo "# keygen authority + node"
authority=$(curl -fsS "${AUTH[@]}" -X POST "$BASE/keygen")
node=$(curl -fsS "${AUTH[@]}" -X POST "$BASE/keygen")
auth_seed=$(echo "$authority" | grep -o '"seed_b64":"[^"]*"' | cut -d'"' -f4)
auth_pub=$(echo "$authority"  | grep -o '"public_key_b64":"[^"]*"' | cut -d'"' -f4)
node_pub=$(echo "$node"       | grep -o '"public_key_b64":"[^"]*"' | cut -d'"' -f4)

echo "# issue a 7-day cert signed by na-001"
cert=$(curl -fsS "${AUTH[@]}" -X POST "$BASE/issue" -H 'content-type: application/json' -d "{
  \"seed_b64\": \"$auth_seed\",
  \"key_id\": \"na-001\",
  \"node_public_key\": \"$node_pub\",
  \"network_name\": \"mesh-alpha\",
  \"roles\": [\"role:anchor\"]
}")
echo "$cert"

echo "# verify against the right anchor -> trusted"
curl -fsS "${AUTH[@]}" -X POST "$BASE/verify" -H 'content-type: application/json' -d "{
  \"certificate\": $cert,
  \"anchors\": { \"na-001\": \"$auth_pub\" }
}"; echo

echo "# verify against a bogus anchor -> not trusted"
curl -fsS "${AUTH[@]}" -X POST "$BASE/verify" -H 'content-type: application/json' -d "{
  \"certificate\": $cert,
  \"anchors\": { \"na-001\": \"$node_pub\" }
}"; echo

echo "# verify/batch: three copies against the right anchor -> all trusted"
curl -fsS "${AUTH[@]}" -X POST "$BASE/verify/batch" -H 'content-type: application/json' -d "{
  \"certificates\": [$cert, $cert, $cert],
  \"anchors\": { \"na-001\": \"$auth_pub\" }
}"; echo

echo "# no token -> 401"
curl -s -o /dev/null -w '[%{http_code}]\n' -X POST "$BASE/keygen"
