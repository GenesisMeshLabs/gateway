#!/usr/bin/env bash
# Records the quickstart (docs/quickstart.md) as session.txt, the transcript
# the GIF is rendered from. Run it on Linux in an empty directory, with
# `genesis-mesh` (pip install genesis-mesh), `genesis-mesh-gateway` and
# `genesis-mesh-operator` on PATH, and jq, openssl and curl installed. Ports
# 8443 and 8080 must be free. Each command is printed with "$ " and then run;
# its output follows unchanged. Lines starting "==> " are step headings.
#
# Render:
#   python docs/assets/render_terminal_gif.py session.txt quickstart.gif \
#     --title "Genesis Mesh -- Gateway Quickstart"
set -uo pipefail
out=${SESSION:-session.txt}
: > "$out"
note() { printf '%s\n' "$1" >> "$out"; }
run() { note "\$ $1"; eval "$1" >> "$out" 2>&1; }

note "==> 1. A local Network Authority and its signed policy fragment"
run 'genesis-mesh init --network-name quickstart > init.log 2>&1'
run '(genesis-mesh na start > na.log 2>&1 &); sleep 5'
run 'NA_KEY=$(grep -v "^#" .genesis-mesh/keys/na.pub)'
run 'genesis-mesh-operator --origin http://127.0.0.1:8443 --network quickstart --authority-key "$NA_KEY" --allow-http --report preflight.json --policy-fragment network.json > /dev/null'
run 'jq "{network, passed}" preflight.json'

note "==> 2. One client, stored as the SHA-256 of its token"
run 'TOKEN=$(openssl rand -hex 32)'
run 'DIGEST=$(printf %s "$TOKEN" | sha256sum | cut -d" " -f1)'
run 'jq --arg d "$DIGEST" "{revision: \"quickstart-1\", clients: [{id: \"quickstart-client\", token_sha256: \$d, networks: [\"quickstart\"], metrics: true, requests_per_minute: 120}], networks: .}" network.json > policy.json'

note "==> 3. Check the policy, initialize durable state, start"
run 'export GATEWAY_POLICY_FILE=$PWD/policy.json'
run 'genesis-mesh-gateway --check-config'
run 'export GATEWAY_STATE_FILE=$PWD/state.db'
run 'genesis-mesh-gateway --init-state'
run '(genesis-mesh-gateway > gateway.log 2>&1 &); sleep 2'
run 'curl -s http://127.0.0.1:8080/ready; echo'

note "==> 4. Join a node, then verify its certificate at the gateway"
run 'INVITE=$(genesis-mesh admin invite --role role:client)'
run 'genesis-mesh join --na http://127.0.0.1:8443 --token "$INVITE" 2>/dev/null'
run 'CERT_ID=$(jq -r .cert_id .genesis-mesh/node.cert.json)'
run 'AUTH="Authorization: Bearer $TOKEN"'
run 'jq "{certificate: .}" .genesis-mesh/node.cert.json > verify.json'
run 'curl -s -H "$AUTH" --json @verify.json http://127.0.0.1:8080/verify; echo'

note "==> 5. Revoke it at the authority; the gateway reads the new CRL within a minute"
run 'genesis-mesh admin revoke "$CERT_ID" --reason cessation_of_operation > revoke.log'
run 'until curl -s -H "$AUTH" http://127.0.0.1:8080/v1/networks | jq -e ".networks[0].revocation.revoked_count == 1" > /dev/null; do sleep 5; done'
run 'curl -s -H "$AUTH" http://127.0.0.1:8080/v1/networks | jq -c ".networks[0] | {name, ready, sequence: .revocation.sequence}"'
run 'curl -s -H "$AUTH" --json @verify.json http://127.0.0.1:8080/verify; echo'

# Colour only: mark success and refusal lines for the renderer. The text of
# each line stays as it was printed.
sed -i \
  -e 's/^Configuration valid$/!ok &/' \
  -e 's/^Durable state initialized from verified operator policy$/!ok &/' \
  -e 's/^{"status":"ready"}$/!ok &/' \
  -e 's/^Joined quickstart as role:client$/!ok &/' \
  -e 's/^{"trusted":true,.*$/!ok &/' \
  -e 's/^{"trusted":false,.*$/!no &/' \
  -e 's/^  "passed": true$/!ok &/' \
  "$out"
