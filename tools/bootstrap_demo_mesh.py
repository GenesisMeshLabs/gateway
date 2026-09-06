"""Create reusable, real demo trust records through the gateway API.

Requires Python cryptography. Keys are read locally and never transmitted.
Only adds role:client treaties and explicitly labeled demo memberships.
Existing active records are reused; no policy or existing record is replaced.
"""
import argparse
import base64
import json
import uuid
import urllib.request
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', default='http://127.0.0.1:8080')
    parser.add_argument('--token-file', required=True)
    parser.add_argument('--peer', action='append', default=[], help='Additional read-only peer network; no operator key required')
    parser.add_argument('--authority', action='append', required=True, help='network=operator-key-file')
    args = parser.parse_args()
    token = Path(args.token_file).read_text().strip()
    keys = {}
    for entry in args.authority:
        name, path = entry.split('=', 1)
        seed = ''.join(line.strip() for line in Path(path).read_text().splitlines() if not line.startswith('#'))
        keys[name] = Ed25519PrivateKey.from_private_bytes(base64.b64decode(seed))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    def get(path):
        with opener.open(args.base + path, timeout=20) as response:
            return json.load(response)
    catalog = {(o['method'], o['upstream_path']): o for o in get('/v1/services')['operations']}

    def call(network, method, path, body=None):
        operation = catalog[(method, path)]
        headers = {'Authorization': 'Bearer ' + token}
        if operation['admin']:
            timestamp = datetime.now(timezone.utc).isoformat()
            nonce = str(uuid.uuid4())
            envelope = {'body': body or {}, 'key_id': 'operator-local', 'timestamp': timestamp, 'nonce': nonce}
            signature = keys[network].sign(json.dumps(envelope, sort_keys=True, separators=(',', ':')).encode())
            headers.update({'X-Admin-Key-Id': 'operator-local', 'X-Admin-Timestamp': timestamp,
                            'X-Admin-Nonce': nonce, 'X-Admin-Signature': base64.b64encode(signature).decode()})
        data = None if method == 'GET' else json.dumps(body or {}).encode()
        if data is not None:
            headers['Content-Type'] = 'application/json'
        request = urllib.request.Request(args.base + '/v1/networks/' + network + '/services/' + operation['id'],
                                         data=data, headers=headers, method=method)
        with opener.open(request, timeout=20) as response:
            return json.load(response)

    def reusable(row, field):
        record = row[field]
        return row['status'] == 'active' and datetime.fromisoformat(record['expires_at'].replace('Z', '+00:00')) > datetime.now(timezone.utc) + timedelta(days=1)

    public = {n: call(n, 'GET', '/genesis')['network_authority']['public_key'] for n in list(keys) + args.peer}
    treaties, memberships = {}, {}
    for network in keys:
        existing = call(network, 'GET', '/recognition-treaties')['recognition_treaties']
        for peer in public:
            if peer == network:
                continue
            treaty = next((r['treaty'] for r in existing if reusable(r, 'treaty')
                           and r['treaty']['issuer_sovereign_id'] == network
                           and r['treaty']['subject_sovereign_id'] == peer
                           and public[peer] in r['treaty']['subject_public_keys']
                           and 'role:client' in r['treaty']['scope']['allowed_roles']), None)
            if treaty is None:
                treaty = call(network, 'POST', '/admin/recognition-treaties', {
                    'subject_sovereign_id': peer, 'subject_public_keys': [public[peer]],
                    'scope': {'allowed_roles': ['role:client']}, 'validity_hours': 720,
                    'metadata': {'purpose': 'gateway demo mesh', 'demo': True}})
            result = call(network, 'POST', '/recognition-treaties/verify', {'treaty': treaty, 'issuer_public_keys': [public[network]]})
            assert result['accepted'], result
            treaties[(network, peer)] = treaty
        existing_members = call(network, 'GET', '/attestations')['attestations']
        memberships[network] = []
        for subject in ['demo:records-service', 'demo:permit-service', 'demo:data-exchange']:
            attestation = next((r['attestation'] for r in existing_members if reusable(r, 'attestation')
                                and r['attestation']['subject_id'] == subject
                                and r['attestation']['claims'].get('public_mesh') is True
                                and r['attestation']['claims'].get('demo') is True), None)
            if attestation is None:
                attestation = call(network, 'POST', '/admin/attestations', {
                    'subject_id': subject, 'roles': ['role:client'], 'validity_hours': 720,
                    'claims': {'public_mesh': True, 'demo': True, 'purpose': 'Illustrative participant; no application endpoint'}})
            memberships[network].append(attestation)
    for peer in args.peer:
        memberships[peer] = [r['attestation'] for r in call(peer, 'GET', '/attestations')['attestations'] if reusable(r, 'attestation') and r['attestation']['claims'].get('public_mesh') is True and r['attestation']['claims'].get('demo') is True]
    for (network, peer), treaty in treaties.items():
        feed = call(peer, 'GET', '/sovereign-revocation-feed')
        try:
            call(network, 'POST', '/admin/sovereign-revocation-feeds/import', {'feed': feed})
        except urllib.error.HTTPError as error:
            details = json.load(error)
            if error.code != 409 or details.get('error', {}).get('code') != 'stale_sequence':
                raise RuntimeError(details) from error
            print(network + ': retained existing revocation high-water mark for ' + peer)
        for attestation in memberships[peer]:
            result = call(network, 'POST', '/attestations/verify-with-treaty', {
                'attestation': attestation, 'treaty': treaty, 'treaty_issuer_public_keys': [public[network]]})
            assert result['accepted'], result
        print(network + ' recognizes ' + peer + ': signature, revocation feed and ' + str(len(memberships[peer])) + ' cross-network memberships verified')
    print('Demo mesh ready: ' + str(len(public)) + ' authorities, ' + str(len(treaties)) + ' directed treaties, ' + str(sum(map(len, memberships.values()))) + ' signed demo memberships. Validity: 30 days; rerun to reuse or renew expiring demo records.')


if __name__ == '__main__':
    main()
