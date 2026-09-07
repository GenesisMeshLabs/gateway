# Security assurance and acceptance plan

Started 2026-09-07 for the deployed v0.57.0 gateway. Scope includes Rust trust
and HTTP code, embedded JavaScript, deployment/release automation, dependencies,
the shipped container and the current self-hosted deployment. Findings require
reproduction, a fix or an explicit unresolved disposition, and a regression check.
Passing scans is bounded evidence, not proof that vulnerabilities do not exist.

## Execution order

1. Finish credential rotation: inventory owners and schedules, deploy replacement
   identities, switch callers, remove old identities, prove 401 on every gateway
   process and through ingress, and preserve replacement scope denials.
2. Complete separate JoinCRL and membership-feed canaries: acceptance, revoke,
   denial, process restart, retained sequence floors and continued denial.
3. Back up the live SQLite store consistently, restore into isolated storage,
   authenticate against current pinned keys and independent sequence records,
   and verify revoked canaries remain denied. Never initialize over lost history.
4. Define audit retention, capacity alerts and integrity boundaries. Keep an
   independently stored sequence/backup manifest; local SQLite is not immutable.
5. Run the static/dynamic checks below, reproduce findings, implement security
   fixes only, and rerun affected checks plus existing regression gates.

## Static analysis and supply chain

- Existing Rustfmt/Clippy, locked dependency audit, security regressions and
  cross-language canonical/signature fixtures remain required checks.
- Add CodeQL analysis for Rust, JavaScript and GitHub Actions using the
  security-extended suite. Review its extraction/coverage as well as alerts;
  framework and language support do not imply every custom trust rule is modeled.
- Scan a public source snapshot and exported image for exposed secrets and known
  dependency/OS vulnerabilities. Never mount the live secret directory or Docker
  control socket into a scanner. Record scanner version and image/source digest.
- Manually review authorization, issuer binding, rollback protection, untrusted
  URLs/redirects, request cancellation, input/body limits, log/audit leakage,
  release permissions and credentials in artifacts. Convert confirmed findings
  into targeted regression tests rather than merely suppressing warnings.

## Dynamic analysis

- Passive web scanning of an isolated replica's public console/API surfaces.
  A passive scan cannot establish authenticated business-logic coverage.
- Authenticated negative requests for wrong/retired credentials, cross-network
  access, missing operator signatures, wrong methods, unsupported service paths,
  malformed/oversized JSON, forged signatures and forbidden caller trust material.
- Exercise OIDC signature/claim/key failures and mTLS client rejection in isolated
  tests; keep those deployment adapters disabled as decided in ADR 0001.
- Exercise quota concurrency/backend failures, durable-state corruption/ownership,
  revocation rollback, audit failures and restart recovery. Avoid running broad
  active crawlers against real authority mutation endpoints.
- Verify public responses and browser rendering do not expose service secrets,
  unapproved network details or executable upstream content.

## Closure criteria

Retain machine-readable scan/test reports and a human-readable findings register
with scope, severity, reproduction, disposition and retest evidence. Fix confirmed
reachable findings in scope; document any unresolved issue, unavailable test or
coverage gap. Do not label a scan job successful solely because its tool exited
zero: inspect the findings and extraction status. Independent penetration testing,
organization identity/PKI and accreditation remain external acceptance work.

Primary tool references: [CodeQL language coverage](https://codeql.github.com/docs/codeql-overview/supported-languages-and-frameworks/),
[CodeQL Rust queries](https://docs.github.com/en/code-security/code-scanning/managing-your-code-scanning-configuration/rust-built-in-queries),
[ZAP baseline scope](https://www.zaproxy.org/docs/docker/baseline-scan/),
[Trivy image scanning](https://trivy.dev/docs/latest/guide/target/container_image/).
