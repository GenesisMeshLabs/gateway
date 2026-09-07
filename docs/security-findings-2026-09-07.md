# Security findings and verification, 2026-09-07

Scope: gateway Rust/JavaScript/Actions source, locked Rust dependencies, Linux
AMD64 runtime, isolated HTTP replica and self-hosted public ingress. The plan is
[security-assurance-plan.md](security-assurance-plan.md). Raw local reports are
under `.local/security-scan`; they are not bundled with credentials in releases.

## Findings register

| Finding | Disposition and verification |
| --- | --- |
| Mutable CI action tags (9 CodeQL findings) | Fixed: every action reference pinned to a commit, with weekly Dependabot updates. CodeQL Actions retest passed. |
| Certificate identifiers printed by verification CLI (2 CodeQL findings) | Removed unnecessary identifier output, retaining decision/reasons. CodeQL Rust retest resolved both findings. |
| Certificate diagnostics in two fixture tests | Removed unnecessary fixture dumps. These were test-only findings, not demonstrated production secret leaks. CodeQL retest resolved them. |
| Operator token-file to HTTP flows in probe scripts (3 CodeQL findings) | Intentional authentication, manually triaged: files and destinations are explicit local operator inputs; no server request controls either. Security probe restricted to loopback; SLO probe requires HTTPS except loopback; redirects prohibited. Tokens never enter reports. These findings are false positives for exfiltration, not vulnerabilities fixed by suppressing a scanner. |
| Runtime OS packages: 310 advisory occurrences, including 4 critical and 63 high | Replaced Debian 12/curl/shell runtime with digest-pinned distroless Debian 13 and native bounded health probe. Final image: 20 occurrences, 13 medium/7 low, **zero high/critical**, zero secrets. Remaining advisories are listed below, not hidden by an ignore file. |
| Missing Permissions Policy and browser isolation headers | Added explicit permission denial, COOP, COEP and CORP. ZAP retest: 66 rule passes, zero failures, only the intentional non-storable-content warning. Same-origin console assets remain allowed. |
| Non-storable content | Intentional `Cache-Control: no-store` to protect operator responses; retain it. Not a security defect. |
| Kubernetes default namespace (low) and placeholder registry (medium) | Distribution-template findings, not a live Kubernetes deployment. Namespace and trusted registry/admission must be chosen by the installing organization; registry admission remains P1. No claim these organizational settings are activated. |

Trivy 0.74.0 scanned exported images without Docker control-socket access or live
secret mounts. Final local image digest:
`sha256:f2638268fa25348ec035dd20aad556e10303a6c8a4b2f58e1bc82114873a3eab`.
The scanner did not extract Rust dependencies from the stripped executable;
locked Cargo audit is a separate required check. OS advisory occurrence counts
are package findings, not counts of remotely exploitable gateway defects.

## Executed dynamic and regression checks

- 17 bounded authenticated HTTP checks passed on the restored production-mode
  replica: missing/invalid/retired tokens, preserved operator access, relay scope,
  unavailable signing routes, wrong methods, malformed/oversized payloads, empty
  batch, forbidden caller anchors, cross-network access, restored revocation,
  forged signature, unknown proxy operation and browser security headers.
- Existing Linux suite: 68 tests passed, with the Redis integration test separate.
  Coverage includes wrong issuer/key, rollback/forgery, durable corruption and
  ownership conflicts, audit restore, OIDC signature/claim failures, mTLS missing
  and foreign clients, quota failure, proxy redirects/path injection and public
  projection privacy. Browser signing interoperability also passed.
- Native image health probe passed; actual container became healthy. Local and
  public `/api` report 0.57.1, `/ready` is ready, four networks are available, and
  retired operator credentials still return 401 after deployment.
- The ZAP baseline covers eight discovered public URLs; it is passive and cannot
  substitute for authenticated API abuse testing or an independent pentest.
- Separate live rotation/revoke/restart/offline-restore evidence and audit alarm
  checks are in [deployment acceptance](acceptance-2026-09-07.md).

## Continuing assurance and remaining limits

CodeQL Rust/JavaScript/Actions runs on pushes/PRs and weekly. Locked Cargo audit
and security regressions remain CI gates. The container/secret workflow runs
weekly or on demand, retains full reports, and fails for high/critical runtime
advisories or exposed secrets. Dependabot proposes updates to pinned inputs.
Review lower findings too; scanner success alone is not an acceptance decision.

The residual OS entries currently have no fixed version in the scanner's Debian
data. Their presence remains tracked. Several concern C locale conversion,
formatted-I/O, glob/regex/debug interfaces that have no identified caller in the
gateway's reviewed HTTP paths, but this is not a complete binary reachability
proof. Do not label all vulnerabilities fixed. Rebuild/rescan when upstream
fixes arrive, and reassess any demonstrated reachable issue immediately.

Independent penetration testing, fuzzing coverage, ARM64 runtime execution,
Redis HA/capacity, host/ingress configuration review and organizational registry
admission remain separate evidence. No claim of zero unknown vulnerabilities,
WORM audit integrity or government accreditation is made.

## Residual runtime advisories

| Advisory | Package | Severity |
| --- | --- | --- |
| CVE-2026-18374 | libc6 | MEDIUM |
| CVE-2026-19499 | libc6 | MEDIUM |
| CVE-2026-19542 | libc6 | MEDIUM |
| CVE-2026-5435 | libc6 | MEDIUM |
| CVE-2026-5450 | libc6 | MEDIUM |
| CVE-2026-5928 | libc6 | MEDIUM |
| CVE-2026-6238 | libc6 | MEDIUM |
| CVE-2026-6368 | libc6 | MEDIUM |
| CVE-2026-6791 | libc6 | MEDIUM |
| CVE-2026-77117 | libc6 | MEDIUM |
| CVE-2026-80489 | libc6 | MEDIUM |
| CVE-2010-4756 | libc6 | LOW |
| CVE-2018-20796 | libc6 | LOW |
| CVE-2019-1010022 | libc6 | LOW |
| CVE-2019-1010023 | libc6 | LOW |
| CVE-2019-1010024 | libc6 | LOW |
| CVE-2019-1010025 | libc6 | LOW |
| CVE-2019-9192 | libc6 | LOW |
| CVE-2026-27171 | zlib1g | MEDIUM |
| CVE-2026-85091 | zlib1g | MEDIUM |
