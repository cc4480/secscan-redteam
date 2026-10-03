# Compliance-mapped reporting (v0.12.0)

Enterprise buyers don't buy findings — they buy evidence their auditors
accept. This document describes the compliance story the runner produces
for every engagement: what the pack contains, which frameworks it
supports, and where the honest limits are.

## What each engagement produces

Next to `report.md` in the engagement directory, the runner writes three
mechanical, runner-computed artifacts (no LLM invention):

| File | Contents |
|---|---|
| `compliance-pack.json` | Structured evidence pack (machine-readable) |
| `compliance-pack.md` | Human-readable evidence pack |
| `attestation.md` | One-page attestation letter template for the client's auditors |

## Frameworks covered

- **PCI DSS v4.0.1 — Requirement 11.4** (penetration testing): the parent
  requirement plus 11.4.1 (documented methodology), 11.4.2 (internal
  testing), 11.4.3 (external testing), 11.4.4 (remediation + retest),
  11.4.5 (segmentation testing), 11.4.6 (service providers), 11.4.7
  (multi-tenant providers).
- **SOC 2** — CC6.1 (logical access security), CC6.6 (protection against
  external threats), CC7.1 (detection/monitoring for new vulnerabilities).
- **ISO/IEC 27001:2022** — A.8.8 (management of technical vulnerabilities).

The full control catalog lives in `runner/src/compliance/controls.ts`.

## How coverage works

Every finding carries MITRE ATT&CK technique IDs. The compliance module
maps each technique ID used by the 418-item battery to the controls it
evidences (`runner/src/compliance/mapping.ts`), so control coverage is
computed mechanically from the findings — not hand-waved. The test suite
asserts **zero unmapped technique IDs** and **zero invented control IDs**.

## The evidence pack contains

1. **Engagement metadata** — target, scope, ROE, test window, objective,
   authorization proof reference (DNS TXT ownership verification), and the
   named human operator accountable for the engagement.
2. **Documented methodology** — the section QSAs demand under PCI DSS
   11.4.1. It describes the agent-driven approach truthfully (autonomous
   agent team: coordinator/recon/exploiter/reporter, coordinator sign-off
   gates, mechanical safety rails), the phases, the tools used, the
   validation standard (benign canary markers — proof of execution, not
   assertion), and the **explicit exclusions** (DoS, destructive payloads,
   phishing/social engineering, out-of-scope targets).
3. **Findings → controls table** — each finding with severity, ATT&CK IDs,
   mapped controls, evidence reference, remediation guidance, and retest
   status.
4. **Retest evidence** — before/after observations per vulnerability class
   across the registry history (supports PCI DSS 11.4.4's "repeat testing
   to verify corrections").
5. **Honest limits** — what the pack does NOT claim (see below).

## The attestation letter

`attestation.md` is a one-page template stating what was tested, when,
the scope, methodology, exclusions, and validation standard — with fill-in
fields for the client name, operator, issuing organization, and signature.
Honesty is mechanical: the test suite asserts the letter never claims the
client is "compliant"/"certified" and never claims the testing organization
holds any certification. It is evidence *for* the client's auditors, not
a verdict *about* the client.

## Honest limits (stated in the pack itself)

- The pack is **evidence supporting requirements** — it never declares the
  client compliant or certified. That judgment belongs to the client's
  QSA/auditor.
- Controls with no exercised findings in an engagement are listed as
  having no evidence from that test — never pretended otherwise.
- Findings without ATT&CK IDs carry no control mapping (the mapping is
  technique-keyed, honestly).
- The tester is an **AI agent team under mechanical safety rails**, not a
  human penetration tester. Assessors evaluating tester qualification
  (e.g. PCI DSS 11.4.1's "qualified" language) should weigh the
  methodology description directly — it is written for exactly that
  reading.
- Retest evidence is observational (before/after), not a certification of
  remediation.

## Operator setup

Set the accountable operator's name before delivery (used in the pack and
attestation; the pack flags it honestly if missing):

```bash
export REDTEAM_OPERATOR="Jane Operator"
```

or pass `operatorName` in the `EngagementInput`.

## What this does NOT do

- It does not generate evidence for frameworks outside the catalog.
- It does not replace a QSA, a SOC 2 auditor, or an ISO certification
  body.
- It does not make the automated test a substitute for every compliance
  need — e.g. PCI DSS 11.4.5 segmentation testing and 11.4.6/11.4.7
  provider obligations are in the catalog, but whether a given engagement's
  scope satisfies them is the assessor's call on the evidence.
