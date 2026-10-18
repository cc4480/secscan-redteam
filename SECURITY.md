# Security Policy

SecScan RedTeam is an authorized-use penetration-testing product. It scans and tests systems only when the
engagement operator holds verified authorization for those exact targets, for scoped paid B2B engagements.
Functionality that makes authorized testing possible is intended behavior, not a vulnerability: reports that
the tool "can scan a target", "can run the commands it was pointed at", or "can exploit an authorized host"
are not security issues, while reports that the authorization and safety rails can be bypassed are.

## Supported versions

Security fixes land on the current minor line; older minors are unsupported.

| Component | Supported |
|---|---|
| `@secscan/redteam-runner` (this repository, `runner/`) | 0.37.x |
| `@secscan/redteam-auth-gate`, `@secscan/redteam-llm-router`, `@secscan/redteam-harness-plugin` | current 0.1.x / 0.2.x lines |
| Desktop shell that vendors the runner (separate desktop repository) | current 0.1.x minor |

## Reporting privately

Open this repository's **Security** tab and choose **Report a vulnerability** (GitHub private vulnerability
reporting). The resulting security advisory is visible only to maintainers. Do not disclose a suspected
vulnerability in a public issue, pull request, discussion, or chat message; if the private form is not
offered to you, open a public issue with no technical detail and ask for a private channel.

Include in your report: the affected component and version (package name plus version, or commit); the
impact, including which authorization or safety property is bypassed; reproduction steps or a proof of
concept if it can be shared safely; and relevant logs, with credentials and client data redacted.

## Response expectations

- Acknowledgement within 3 business days.
- Triage and an initial remediation plan within 10 business days.
- Coordinated disclosure: we agree a publication date with you and credit you if
  you want credit.

## Scope

In scope: the engagement runner (`runner/`), the desktop shell that ships it, and
the MCP tools and bridges (`harness-plugin/`, the SecScan and SecLayer MCP
integration). In-scope classes:

- Authorization and scope bypass: reaching a host outside the ownership-verified
  ROE scope, escaping local-sandbox rules, skipping phase sign-off, disabling the
  kill switch, or bypassing the destructive-command and DoS exclusions.
- Credential handling: credentials or tokens appearing in logs, errors, reports,
  process arguments, PoC bundles, or committed files.
- Tool supply chain: tampering with bundled external tools or payload libraries,
  resolving a substituted binary, or a reachable vulnerable dependency.

Out of scope: the test keys and private keys in vendored third-party dependency
fixtures (upstream test material, not live credentials); findings that require
both the console token and local administrator access on the same machine;
vulnerabilities in third-party tools themselves (nmap, nuclei, Metasploit,
sqlmap, ffuf, gobuster, nikto, john); dependency advisories with no reachable
code path in this product.

This policy covers reports about the product. It does not authorize testing any third-party system, and it
does not replace an engagement's ROE or the product's authorization gate.
