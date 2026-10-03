// ---------------------------------------------------------------------------
// RDP session-shadowing exposure — HUMAN-GATED (WS-065).
//
// Shadowing a live user's session is inherently interactive: an operator
// sits in a GUI session and views another person's live desktop. A headless
// agent cannot meaningfully automate that, and must not pretend to.
// What the runner CAN do — and what rdpShadowPrep() does — is prepare
// EVERYTHING up to the human step via read-only WinRM enumeration:
// live session IDs, the shadow permission state, the exact shadow command,
// and the consent/ROE checklist. The item keeps needs:"human operator".
// ---------------------------------------------------------------------------

/** Read-only PowerShell: enumerate live RDP sessions + shadow policy state. */
export const RDP_SHADOW_PREP_PS = [
  "$err = $null",
  "$sessions = @(qwinsta 2>$null | Select-Object -Skip 1 | ForEach-Object {",
  "  $p = $_ -split '\\s+', 6",
  "  if ($p.Count -ge 4) { [pscustomobject]@{ Session=$p[0].Trim('>'); User=$p[1]; Id=$p[2]; State=$p[3] } }",
  "} | Where-Object { $_.State -match 'Active|Disc' })",
  "$shadowPol = Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name Shadow -ErrorAction SilentlyContinue",
  "$ts = Get-CimInstance -Namespace root/cimv2/terminalservices -ClassName Win32_TSAccount -ErrorAction SilentlyContinue |",
  "  Select-Object AccountName, @{n='RemoteControl';e={ $_.PermissionsAllowed -band 16 }}",
  "[pscustomobject]@{",
  "  Sessions = $sessions",
  "  ShadowPolicy = if ($shadowPol) { $shadowPol.Shadow } else { 'not-set (server default applies)' }",
  "  RemoteControlGrants = @($ts)",
  "} | ConvertTo-Json -Depth 4 -Compress",
].join("\n");

/**
 * Build the human handoff package for RDP shadowing from the read-only
 * enumeration output. Pure function — tested directly.
 */
export function buildShadowHandoff(prepJson: string, host: string): string {
  let sessions = "unknown";
  let policy = "unknown";
  try {
    const o = JSON.parse(prepJson) as {
      Sessions?: { Session?: string; User?: string; Id?: string; State?: string }[];
      ShadowPolicy?: unknown;
    };
    const list = Array.isArray(o.Sessions) ? o.Sessions : [];
    sessions =
      list.length > 0
        ? list.map((s) => `session "${s.Session ?? "?"}" id=${s.Id ?? "?"} user=${s.User ?? "?"} state=${s.State ?? "?"}`).join("; ")
        : "no active/disconnected user sessions enumerated";
    policy = String(o.ShadowPolicy ?? "unknown");
  } catch {
    sessions = `enumeration output was not JSON — raw: ${prepJson.slice(0, 300)}`;
  }
  return [
    `RDP SHADOW HANDOFF — ${host} (HUMAN OPERATOR REQUIRED)`,
    `Live sessions: ${sessions}`,
    `Shadow consent policy (0=disable,1=full w/o consent,2=full w/ consent,3=view w/o consent,4=view w/ consent): ${policy}`,
    `Exact command (run from an RDP session on ${host} as the authorized test account): mstsc /shadow:<SESSION_ID> [/control] [/noConsentPrompt only if ROE explicitly allows]`,
    `ROE / CONSENT CHECKLIST — all must be true before shadowing:`,
    `  1. The engagement ROE explicitly authorizes session shadowing (it is surveillance otherwise).`,
    `  2. The target session's user has consented, OR the consent policy + ROE waives it — never assume.`,
    `  3. Record: session ID shadowed, start/end time, consent basis, what was observed (facts only).`,
    `  4. Black mode: shadowing a live user session is never acceptable — report the permission state only.`,
    `What to observe and record: whether a consent prompt appeared on the target session, what the operator could see/do, and whether the shadow event was logged (Event ID 20510/20506 class).`,
  ].join("\n");
}
