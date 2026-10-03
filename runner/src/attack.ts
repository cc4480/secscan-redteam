/**
 * MITRE ATT&CK technique catalog used by the runner.
 *
 * Started as a web-focused subset; v0.8.0 adds host techniques (Windows /
 * Linux) for the host batteries. The coordinator maps every operation-plan
 * step to one of these IDs; every streamed event carries the ID of the
 * technique it exercises. This is what makes the engagement legible to a
 * client's SOC: they can see exactly which adversary behaviors were emulated
 * and where their detections did or didn't fire.
 *
 * Honest scope note (also stated in the client report): ATT&CK is built for
 * endpoint/network intrusions, and web vulnerability classes (SQLi, XSS, IDOR…)
 * map imperfectly onto it. In this runner, successful exploitation of a
 * public-facing web flaw is recorded as T1190 (Exploit Public-Facing
 * Application); the specific flaw class is named in the event text and the
 * finding. The mapping is a lens, not a claim that ATT&CK natively models
 * every web bug.
 */

export * from "./attack/catalog.js";
