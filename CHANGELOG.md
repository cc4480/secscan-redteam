# Changelog

Notable changes to the secscan-redteam runner. This file starts at 0.35.0; no
prior release history is reconstructed here.

## [0.35.0] - 2026-10-17

- **WA-*: the 120-item web application battery.** A fifth, opt-in target
  (`WA-001`...`WA-120`, 19 blocks) for attacking a client's own web
  application; the four vendor batteries and the 418-item contract are
  unchanged.
- **`ALL_TARGETS` and the `webapp` target.** `webapp` is registered in the
  target registry (prefix `WA`, `BATTERY_ITEM_COUNTS.webapp = 120`, profile
  `kind: "webapp"`) and exposed through `ALL_TARGETS`, while
  `FULL_BATTERY_TARGETS` stays at the four vendor targets.
- **Launch surface.** `start_engagement` gains a `targets` argument, so the
  harness can launch a webapp engagement, and `http_probe`'s `targetProfile`
  accepts `"webapp"`.
- **`docs/webapp-battery.md` added.** Documents the 19 blocks, the tool that
  executes each, every `needs` prerequisite, the evidence discipline and the
  provenance from the SecScan and Seclayer scan corpora; `docs/full-battery.md`
  links to it.
