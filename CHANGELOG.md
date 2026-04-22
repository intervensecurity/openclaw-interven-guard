# Changelog

All notable changes to `openclaw-interven-guard` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Semantic Versioning](https://semver.org/).

## [0.3.0] — 2026-04-19

### Changed — PAM-style hard block on REQUIRE_APPROVAL (BREAKING)

Interven is now positioned correctly as a **firewall**, not an operator-decision aid. When a scan returns `REQUIRE_APPROVAL`, the plugin **hard-blocks** the tool call instead of surfacing an OpenClaw approval card to the operator.

**Old behavior (v0.2.x):** plugin returned `{ requireApproval: ... }` → operator saw a Yes/No card on Telegram → operator decided → OpenClaw ran the tool. Interven was a passive observer.

**New behavior (v0.3.0):** plugin returns `{ block: true, blockReason: "🛡️ Blocked pending security review. Approve at https://app.intervensecurity.com/approvals/<id>. Once approved, ask me to retry." }`. The security analyst (a separate human from the agent operator) approves in the Interven Console. The operator retries the same action, the gateway recognises the recent approval (via the new `RECENT_APPROVAL_GRANT` short-circuit on identical request signatures), and the tool runs.

**Why:** The previous flow let the agent operator approve their own potentially-malicious actions, which makes Interven a logging system rather than a security control. Real PAM systems (BeyondTrust, CyberArk, Teleport) all use this two-actor pattern: requester ≠ approver. v0.3.0 brings Interven in line.

### Migration from v0.2.x
- The OpenClaw approval card on Telegram/Discord/Slack will no longer appear for `REQUIRE_APPROVAL` decisions.
- Operators will see a hard-block message instead, with a link to the Interven Console.
- After the analyst approves, the operator must re-trigger the same action (saying "ask me to retry" works); the gateway will short-circuit to ALLOW because of the recent approval grant.
- This requires the gateway to be on Interven v0.4.0+ which ships the `RECENT_APPROVAL_GRANT` logic and migration `015_approval_signature.sql`. Older Interven gateways will work with this plugin but the retry won't auto-allow until they upgrade.

### Removed
- The `requireApproval` hook return from the `before_tool_call` flow. Plugins requiring operator-driven approval workflows should fork.

## [0.2.2] — 2026-04-19

### Fixed
- v0.2.1 install crashed at the config-write step with `must have required property 'apiKey'` because the configSchema marked `apiKey` as `required` and OpenClaw's installer writes an empty `{}` config before the operator has a chance to fill in fields. v0.2.2 removes `required: ["apiKey"]` from the schema — the field is documented as required-for-enforcement in its description, and the plugin code already fails open with a clear log line when it's missing, so the operator gets a clean install + a deferred apiKey-set step.
- Removed the `iv_(live|test)_*` regex pattern from `apiKey` for the same reason — strict patterns can fail validation against the empty default written at install time.

## [0.2.1] — 2026-04-19

### Changed (security scanner pass)
- Removed all `process.env.*` reads from `index.ts`. v0.2.0 was hard-blocked at install by OpenClaw's static security scanner ("Environment variable access combined with network send — possible credential harvesting") because it co-located env access and outbound `fetch` in one file. v0.2.1 sources every config field exclusively from `api.pluginConfig`, eliminating the env-access pattern.
- `apiKey` is now marked **required** in `openclaw.plugin.json` configSchema (validated against `^iv_(live|test)_[A-Za-z0-9]{20,}$`). Without it the plugin fails open as before, but operators get an explicit prompt at install time.
- `scanTimeoutMs` exposed as a configSchema field (was previously env-only).

### Migration
v0.1.x / v0.2.0 users who set `INTERVEN_API_KEY` / `INTERVEN_GATEWAY_URL` / `INTERVEN_SCAN_TIMEOUT_MS` / `INTERVEN_GUARDED_TOOLS` as env vars must move those values into `~/.openclaw/openclaw.json` under `plugins.entries["openclaw-interven-guard"].config.{apiKey, gatewayUrl, scanTimeoutMs, guardedTools}`. See README for the exact JSON snippet.

## [0.2.0] — 2026-04-19

### Added
- Configurable guarded tools via `INTERVEN_GUARDED_TOOLS` env var or `guardedTools` plugin config (array). Lets operators narrow scanning to e.g. just `web_fetch` without forking the plugin.
- `guardedTools` field documented in `openclaw.plugin.json` configSchema.
- LICENSE file (MIT) and CHANGELOG.md for ClawHub publishing.
- `openclaw.build.openclawVersion: "2026.4.15"` in package.json — pins the gateway version this plugin was built against (required by the ClawHub publisher).

### Changed
- Default gateway URL is now `https://api.intervensecurity.com` (was `http://100.80.251.3:4000` lab IP). Override with `INTERVEN_GATEWAY_URL` for self-hosted Interven.
- `package.json` hardened for ClawHub publish: license, repository, homepage, keywords, files allowlist, engines.

## [0.1.0] — 2026-04-15

### Added
- Initial release. `before_tool_call` hook scans `web_fetch`, `exec`, `web_search`, `browser`, `message` through Interven `POST /v1/scan`.
- Decisions: `ALLOW` passes through, `DENY` blocks with reason codes, `SANITIZE` blocks with sanitized payload preview, `REQUIRE_APPROVAL` returns OpenClaw approval object.
- Fail-open on network error, timeout, missing API key, bad JSON, or non-200 response.
- Configurable via env vars (`INTERVEN_GATEWAY_URL`, `INTERVEN_API_KEY`, `INTERVEN_SCAN_TIMEOUT_MS`) or plugin config (`gatewayUrl`, `apiKey`).

## 0.3.1 - 2026-04-21
### Fixed
- `exec` tool: when the shell command is a `curl` invocation, the plugin now parses the curl
  flags (`-X METHOD`, `-H`, `-d`/`--data`/`--data-raw`) to extract the real URL/method/body
  before sending the scan request. Previously these calls were classified as `custom_proxy`
  against `exec://localhost` so tool-specific policies (Slack/GitHub/GDrive) did not fire.

## 0.3.2 - 2026-04-22
### Added
- `approvalWaitSec` config option (default 180s). On REQUIRE_APPROVAL the plugin now polls
  Interven's new `/v1/approvals/:id/status` endpoint and completes the tool call in the same
  conversation turn once the analyst decides. No manual retry needed. Set to 0 for the
  legacy v0.3.1 hard-block behavior.

### Required gateway version
- Requires gateway version that exposes `GET /v1/approvals/:id/status` (Interven gateway
  deployed 2026-04-22 or later).
