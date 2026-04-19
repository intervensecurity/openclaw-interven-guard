# Changelog

All notable changes to `openclaw-interven-guard` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Semantic Versioning](https://semver.org/).

## [0.2.0] — 2026-04-19

### Added
- Configurable guarded tools via `INTERVEN_GUARDED_TOOLS` env var or `guardedTools` plugin config (array). Lets operators narrow scanning to e.g. just `web_fetch` without forking the plugin.
- `guardedTools` field documented in `openclaw.plugin.json` configSchema.
- LICENSE file (MIT) and CHANGELOG.md for ClawHub publishing.

### Changed
- Default gateway URL is now `https://api.intervensecurity.com` (was `http://100.80.251.3:4000` lab IP). Override with `INTERVEN_GATEWAY_URL` for self-hosted Interven.
- `package.json` hardened for ClawHub publish: license, repository, homepage, keywords, files allowlist, engines.

## [0.1.0] — 2026-04-15

### Added
- Initial release. `before_tool_call` hook scans `web_fetch`, `exec`, `web_search`, `browser`, `message` through Interven `POST /v1/scan`.
- Decisions: `ALLOW` passes through, `DENY` blocks with reason codes, `SANITIZE` blocks with sanitized payload preview, `REQUIRE_APPROVAL` returns OpenClaw approval object.
- Fail-open on network error, timeout, missing API key, bad JSON, or non-200 response.
- Configurable via env vars (`INTERVEN_GATEWAY_URL`, `INTERVEN_API_KEY`, `INTERVEN_SCAN_TIMEOUT_MS`) or plugin config (`gatewayUrl`, `apiKey`).
