# Interven Guard for OpenClaw

Scan every outbound tool call your OpenClaw agent makes — **before** it executes — through the [Interven](https://intervensecurity.com) AI firewall. Block malicious URLs, redact PII and secrets, and route risky actions to human approval, without changing your agent code.

## What it guards

By default this plugin scans five built-in OpenClaw tools:

| Tool | Why scan it |
|------|-------------|
| `web_fetch` | The agent fetching attacker-controlled URLs, exfiltration sinks, or phishing pages |
| `exec` | Shell commands — code execution and data exfil via curl/wget/scp |
| `web_search` | Reconnaissance and prompt-injection feedback loops |
| `browser` | Browser automation hitting unvetted destinations |
| `message` | Outbound chat messages that may leak secrets, PII, or sensitive context |

You can narrow this set per-deployment (see [Configuration](#configuration)).

## Decisions

The plugin maps Interven's four decisions to OpenClaw hook results:

| Interven decision | OpenClaw result |
|-------------------|-----------------|
| `ALLOW` | Tool runs normally |
| `DENY` | `{ block: true, blockReason: "[Interven] DENY: <codes>" }` |
| `SANITIZE` | Blocked with sanitized payload preview in the reason |
| `REQUIRE_APPROVAL` | `{ requireApproval: { title, description, severity } }` — surfaces in OpenClaw's approval UI |

Network errors, timeouts, missing API keys, or non-200 responses **fail open** — your agent keeps working even if Interven is unreachable.

## Install

### Quick install (ClawHub — recommended)

```bash
openclaw plugins install clawhub:interven-guard
echo 'INTERVEN_API_KEY=iv_live_your_key_here' >> ~/.openclaw/.env
```

That's it. Get an API key at [intervensecurity.com](https://intervensecurity.com) (free tier: 1,000 scans/month).

### Manual install (development / self-hosted Interven)

```bash
git clone https://github.com/intervensecurity/openclaw-interven-guard.git
openclaw plugins install ./openclaw-interven-guard
```

Then add to `~/.openclaw/.env`:

```bash
INTERVEN_API_KEY=iv_live_your_key_here
# Optional — only if you self-host Interven instead of using the hosted SaaS
# INTERVEN_GATEWAY_URL=http://your-interven-host:4000
```

Restart the gateway:

```bash
openclaw gateway restart
```

Verify:

```bash
openclaw plugins list --verbose | grep interven-guard
openclaw plugins inspect openclaw-interven-guard
```

## Configuration

All fields are optional and have sensible defaults.

| Source | Field / variable | Default | Notes |
|--------|------------------|---------|-------|
| Env | `INTERVEN_API_KEY` | — | **Required** for enforcement. Without it, plugin fails open. |
| Env | `INTERVEN_GATEWAY_URL` | `https://api.intervensecurity.com` | Override only when self-hosting |
| Env | `INTERVEN_SCAN_TIMEOUT_MS` | `15000` | Per-scan timeout. Min 3000. On timeout → fail open. |
| Env | `INTERVEN_GUARDED_TOOLS` | `web_fetch,exec,web_search,browser,message` | Comma-separated. Set to `web_fetch` only to scan outbound HTTP fetches. |
| `openclaw.json` | `plugins.entries["openclaw-interven-guard"].config.gatewayUrl` | — | Overrides env |
| `openclaw.json` | `plugins.entries["openclaw-interven-guard"].config.apiKey` | — | Overrides env (prefer env on shared hosts) |
| `openclaw.json` | `plugins.entries["openclaw-interven-guard"].config.guardedTools` | — | Array; overrides env |

### Example `openclaw.json` snippet

```json5
{
  plugins: {
    allow: ["openclaw-interven-guard"],
    entries: {
      "openclaw-interven-guard": {
        enabled: true,
        config: {
          // Only scan outbound HTTP fetches (lighter, recommended for chat agents)
          guardedTools: ["web_fetch"]
        }
      }
    }
  }
}
```

## Tuning OpenClaw so the model actually calls tools

Small models (e.g. `gpt-4o-mini`) can skip tool calls when the system prompt is bloated with skills. If your agent answers "I can't access that URL" instead of calling `web_fetch`, trim the prompt:

```json5
{
  tools: { profile: "coding" },          // includes web_fetch, drops messaging surface
  skills: {
    allowBundled: false,
    limits: { maxSkillsPromptChars: 4000 }
  },
  agents: {
    list: [{
      id: "main",
      skills: [],                        // explicit empty: no skill text injected
      model: { primary: "openai/gpt-4o-mini" }
    }]
  }
}
```

Verified config keys (OpenClaw v2026.4.x): `skills.allowBundled` (bool, default `true`), `skills.limits.maxSkillsPromptChars` (default 18000), `agents.list[].skills` (`[]` = none), `tools.profile` ∈ `minimal | coding | messaging | full`.

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `hook registration missing name` | You're using `api.registerHook(...)` somewhere. Use `api.on("before_tool_call", …)` only. |
| `TypeError: message.startsWith is not a function` | Pino-style `log.warn({err}, "msg")` somewhere. Use `console.log` only. |
| Plugin install rejected: "dangerous code patterns" | You're installing an unsigned local copy. Either install from ClawHub (`clawhub:interven-guard`) or use `--dangerously-force-unsafe-install` for dev only. |
| Hook never fires | Confirm OpenClaw ≥ `2026.3.13`. Run `openclaw plugins doctor`. Check the model is actually calling the tool (see "Tuning" above). |
| Clean URLs returning `REQUIRE_APPROVAL` | Agent's Interven trust score has degraded after repeated denies. Reset via dashboard or — for self-hosted — `UPDATE agent_trust_state SET trust_score=1.0, scrutiny_until=NULL WHERE agent_id='<your-uuid>'`. |
| `Could not derive scan payload for <tool>` | Tool params shape changed. File an issue with the OpenClaw version and tool name. |

## How it works

```
┌──────────────┐   tool call    ┌──────────────────┐    /v1/scan    ┌──────────┐
│ OpenClaw     │ ─────────────▶ │ before_tool_call │ ─────────────▶ │ Interven │
│ agent        │                │ hook (this)      │ ◀───────────── │ gateway  │
└──────────────┘ ◀───────────── └──────────────────┘  decision      └──────────┘
                  block / allow         │
                  / requireApproval     │ console.log
                                        ▼
                                   stdout / journal
```

Every guarded tool call is intercepted, sent to Interven's `/v1/scan` endpoint with the URL, method, and body, and the response decision is mapped back to OpenClaw's hook return shape. Interven runs 14 detection engines (PII, secrets, threat intel, semantic intent, trust scoring, etc.) and returns a decision in ~80ms p50.

## License

[MIT](./LICENSE) © Interven Security

## Links

- [Interven docs](https://intervensecurity.com/docs)
- [Interven API reference](https://intervensecurity.com/docs/api)
- [Get an API key](https://intervensecurity.com/signup)
- [Source / issues](https://github.com/intervensecurity/openclaw-interven-guard)
