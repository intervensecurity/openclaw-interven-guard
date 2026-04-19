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
| `REQUIRE_APPROVAL` | **Hard block** with a message pointing the operator to the Interven Console. The security analyst approves there; the operator retries; the gateway short-circuits to `ALLOW` via the recent approval grant. |

Network errors, timeouts, missing API keys, or non-200 responses **fail open** — your agent keeps working even if Interven is unreachable.

### Why we hard-block instead of asking the operator

Interven is an **AI firewall**, not an operator-decision aid. Letting the operator (whose account could be compromised, who could be careless, or who just isn't the security team) approve their own risky actions makes Interven a logging tool, not a security control. v0.3.0 implements the two-actor PAM pattern used by BeyondTrust / CyberArk / Teleport: the agent operator requests, a separate security analyst approves. The operator retries after the analyst decides; the gateway recognises the recent approval and lets the second attempt through.

## Install

### Step 1 — Install the plugin

```bash
openclaw plugins install clawhub:openclaw-interven-guard
```

### Step 2 — Configure your API key in `~/.openclaw/openclaw.json`

The API key is set in plugin config (the plugin does **not** read environment variables — see [Security model](#security-model) below). Add this block to your `openclaw.json`:

```json5
{
  plugins: {
    allow: ["openclaw-interven-guard"],
    entries: {
      "openclaw-interven-guard": {
        enabled: true,
        config: {
          apiKey: "iv_live_your_key_here"
        }
      }
    }
  }
}
```

Get an API key at [intervensecurity.com](https://intervensecurity.com) (free tier: 1,000 scans/month).

> **Tip:** `chmod 600 ~/.openclaw/openclaw.json` to keep the API key readable only by your user. If you check `openclaw.json` into git, use a config-templating tool (envsubst, sops, dotenvx) to substitute the key at deploy time — never commit the literal `iv_live_*` value.

### Step 3 — Restart the gateway

```bash
openclaw gateway restart
```

### Verify

```bash
openclaw plugins list --verbose | grep interven-guard
openclaw plugins inspect openclaw-interven-guard
journalctl --user -u openclaw-gateway.service -f | grep interven-guard
```

You should see `[interven-guard] guarding tools: ...` in the gateway logs on startup.

### Manual install (development / self-hosted Interven)

```bash
git clone https://github.com/intervensecurity/openclaw-interven-guard.git
openclaw plugins install ./openclaw-interven-guard
```

Then configure as in Step 2 above. To point at a self-hosted Interven instead of the SaaS, add `gatewayUrl`:

```json5
"openclaw-interven-guard": {
  enabled: true,
  config: {
    apiKey: "iv_live_your_key_here",
    gatewayUrl: "http://your-interven-host:4000"
  }
}
```

## Configuration

All config lives under `plugins.entries["openclaw-interven-guard"].config` in `~/.openclaw/openclaw.json`. The plugin reads **no** environment variables.

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `apiKey` | string | — | **Required** for enforcement. Format `iv_live_*`. Without it, plugin fails open. |
| `gatewayUrl` | string | `https://api.intervensecurity.com` | Override only when self-hosting Interven |
| `guardedTools` | string[] | `["web_fetch","exec","web_search","browser","message"]` | Set to `["web_fetch"]` to only scan outbound HTTP fetches |
| `scanTimeoutMs` | integer | `15000` | Per-scan timeout (min 3000). On timeout → fail open. |

### Example `openclaw.json` snippet (recommended for chat agents)

```json5
{
  plugins: {
    allow: ["openclaw-interven-guard"],
    entries: {
      "openclaw-interven-guard": {
        enabled: true,
        config: {
          apiKey: "iv_live_your_key_here",
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

## Security model

This plugin sits in your agent's outbound path and intentionally:

- **Reads from `api.pluginConfig` only.** No `process.env`, no `child_process`, no filesystem reads, no credential stores. The API key reaches the plugin exclusively through OpenClaw's typed plugin-config surface.
- **Sends outbound HTTP to one host only** — the `gatewayUrl` you set (default `https://api.intervensecurity.com`). The destination is fixed at config time; the plugin cannot redirect traffic elsewhere at runtime.
- **Sends only the tool-call metadata** that's necessary for policy evaluation: HTTP method, URL, body, optional headers. It does not send your agent's conversation history, system prompts, memory, or any other workspace data.
- **Logs to `console.log` only**, never to disk, and never includes the API key in any log line.

If you're auditing this plugin before installing it on a sensitive agent, the entire data flow is in [`index.ts`](./index.ts) — ~360 lines, no dependencies beyond OpenClaw's plugin SDK and Node 20+ built-in `fetch`.

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `hook registration missing name` | You're using `api.registerHook(...)` somewhere. Use `api.on("before_tool_call", …)` only. |
| `TypeError: message.startsWith is not a function` | Pino-style `log.warn({err}, "msg")` somewhere. Use `console.log` only. |
| Plugin install rejected: "dangerous code patterns" | You're installing an unsigned local copy. Either install from ClawHub (`clawhub:openclaw-interven-guard`) or use `--dangerously-force-unsafe-install` for dev only. |
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
