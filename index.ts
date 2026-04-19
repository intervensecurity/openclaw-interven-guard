/**
 * openclaw-interven-guard — before_tool_call → Interven POST /v1/scan
 *
 * Configuration (all via openclaw.json plugin config):
 *   plugins.entries["openclaw-interven-guard"].config.{
 *     gatewayUrl:     string  (optional, default "https://api.intervensecurity.com")
 *     apiKey:         string  (REQUIRED for enforcement; without it the plugin fails open)
 *     guardedTools:   string[] (optional, default ["web_fetch","exec","web_search","browser","message"])
 *     scanTimeoutMs:  number  (optional, default 15000, min 3000)
 *   }
 *
 * Notes for security scanners: this plugin intentionally performs outbound
 * fetch to the configured Interven gateway only. It does NOT read environment
 * variables, child_process, the filesystem, or any credential store.
 * All configuration is sourced exclusively from api.pluginConfig.
 *
 * Logging: console.log only (do not use api.logger here).
 */
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";

const DEFAULT_GUARDED_TOOLS = ["web_fetch", "exec", "web_search", "browser", "message"];
const VALID_TOOLS = new Set(["web_fetch", "exec", "web_search", "browser", "message"]);
const DEFAULT_GATEWAY = "https://api.intervensecurity.com";
const DEFAULT_SCAN_TIMEOUT_MS = 15000;
const MIN_SCAN_TIMEOUT_MS = 3000;

type ScanBody = {
  method: string;
  url: string;
  headers?: Record<string, string>;
  body: unknown;
  runtime_type?: string;
};

type ScanResponse = {
  decision?: string;
  reason_codes?: string[];
  sanitized_body?: unknown;
  trace_id?: string;
  risk_score?: number;
  risk_band?: string;
};

function pickString(obj: Record<string, unknown>, keys: string[]): string | undefined {
  for (const k of keys) {
    const v = obj[k];
    const s = coerceToTrimmedString(v);
    if (s) return s;
  }
  return undefined;
}

/** OpenClaw may pass URL objects or non-strings for tool params — never call string methods on raw values. */
function coerceToTrimmedString(v: unknown): string | undefined {
  if (typeof v === "string") {
    const t = v.trim();
    return t.length ? t : undefined;
  }
  if (v && typeof v === "object") {
    if (v instanceof URL) return v.href;
    const href = (v as { href?: unknown }).href;
    if (typeof href === "string" && href.trim()) return href.trim();
  }
  if (typeof v === "number" && Number.isFinite(v)) return String(v);
  return undefined;
}

function normalizeToolParams(raw: unknown): Record<string, unknown> {
  if (raw && typeof raw === "object" && !Array.isArray(raw)) {
    return raw as Record<string, unknown>;
  }
  return {};
}

/** Hook / UI code may call .startsWith on block reasons — always return a real string. */
function safeHookString(value: unknown, fallback: string): string {
  if (typeof value === "string") return value.length ? value : fallback;
  if (value == null) return fallback;
  try {
    const s = String(value);
    return s.length ? s : fallback;
  } catch {
    return fallback;
  }
}

function formatReasonCodes(rc: unknown): string {
  if (Array.isArray(rc)) {
    return rc
      .map((x) => {
        if (typeof x === "string") return x;
        try {
          return JSON.stringify(x);
        } catch {
          return String(x);
        }
      })
      .join(", ");
  }
  if (rc == null) return "";
  if (typeof rc === "string") return rc;
  try {
    return JSON.stringify(rc);
  } catch {
    return String(rc);
  }
}

function deepGet(obj: unknown, path: string[]): unknown {
  let cur: unknown = obj;
  for (const p of path) {
    if (cur === null || typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[p];
  }
  return cur;
}

function normalizeToolName(raw: string): string {
  return raw.trim().toLowerCase().replace(/-/g, "_");
}

function resolveGatewayUrl(api: { pluginConfig?: Record<string, unknown> }): string {
  const fromConfig = api.pluginConfig?.gatewayUrl;
  if (typeof fromConfig === "string" && fromConfig.trim()) return fromConfig.trim().replace(/\/$/, "");
  return DEFAULT_GATEWAY.replace(/\/$/, "");
}

function resolveApiKey(api: { pluginConfig?: Record<string, unknown> }): string | undefined {
  const fromConfig = api.pluginConfig?.apiKey;
  if (typeof fromConfig === "string" && fromConfig.trim()) return fromConfig.trim();
  return undefined;
}

function resolveScanTimeoutMs(api: { pluginConfig?: Record<string, unknown> }): number {
  const raw = api.pluginConfig?.scanTimeoutMs;
  let n: number;
  if (typeof raw === "number" && Number.isFinite(raw)) {
    n = raw;
  } else if (typeof raw === "string") {
    const parsed = Number.parseInt(raw, 10);
    n = Number.isFinite(parsed) ? parsed : DEFAULT_SCAN_TIMEOUT_MS;
  } else {
    n = DEFAULT_SCAN_TIMEOUT_MS;
  }
  return Math.max(MIN_SCAN_TIMEOUT_MS, n);
}

/**
 * Resolve the set of guarded tools.
 * Source: pluginConfig.guardedTools (array or comma-separated string).
 * Unknown names are dropped silently. Empty result falls back to defaults.
 */
function resolveGuardedTools(api: { pluginConfig?: Record<string, unknown> }): Set<string> {
  const fromConfig = api.pluginConfig?.guardedTools;
  let raw: string[] | null = null;
  if (Array.isArray(fromConfig)) {
    raw = fromConfig.filter((x): x is string => typeof x === "string");
  } else if (typeof fromConfig === "string") {
    raw = fromConfig.split(",");
  }
  if (!raw) return new Set(DEFAULT_GUARDED_TOOLS);
  const cleaned = raw
    .map((s) => s.trim().toLowerCase())
    .filter((s) => s.length && VALID_TOOLS.has(s));
  return cleaned.length ? new Set(cleaned) : new Set(DEFAULT_GUARDED_TOOLS);
}

function buildScanPayload(
  toolName: string,
  params: Record<string, unknown>,
  api: { config?: unknown }
): ScanBody | null {
  const rt = "openclaw";

  switch (toolName) {
    case "web_fetch": {
      // Typical shape: { url: string, extractMode?: string } (OpenClaw web_fetch)
      const url = pickString(params, ["url", "href", "target", "targetUrl", "address"]);
      if (!url) return null;
      const extractMode = coerceToTrimmedString(params.extractMode);
      const body: Record<string, unknown> = {};
      if (extractMode) body.extractMode = extractMode;
      return { method: "GET", url, body: Object.keys(body).length ? body : {}, runtime_type: rt };
    }
    case "exec": {
      const command = pickString(params, ["command", "cmd", "shell", "line"]);
      if (!command) return null;
      return {
        method: "POST",
        url: "exec://localhost",
        body: { command },
        runtime_type: rt,
      };
    }
    case "web_search": {
      const query = pickString(params, ["query", "q", "search", "text"]);
      if (!query) return null;
      const providerRaw = deepGet(api.config, ["tools", "web", "search", "provider"]);
      const provider = typeof providerRaw === "string" && providerRaw.trim() ? providerRaw.trim() : "unknown";
      return {
        method: "GET",
        url: `search://${encodeURIComponent(provider)}`,
        body: { query },
        runtime_type: rt,
      };
    }
    case "browser": {
      const url = pickString(params, ["url", "href", "targetUrl", "address", "target"]);
      if (!url) return null;
      return { method: "GET", url, body: {}, runtime_type: rt };
    }
    case "message": {
      const channel =
        pickString(params, ["channel", "channelId", "to", "destination", "recipient"]) ?? "unknown";
      const text =
        pickString(params, ["text", "message", "content", "body", "caption"]) ??
        (params.text != null ? String(params.text) : "");
      return {
        method: "POST",
        url: `message://${encodeURIComponent(channel)}`,
        body: { text },
        runtime_type: rt,
      };
    }
    default:
      return null;
  }
}

async function postScan(
  baseUrl: string,
  apiKey: string,
  body: ScanBody,
  timeoutMs: number
): Promise<ScanResponse | null> {
  const url = `${baseUrl}/v1/scan`;
  let res: Response;
  try {
    res = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (err) {
    console.log(`[interven-guard] Interven unreachable or scan timed out (${timeoutMs}ms) — fail open: ${String(err)}`);
    return null;
  }

  let data: ScanResponse;
  try {
    data = (await res.json()) as ScanResponse;
  } catch {
    console.log(`[interven-guard] Bad JSON from Interven (status=${res.status}) — fail open`);
    return null;
  }

  if (!res.ok) {
    console.log(`[interven-guard] Interven HTTP ${res.status} — fail open`, data);
    return null;
  }

  return data;
}

function mapDecision(data: ScanResponse | null): Record<string, unknown> | void {
  if (!data || !data.decision) {
    return;
  }

  const decision = String(data.decision).toUpperCase();
  const codes = formatReasonCodes(data.reason_codes);
  const traceId = safeHookString(data.trace_id, "");
  const trace = traceId ? ` trace_id=${traceId}` : "";

  if (decision === "ALLOW") {
    return;
  }

  if (decision === "DENY") {
    return {
      block: true,
      blockReason: safeHookString(
        `[Interven] DENY${codes ? `: ${codes}` : ""}${trace}`,
        "[Interven] DENY"
      ),
    };
  }

  if (decision === "SANITIZE") {
    let sanitizedSnippet = "";
    try {
      sanitizedSnippet = JSON.stringify(data.sanitized_body);
    } catch {
      sanitizedSnippet = safeHookString(data.sanitized_body, "");
    }
    sanitizedSnippet = safeHookString(sanitizedSnippet, "");
    if (sanitizedSnippet.length > 800) {
      sanitizedSnippet = `${sanitizedSnippet.slice(0, 800)}…`;
    }
    return {
      block: true,
      blockReason: safeHookString(
        `[Interven] SANITIZE blocked (v1). Sanitized: ${sanitizedSnippet}${trace}`,
        "[Interven] SANITIZE blocked"
      ),
    };
  }

  if (decision === "REQUIRE_APPROVAL") {
    // PAM-style: Interven is the authoritative approver, not the OpenClaw operator.
    // We HARD BLOCK the tool here. The security analyst approves in the Interven Console
    // (https://app.intervensecurity.com/approvals/<id>); the agent then RETRIES the same
    // tool call and the gateway short-circuits to ALLOW (RECENT_APPROVAL_GRANT). This is
    // the right primitive for an AI firewall: operator approval ≠ security policy approval.
    const approvalId = safeHookString(data?.approval_id, "");
    const consoleUrl = approvalId
      ? `https://app.intervensecurity.com/approvals/${approvalId}`
      : "https://app.intervensecurity.com/approvals";
    const reasonClause = codes ? ` Reason: ${codes}.` : "";
    return {
      block: true,
      blockReason: safeHookString(
        `🛡️ [Interven] Blocked pending security review.${reasonClause}` +
          ` Approve at ${consoleUrl}` +
          (approvalId ? ` (id: ${approvalId})` : "") +
          `. Once approved, ask me to retry the same action and it will proceed.${trace}`,
        "[Interven] Blocked pending security review"
      ),
    };
  }

  console.log(`[interven-guard] Unknown decision — fail open: ${String(data.decision)}`);
  return;
}

export default definePluginEntry({
  id: "openclaw-interven-guard",
  name: "Interven Guard",
  description: "Scan selected tool calls via Interven /v1/scan before execution.",
  register(api) {
    if (api.registrationMode !== "full") {
      return;
    }

    const guardedTools = resolveGuardedTools(api);
    const scanTimeoutMs = resolveScanTimeoutMs(api);
    console.log(
      `[interven-guard] guarding tools: ${Array.from(guardedTools).sort().join(", ")} (timeout=${scanTimeoutMs}ms)`
    );

    // Typed lifecycle hook — NOT registerHook (that API is for internal HOOK.md-style events only).
    // Logging: use console only — OpenClaw's api.logger is string-first; Pino-style args crash formatting.
    api.on("before_tool_call", async (event, _ctx) => {
      const rawName = event.toolName;
      const toolName = typeof rawName === "string" ? normalizeToolName(rawName) : "";
      if (!toolName || !guardedTools.has(toolName)) {
        return;
      }

      const params = normalizeToolParams(event.params);

      const scanBody = buildScanPayload(toolName, params, api);
      if (!scanBody) {
        console.log(`[interven-guard] Could not derive scan payload for ${toolName} — fail open`);
        return;
      }

      const apiKey = resolveApiKey(api);
      if (!apiKey) {
        console.log(
          "[interven-guard] apiKey missing in plugin config — skipping scan (fail open). " +
            "Set plugins.entries['openclaw-interven-guard'].config.apiKey in openclaw.json."
        );
        return;
      }

      const gateway = resolveGatewayUrl(api);
      const data = await postScan(gateway, apiKey, scanBody, scanTimeoutMs);
      const decision = data?.decision != null ? String(data.decision).toUpperCase() : "NONE";
      console.log(`[interven-guard] ${toolName} -> ${scanBody.url} -> ${decision}`);

      return mapDecision(data);
    });
  },
});
