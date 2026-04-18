/**
 * Smart Approval — LLM pre-filter for dangerous commands.
 *
 * Ported 1:1 from NousResearch/hermes-agent `tools/approval.py::_smart_approve()`
 * with one MetaBot addition: a `Working directory: {cwd}` line in the user
 * prompt (Sonnet uses it as a disambiguation signal — same command in
 * `/tmp/sandbox` vs `/home/user/prod` has different risk).
 *
 * Call path: caller (approval-handler) decides a command should be
 * classified → `classify({command, description, cwd})` → returns verdict.
 * Any failure (timeout, exception, unparseable response) produces
 * `'escalate'`, which the handler then routes to the Phase 3 user card.
 *
 * Transport: uses `@anthropic-ai/claude-agent-sdk`'s `query()` — same entry
 * point as `ClaudeExecutor`. This goes through the user's Claude Code
 * subscription (OAuth, `~/.claude/.credentials.json`), NOT the Anthropic API
 * with credits. The classifier query is configured to be inert:
 *   - `maxTurns: 1` (single response, no tool-using loop)
 *   - `allowedTools: []` (classifier cannot execute anything)
 *   - `permissionMode: 'bypassPermissions'` + `allowDangerouslySkipPermissions: true`
 *     (no nested PreToolUse recursion — we're already inside one)
 *   - `hooks` omitted (same reason)
 *   - `systemPrompt: ''` — explicit empty string. Per `sdk.d.ts` line 1372,
 *     `systemPrompt?: string | { type: 'preset', ... }`. Passing `''` uses a
 *     custom prompt that happens to be empty; it does NOT auto-fall-back to
 *     the Claude Code preset (that requires `{type:'preset',preset:'claude_code'}`
 *     explicitly). This keeps the classifier prompt-only, matching Hermes.
 *   - `settingSources` omitted → no filesystem settings/CLAUDE.md/hooks are
 *     loaded into the nested session (sdk.d.ts line 1326).
 */

import { query } from '@anthropic-ai/claude-agent-sdk';
import type { SDKMessage } from '@anthropic-ai/claude-agent-sdk';
import type { CommandExplanation } from './approval-store.js';

export type { CommandExplanation };

export type SmartVerdict = 'approve' | 'deny' | 'escalate';

export interface SmartApprovalConfig {
  /** When false, `classify()` short-circuits to `'escalate'` (card flow). */
  enabled: boolean;
  /**
   * Upper bound on wall-clock time for a single classification. If the
   * underlying `query()` hasn't produced a usable verdict within this window
   * we abort and return `'escalate'`. Default 5000 ms.
   *
   * This sits on the HOT PATH — every flagged command (even benign ones
   * later auto-approved) blocks on this — so it's intentionally short.
   */
  timeoutMs: number;
  /**
   * Separate, longer timeout for `explain()`. Explain only runs on
   * commands that are definitely going to a user card (hard-blacklist
   * path), so the operator is already waiting on a Feishu message anyway;
   * trading a few extra seconds of latency for a populated explanation is
   * worth it. Defaults to 15000 ms when omitted.
   *
   * Structured-JSON generation with Chinese summary + risks array
   * empirically takes 6–12 seconds on Sonnet, so the 5 s classify budget
   * is too tight — measured at 4.3 s even for a bare verdict word.
   */
  explainTimeoutMs?: number;
}

export interface SmartApprovalRequest {
  command: string;
  description: string;
  cwd: string;
}

export interface SmartApprovalResult {
  verdict: SmartVerdict;
  /** Short human-readable reason (for audit logs). */
  reason: string;
  /** Wall-clock latency of the classify() call. */
  latencyMs: number;
  /** Raw response text (truncated), useful for debugging; omitted on timeout. */
  raw?: string;
  /**
   * LLM-generated explanation for the approval card. Populated when the
   * classifier returned parseable JSON including the explanation fields;
   * absent when the model responded with a bare verdict word or when
   * parsing failed. Consumers render it only if present.
   */
  explanation?: CommandExplanation;
}

/** Minimal logger contract — matches pino's `info/warn/error(obj, msg)` shape. */
export interface Logger {
  info: (obj: object, msg?: string) => void;
  warn: (obj: object, msg?: string) => void;
  error: (obj: object, msg?: string) => void;
}

/**
 * Build the classifier prompt. Exported for testing; callers should use
 * `classify()` which wires this into the SDK.
 *
 * Prompt is Hermes `tools/approval.py:552-564` with two MetaBot additions:
 *   1. `Working directory: {cwd}` line — disambiguation signal.
 *   2. Structured JSON output with `verdict` + operator-facing explanation
 *      fields (`summary`, `risks`, `reversible`) — the card uses these to
 *      tell the user *what* the command does and *why* it's risky before
 *      they click. The parser falls back to a bare-word verdict when JSON
 *      parsing fails (any older model or malformed output stays safe).
 */
export function buildClassifierPrompt(req: SmartApprovalRequest): string {
  return [
    'You are a security reviewer for an AI coding agent. A terminal command was flagged by pattern matching as potentially dangerous.',
    '',
    `Command: ${req.command}`,
    `Flagged reason: ${req.description}`,
    `Working directory: ${req.cwd}`,
    '',
    'Assess the ACTUAL risk of this command. Many flagged commands are false positives — for example, `python -c "print(\'hello\')"` is flagged as "script execution via -c flag" but is completely harmless.',
    '',
    'Rules for "verdict" (valid values: APPROVE, DENY, or ESCALATE):',
    '- APPROVE if the command is clearly safe (benign script execution, safe file operations, development tools, package installs, git operations, etc.)',
    '- DENY if the command could genuinely damage the system (recursive delete of important paths, overwriting system files, fork bombs, wiping disks, dropping databases, etc.)',
    '- ESCALATE if you\'re uncertain',
    '',
    'Also produce a short operator-facing explanation so a human can decide quickly if they see a prompt. Respond with a single JSON object of exactly this shape:',
    '{',
    '  "verdict": "APPROVE" | "DENY" | "ESCALATE",',
    '  "summary": "<one-sentence Chinese description of what this command does>",',
    '  "risks": ["<specific risk in Chinese>", "..."],',
    '  "reversible": "yes" | "no" | "partial" | "unknown"',
    '}',
    '',
    'Rules for explanation fields:',
    '- "summary": plain, non-alarmist; describe the action, not the risk.',
    '- "risks": 0–3 concrete consequences (empty array if APPROVE).',
    '- "reversible": "yes" if a mistake is trivially undone, "no" if the effect is irreversible (deleted data, overwritten system files, dropped DB), "partial" if recoverable but costly, "unknown" if context-dependent.',
    '',
    'Output ONLY the JSON object, no surrounding prose.',
  ].join('\n');
}

/**
 * Build the explain-only prompt used for hard-blacklisted commands — those
 * always reach the user card regardless of verdict, so we skip the verdict
 * field and just ask for the operator-facing explanation. Saves a bit of
 * generation length and removes any risk of the LLM's verdict coloring the
 * card copy for commands we have already decided require human review.
 */
export function buildExplainPrompt(req: SmartApprovalRequest): string {
  return [
    'You are a security reviewer preparing an explanation for a human operator who must decide whether to allow a terminal command. The command has already been flagged and will be shown to the operator; do not recommend approval or denial — only describe the command and its risks.',
    '',
    `Command: ${req.command}`,
    `Flagged reason: ${req.description}`,
    `Working directory: ${req.cwd}`,
    '',
    'Respond with a single JSON object of exactly this shape:',
    '{',
    '  "summary": "<one-sentence Chinese description of what this command does>",',
    '  "risks": ["<specific risk in Chinese>", "..."],',
    '  "reversible": "yes" | "no" | "partial" | "unknown"',
    '}',
    '',
    'Rules:',
    '- "summary": plain, non-alarmist; describe the action, not the risk.',
    '- "risks": 1–3 concrete consequences.',
    '- "reversible": "yes" if trivially undone, "no" if irreversible, "partial" if recoverable but costly, "unknown" if context-dependent.',
    '',
    'Output ONLY the JSON object, no surrounding prose.',
  ].join('\n');
}

/**
 * Parse the classifier response. Hermes originally used naive
 * `'APPROVE' in upper` / `'DENY' in upper` substring tests, which fail-open
 * on mixed text like `"DENY — do not approve"` (both tokens present, first
 * check wins → 'approve'). We harden this by requiring a single
 * **unambiguous standalone token**: the response must contain exactly one of
 * { APPROVE, DENY, ESCALATE } as a whole word. Any other shape — empty,
 * ambiguous, multiple tokens, none of the three — fails safe to 'escalate'.
 */
export function parseVerdict(response: string): SmartVerdict {
  const upper = response.trim().toUpperCase();
  if (!upper) return 'escalate';

  // Word-boundary matches so "DISAPPROVE" doesn't trip APPROVE, and
  // "ANTIDENY" doesn't trip DENY. Count distinct tokens; ambiguity ⇒ escalate.
  const hasApprove = /\bAPPROVE\b/.test(upper);
  const hasDeny = /\bDENY\b/.test(upper);
  const hasEscalate = /\bESCALATE\b/.test(upper);

  const tokenCount = (hasApprove ? 1 : 0) + (hasDeny ? 1 : 0) + (hasEscalate ? 1 : 0);
  if (tokenCount !== 1) return 'escalate';

  if (hasApprove) return 'approve';
  if (hasDeny) return 'deny';
  return 'escalate';
}

/**
 * Extract a balanced `{ ... }` JSON object from the response text. Looks for
 * the outermost braces; tolerates surrounding prose (some models add stray
 * prefixes like "Here's my analysis:" despite the "Output ONLY the JSON"
 * instruction). Returns the raw JSON string or `undefined` if none found.
 */
function extractJsonObject(text: string): string | undefined {
  const start = text.indexOf('{');
  const end = text.lastIndexOf('}');
  if (start < 0 || end <= start) return undefined;
  return text.slice(start, end + 1);
}

/**
 * Coerce a raw JSON object into a `CommandExplanation`. Missing / malformed
 * fields produce sensible defaults (`unknown` reversibility, empty risks).
 * Returns `undefined` when there's literally nothing usable (no summary and
 * no risks) so callers can fall back to the non-explanation card layout.
 */
function coerceExplanation(obj: Record<string, unknown>): CommandExplanation | undefined {
  const summary = typeof obj.summary === 'string' ? obj.summary.trim() : '';
  const rawRisks = Array.isArray(obj.risks) ? obj.risks : [];
  const risks = rawRisks
    .filter((r): r is string => typeof r === 'string' && r.trim().length > 0)
    .map((r) => r.trim());
  const rev = obj.reversible;
  const reversible: CommandExplanation['reversible'] =
    rev === 'yes' || rev === 'no' || rev === 'partial' || rev === 'unknown'
      ? rev
      : 'unknown';
  if (!summary && risks.length === 0) return undefined;
  return { summary, risks, reversible };
}

/**
 * Parse a full classifier response (verdict + optional explanation).
 *
 * Prefers the JSON shape emitted by the current prompt; falls back to
 * `parseVerdict()` on plain-text responses so older-style canned responses
 * (bare `APPROVE`/`DENY`/`ESCALATE`) keep working. Any parse failure produces
 * `{verdict: 'escalate'}` with no explanation — the handler will then drive
 * the card with the legacy compact layout.
 */
export function parseClassifierResponse(
  response: string,
): { verdict: SmartVerdict; explanation?: CommandExplanation } {
  const trimmed = response.trim();
  if (!trimmed) return { verdict: 'escalate' };

  const jsonCandidate = extractJsonObject(trimmed);
  if (jsonCandidate) {
    try {
      const obj = JSON.parse(jsonCandidate) as Record<string, unknown>;
      const verdictRaw = typeof obj.verdict === 'string' ? obj.verdict : '';
      const verdict = parseVerdict(verdictRaw);
      const explanation = coerceExplanation(obj);
      return { verdict, explanation };
    } catch {
      // Fall through to plain-text parsing.
    }
  }
  return { verdict: parseVerdict(trimmed) };
}

/**
 * Parse an explanation-only response (used by `explain()` for the hard-
 * blacklist path). Returns `undefined` when no JSON object can be coerced.
 */
export function parseExplanationResponse(response: string): CommandExplanation | undefined {
  const trimmed = response.trim();
  if (!trimmed) return undefined;
  const jsonCandidate = extractJsonObject(trimmed);
  if (!jsonCandidate) return undefined;
  try {
    const obj = JSON.parse(jsonCandidate) as Record<string, unknown>;
    return coerceExplanation(obj);
  } catch {
    return undefined;
  }
}

/**
 * Injection seam used by tests to stub out the `query()` SDK call.
 * Production path simply wraps `query()` from the Agent SDK.
 */
export type QueryFn = (args: {
  prompt: string;
  model: string;
  abortController: AbortController;
}) => AsyncIterable<SDKMessage>;

/**
 * Scrub MetaBot-specific secrets out of the env before we hand it to the
 * nested classifier session. Defense-in-depth only — `allowedTools: []` and
 * `settingSources: []` already prevent the inner model from exercising any
 * tool/hook that could exfiltrate these vars. But the SDK defaults `env` to
 * `process.env` (sdk.d.ts line 2584), so if a future runtime change enables
 * an enterprise-managed hook the scrubbed env keeps our secrets out of it.
 *
 * We deny-list obvious secret prefixes rather than allow-listing, because
 * Claude Code OAuth needs a dynamic surface (HOME, PATH, XDG_*, LANG, …)
 * and an allow-list would make us brittle to SDK changes.
 */
const SECRET_ENV_DENYLIST = [
  // Prefixes — everything under these namespaces is MetaBot-specific.
  /^METABOT_/,
  /^FEISHU_/,
  /^TELEGRAM_/,
  /^WECHAT_/,
  /^MEMORY_/,
  /^VOLC_/,       // VOLC_ACCESS_KEY_ID, VOLC_SECRET_KEY, VOLC_RTC_APP_ID, VOLC_RTC_APP_KEY
  /^VOLCENGINE_/, // VOLCENGINE_TTS_APPID, VOLCENGINE_TTS_ACCESS_KEY
  // Anthropic credentials — force SDK to resolve OAuth coding-plan via the
  // credentials file rather than inheriting API credits from env.
  /^ANTHROPIC_API_KEY$/,
  /^ANTHROPIC_AUTH_TOKEN$/,
  // Generic secret suffixes. `_KEY` covers VOLC_RTC_APP_KEY, SSH_KEY, GPG_KEY
  // etc.; `_KEY_ID` covers VOLC_ACCESS_KEY_ID, AWS_ACCESS_KEY_ID; `_APPID`
  // covers VOLCENGINE_TTS_APPID.
  /_SECRET$/,
  /_TOKEN$/,
  /_PASSWORD$/,
  /_APIKEY$/,
  /_API_KEY$/,
  /_KEY$/,
  /_KEY_ID$/,
  /_APPID$/,
];

export function buildClassifierEnv(): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (v === undefined) continue;
    // Canonicalize to upper-case before matching. POSIX env names are
    // case-sensitive, but in practice secrets may arrive with any casing
    // (`openai_api_key`, `Feishu_App_Secret`, …) — especially from `.env`
    // files or shell exports. Uppercasing first means a single denylist
    // entry covers all casings.
    const canon = k.toUpperCase();
    if (SECRET_ENV_DENYLIST.some((re) => re.test(canon))) continue;
    out[k] = v;
  }
  return out;
}

const defaultQueryFn: QueryFn = ({ prompt, model, abortController }) =>
  query({
    prompt,
    options: {
      model,
      maxTurns: 1,
      allowedTools: [],
      // `settingSources: []` explicitly opts out of user/project/local
      // filesystem settings — no CLAUDE.md, no local hooks, no MCP
      // definitions leak into the classifier (sdk.d.ts line 1326).
      settingSources: [],
      permissionMode: 'bypassPermissions',
      // Required by the SDK when permissionMode is 'bypassPermissions'.
      // See sdk.d.ts:1193-1196.
      allowDangerouslySkipPermissions: true,
      // Explicit empty string — the SDK's `systemPrompt` accepts either a
      // custom string or a `{type:'preset'}` object (sdk.d.ts line 1372). An
      // empty string is a custom-prompt value that contributes nothing, which
      // is what Hermes's `_smart_approve()` does (single user message, no
      // system prompt). It does NOT auto-fall-back to the Claude Code preset.
      systemPrompt: '',
      // hooks intentionally omitted: this query runs from inside a
      // PreToolUse hook, and registering new hooks here would risk
      // recursive approval loops.
      // Scrubbed env — keeps MetaBot secrets out of the nested session even
      // if a future SDK change or enterprise-managed hook tries to read them.
      env: buildClassifierEnv(),
      abortController,
    } as Record<string, unknown>,
  }) as unknown as AsyncIterable<SDKMessage>;

export class SmartApprovalClassifier {
  constructor(
    private readonly cfg: SmartApprovalConfig,
    /**
     * Resolves the classifier model at call time. Pass
     * `() => config.claude.model` so operator `/model` switches propagate.
     */
    private readonly getModel: () => string | undefined,
    private readonly logger: Logger,
    /** Injected for testing; defaults to the real SDK `query()`. */
    private readonly queryFn: QueryFn = defaultQueryFn,
  ) {}

  async classify(req: SmartApprovalRequest): Promise<SmartApprovalResult> {
    const start = Date.now();

    if (!this.cfg.enabled) {
      return { verdict: 'escalate', reason: 'smart approval disabled', latencyMs: 0 };
    }

    const model = this.getModel();
    if (!model) {
      return { verdict: 'escalate', reason: 'no model configured', latencyMs: 0 };
    }

    const prompt = buildClassifierPrompt(req);
    const abortController = new AbortController();
    const timeoutHandle = setTimeout(() => abortController.abort(), this.cfg.timeoutMs);
    if (typeof timeoutHandle === 'object' && 'unref' in timeoutHandle) {
      (timeoutHandle as { unref(): void }).unref();
    }

    let text = '';
    try {
      for await (const msg of this.queryFn({ prompt, model, abortController })) {
        if (msg.type === 'assistant') {
          // BetaMessage.content is an array of blocks; concatenate text blocks
          // only. Tool_use / thinking blocks are ignored (shouldn't appear
          // with allowedTools: [] anyway).
          const content = (msg.message as { content?: unknown[] } | undefined)?.content;
          if (Array.isArray(content)) {
            for (const block of content) {
              const b = block as { type?: string; text?: string };
              if (b.type === 'text' && typeof b.text === 'string') text += b.text;
            }
          }
        }
        // Early-exit on `result` messages — we have our verdict, don't wait
        // for more (Hermes uses max_tokens=16; here maxTurns=1 enforces the
        // same by closing the stream after the first assistant turn).
        if (msg.type === 'result') break;
      }
    } catch (err) {
      // AbortError from the timeout, or any other SDK failure, falls through
      // to 'escalate' — smart approval is an accelerator, NOT a safety net.
      const timedOut = abortController.signal.aborted;
      this.logger.warn(
        {
          err: (err as Error)?.message,
          timedOut,
          latencyMs: Date.now() - start,
          command: req.command.slice(0, 200),
        },
        'smart approval classify failed — escalating',
      );
      clearTimeout(timeoutHandle);
      return {
        verdict: 'escalate',
        reason: timedOut ? 'classifier timeout' : 'classifier error',
        latencyMs: Date.now() - start,
      };
    }
    clearTimeout(timeoutHandle);

    const latencyMs = Date.now() - start;
    const trimmed = text.trim();
    if (!trimmed) {
      this.logger.warn(
        { latencyMs, command: req.command.slice(0, 200) },
        'smart approval returned empty response — escalating',
      );
      return { verdict: 'escalate', reason: 'empty response', latencyMs };
    }

    const { verdict, explanation } = parseClassifierResponse(trimmed);
    return {
      verdict,
      reason:
        verdict === 'escalate' && !/APPROVE|DENY|ESCALATE/i.test(trimmed)
          ? 'unrecognized response'
          : verdict,
      latencyMs,
      raw: trimmed.slice(0, 200),
      explanation,
    };
  }

  /**
   * Generate an operator-facing explanation without asking for a verdict.
   *
   * Used by the approval handler for hard-blacklisted commands, which are
   * always shown to a human regardless of classifier opinion — the verdict
   * is moot, but a short "what this does / why it's risky" blurb on the
   * card helps the operator decide faster. Best-effort: any failure
   * (timeout, parse error, disabled, missing model) returns `undefined`
   * and the card renders without the extra sections.
   */
  async explain(req: SmartApprovalRequest): Promise<CommandExplanation | undefined> {
    if (!this.cfg.enabled) return undefined;
    const model = this.getModel();
    if (!model) return undefined;

    const prompt = buildExplainPrompt(req);
    const abortController = new AbortController();
    // Explain uses its own (longer) budget: the card is already slated to
    // appear for hard-blacklisted commands, so it's fine to spend more wall
    // time to get a populated explanation than to race the fast-path
    // classify timeout and end up empty-handed.
    const explainTimeoutMs = this.cfg.explainTimeoutMs ?? 15000;
    const timeoutHandle = setTimeout(() => abortController.abort(), explainTimeoutMs);
    if (typeof timeoutHandle === 'object' && 'unref' in timeoutHandle) {
      (timeoutHandle as { unref(): void }).unref();
    }

    let text = '';
    try {
      for await (const msg of this.queryFn({ prompt, model, abortController })) {
        if (msg.type === 'assistant') {
          const content = (msg.message as { content?: unknown[] } | undefined)?.content;
          if (Array.isArray(content)) {
            for (const block of content) {
              const b = block as { type?: string; text?: string };
              if (b.type === 'text' && typeof b.text === 'string') text += b.text;
            }
          }
        }
        if (msg.type === 'result') break;
      }
    } catch (err) {
      const timedOut = abortController.signal.aborted;
      this.logger.warn(
        {
          err: (err as Error)?.message,
          timedOut,
          command: req.command.slice(0, 200),
        },
        'smart approval explain failed — proceeding without explanation',
      );
      clearTimeout(timeoutHandle);
      return undefined;
    }
    clearTimeout(timeoutHandle);

    return parseExplanationResponse(text);
  }
}
