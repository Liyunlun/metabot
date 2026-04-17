/**
 * Approval handler factory — the per-task decision tree that gates dangerous
 * Bash commands before they reach the shell.
 *
 * Factored out of `MessageBridge` so Phase 4's smart-approval logic can be
 * exercised without spinning up a live Feishu sender. The factory returns a
 * `(command) => Promise<'allow' | 'deny'>` closure that the Claude executor
 * plugs into its `PreToolUse(Bash)` hook.
 *
 * Decision tree (checked in order, short-circuits on first hit):
 *   1. detectDangerousCommand(command)
 *        ↳ no match → 'allow'  (audit path: 'not_flagged')
 *   2. isHardBlacklisted(normalizedCommand)           ← **before allowlist**:
 *        ↳ hit → jump to (5)    (audit path: 'hard_blacklist_prompted')
 *                 Hard blacklist is non-overridable — neither session/permanent
 *                 allowlist nor YOLO can bypass it. This preserves the Phase 4
 *                 guarantee that catastrophic commands always reach a human.
 *   3. approvalStore.isPreApproved(chatId, patternKey)
 *        ↳ hit → 'allow'        (audit path: 'allowlist_hit')
 *   4. smartApproval.classify(...)
 *        ↳ 'approve'  → 'allow' (audit path: 'smart_approved')
 *        ↳ 'deny'     → 'deny'  (audit path: 'smart_denied')
 *        ↳ 'escalate' → fall through to (5)
 *   5. approvalStore.promptApproval(chatId, {...})  — Phase 3 card
 *        ↳ choice === 'deny' → 'deny'  (audit path: 'user_denied')
 *        ↳ otherwise         → 'allow' (audit path: 'user_approved')
 *
 * Every terminal leaf emits exactly one `approval_decision` audit entry so
 * downstream analysis (pattern-set tuning, false-positive detection) has a
 * single source of truth.
 */

import {
  detectDangerousCommand,
  normalizeCommandForDetection,
} from './dangerous-patterns.js';
import { isHardBlacklisted } from './hard-blacklist.js';
import type { ApprovalStore } from './approval-store.js';
import type {
  SmartApprovalClassifier,
  SmartApprovalResult,
} from './smart-approval.js';

/** Subset of `AuditLogger` we depend on — lets tests inject a spy. */
export interface ApprovalAuditSink {
  log(entry: {
    event: 'approval_decision';
    botName: string;
    chatId: string;
    meta?: Record<string, unknown>;
  }): void;
}

/** Minimal logger contract (pino-compatible). */
export interface Logger {
  info: (obj: object, msg?: string) => void;
  warn: (obj: object, msg?: string) => void;
  error: (obj: object, msg?: string) => void;
}

/**
 * The classifier interface the handler actually calls. Narrowed to the single
 * method used so tests can inject a plain object without constructing the
 * full `SmartApprovalClassifier`.
 */
export type ClassifierLike = Pick<SmartApprovalClassifier, 'classify'>;

export interface CreateApprovalHandlerDeps {
  /**
   * Store-side session key — namespaced `${botName}\x00${chatId}` (see
   * `buildSessionKey`). Codex R4 M1: splitting this from `chatId` keeps
   * two bots sharing a chat-id from cross-contaminating approval state.
   * When omitted, `chatId` is used as the session key — that degrades back
   * to pre-M1 single-bot semantics and is appropriate for tests that only
   * construct one bot per store instance.
   */
  sessionKey?: string;
  /** Raw chat id, kept separate so audit entries and user-facing text stay stable. */
  chatId: string;
  /** Working directory surfaced to the smart classifier as disambiguation context. */
  cwd: string;
  /** Bot name for audit entries. */
  botName: string;
  /**
   * Phase 2 approval store. Required — even if the approval bridge is
   * unavailable on this platform, isPreApproved / YOLO checks still work.
   */
  approvalStore: ApprovalStore;
  /**
   * Phase 4 classifier. Optional — when omitted (or when its config has
   * `enabled: false`), step 4 is skipped and flagged commands go straight
   * to the card.
   */
  smartApproval?: ClassifierLike;
  /**
   * When `false`, the handler skips the Phase 3 card and returns `'deny'`
   * for any flagged command that wasn't pre-approved / smart-approved.
   * This is the `approvalBridge === undefined` fallback path used by
   * platforms without raw-card support.
   */
  cardPromptAvailable: boolean;
  /** Structured audit sink — one entry per terminal decision. */
  audit: ApprovalAuditSink;
  /** Diagnostic logger (non-audit). */
  logger: Logger;
}

export type ApprovalHandler = (command: string) => Promise<'allow' | 'deny'>;

/**
 * Build a per-task approval handler. Pure factory — holds no mutable state of
 * its own; all state lives in the injected `approvalStore` / `smartApproval`.
 */
export function createApprovalHandler(deps: CreateApprovalHandlerDeps): ApprovalHandler {
  const {
    chatId,
    cwd,
    botName,
    approvalStore,
    smartApproval,
    cardPromptAvailable,
    audit,
    logger,
  } = deps;
  const sessionKey = deps.sessionKey ?? chatId;

  /**
   * Terminal audit emitter — one entry per resolved decision with a concrete
   * 'allow'/'deny' verdict. Downstream dashboards can safely aggregate by
   * `verdict` on entries with `phase: 'terminal'`.
   */
  const emitTerminal = (
    path: ApprovalDecisionPath,
    verdict: 'allow' | 'deny',
    command: string,
    extra?: Record<string, unknown>,
  ): void => {
    audit.log({
      event: 'approval_decision',
      botName,
      chatId,
      meta: {
        path,
        phase: 'terminal',
        verdict,
        command: command.slice(0, 200),
        ...extra,
      },
    });
  };

  /**
   * Non-terminal "prompt raised" marker — fired when a card is shown, before
   * the user responds. Carries NO `verdict` field on purpose so aggregators
   * can filter `phase === 'terminal'` when computing allow/deny rates. Pairs
   * 1:1 with a later `user_approved` / `user_denied` terminal entry once the
   * card settles (or times out to deny).
   */
  const emitPrompted = (
    path: 'escalated' | 'hard_blacklist_prompted',
    command: string,
    extra?: Record<string, unknown>,
  ): void => {
    audit.log({
      event: 'approval_decision',
      botName,
      chatId,
      meta: {
        path,
        phase: 'prompted',
        command: command.slice(0, 200),
        ...extra,
      },
    });
  };

  return async (command: string): Promise<'allow' | 'deny'> => {
    // Step 1 — is this even a flagged command?
    const detection = detectDangerousCommand(command);
    if (!detection.matched) {
      // No audit entry for the hot path — too noisy. We log only flagged
      // commands so audit volume stays bounded.
      return 'allow';
    }

    const patternKey = detection.patternKey;
    const description = detection.description;

    // Step 2 — hard blacklist runs BEFORE the allowlist/YOLO check. These
    // commands (rm -rf /, dd to raw block device, fork bomb, mkfs on /dev/*)
    // are always human-gated; a previous "session"/"always" approval of a
    // milder pattern (e.g. `rm -rf /tmp/foo` matches the same `patternKey`
    // "delete in root path" as `rm -rf /`) or YOLO mode must NOT open them.
    // Bypasses the LLM too — straight to step 5.
    const normalized = normalizeCommandForDetection(command);
    const hard = isHardBlacklisted(normalized);

    // Step 3 — session/permanent allowlist (or YOLO), only when NOT hard-
    // blacklisted. Hard blacklist is non-overridable by design.
    if (!hard.blacklisted && approvalStore.isPreApproved(sessionKey, patternKey)) {
      emitTerminal('allowlist_hit', 'allow', command, { patternKey });
      return 'allow';
    }

    // Step 4 — LLM classifier. Skipped when smartApproval is undefined, when
    // the command is hard-blacklisted, or when there's no card path available
    // to ESCALATE to (running classify just to escalate-then-deny is waste).
    let classifierResult: SmartApprovalResult | undefined;
    if (!hard.blacklisted && smartApproval) {
      try {
        classifierResult = await smartApproval.classify({
          command,
          description,
          cwd,
        });
      } catch (err) {
        // Should be impossible — classify() already wraps its failures into
        // an 'escalate' verdict. Defense-in-depth.
        logger.warn(
          { err: (err as Error)?.message, chatId, command: command.slice(0, 200) },
          'smart approval classify threw — escalating',
        );
      }

      if (classifierResult?.verdict === 'approve') {
        emitTerminal('smart_approved', 'allow', command, {
          patternKey,
          smartLatencyMs: classifierResult.latencyMs,
          smartReason: classifierResult.reason,
        });
        return 'allow';
      }
      if (classifierResult?.verdict === 'deny') {
        emitTerminal('smart_denied', 'deny', command, {
          patternKey,
          smartLatencyMs: classifierResult.latencyMs,
          smartReason: classifierResult.reason,
        });
        return 'deny';
      }
      // 'escalate' or undefined → fall through to step 5
    }

    // Step 5 — Phase 3 user card. If the card path isn't available on this
    // platform, fail closed.
    //
    // Scope (Codex R3 P1 — accepted as design):
    //   This branch fires for any sender without raw-card support (Telegram,
    //   raw API, CLI mode). Today the only sender with raw cards is Feishu,
    //   so platforms without it fail closed here for every flagged bash
    //   command that the classifier didn't auto-approve. Known consequence:
    //   Telegram can't run flagged commands (including hard-blacklisted ones
    //   that must reach a human) until a Telegram-compatible prompt surface
    //   lands.
    //   Decision: Feishu-only for this milestone. When Telegram support is
    //   added, give its sender a raw-card equivalent (inline keyboard with
    //   approve/deny buttons) and register it as a `CardSender` with the
    //   approval bridge — no change needed here.
    if (!cardPromptAvailable) {
      emitTerminal('no_card_denied', 'deny', command, {
        patternKey,
        hardBlacklisted: hard.blacklisted,
        hardReason: hard.reason,
        smartReason: classifierResult?.reason,
      });
      return 'deny';
    }

    // Non-terminal "prompted" breadcrumb — fires BEFORE the user answers so
    // that if the card times out or the session ends the audit trail still
    // reflects that a prompt was raised. Carries `phase: 'prompted'` and no
    // `verdict` field; the terminal `user_*` entry below carries the verdict.
    emitPrompted(hard.blacklisted ? 'hard_blacklist_prompted' : 'escalated', command, {
      patternKey,
      hardBlacklisted: hard.blacklisted,
      hardReason: hard.reason,
      smartLatencyMs: classifierResult?.latencyMs,
      smartReason: classifierResult?.reason,
    });

    // `bypassAllowlist` kicks in for hard-blacklisted commands so the card
    // is actually shown even if a session/permanent approval exists for the
    // shared `patternKey` (e.g. prior approval of `rm -rf /tmp/foo` must not
    // silently auto-allow `rm -rf /`). The handler already checked allowlist
    // above for the non-blacklisted branch.
    const choice = await approvalStore.promptApproval(
      sessionKey,
      { command, description, patternKey },
      hard.blacklisted ? { bypassAllowlist: true } : undefined,
    );
    const verdict: 'allow' | 'deny' = choice === 'deny' ? 'deny' : 'allow';
    emitTerminal(verdict === 'deny' ? 'user_denied' : 'user_approved', verdict, command, {
      patternKey,
      choice,
    });
    return verdict;
  };
}

/**
 * Every terminal (and the prompted-marker) audit path. Kept as a string union
 * both for compile-time spell-check and so downstream dashboards can enumerate
 * the full set.
 */
export type ApprovalDecisionPath =
  | 'allowlist_hit'
  | 'hard_blacklist_prompted'
  | 'smart_approved'
  | 'smart_denied'
  | 'escalated'
  | 'user_approved'
  | 'user_denied'
  | 'no_card_denied';
