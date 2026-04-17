/**
 * Approval engine — per-session dangerous-command approval state + FIFO queue.
 *
 * 1:1 port of Hermes Agent's `tools/approval.py` approval machinery
 * (`_session_approved`, `_session_yolo`, `_permanent_approved`, `_pending`,
 * `_gateway_queues`, `_ApprovalEntry`, `promptDangerousApproval`,
 * `resolveGatewayApproval`, `approveSession`, etc.) translated to the
 * Node/TypeScript event-loop model.
 *
 * Translation notes (Python → Node):
 *   - Hermes runs agent turns on executor threads and uses
 *     `threading.Event` to block a thread until `/approve` or `/deny`
 *     resolves it. Node is single-threaded with an event loop, so we use
 *     a Promise + external resolver (the moral equivalent of an Event).
 *   - No `threading.Lock` needed: every method is synchronous w.r.t. the
 *     event loop, so atomicity is guaranteed between `await` points.
 *   - `contextvars.ContextVar` is unused here — callers pass `sessionKey`
 *     explicitly, as the rest of MetaBot already does.
 *
 * This module is **stateful but UI-less**. The Feishu card wiring lands in
 * Phase 3 via the `NotifyCallback` hook. Permanent-approval persistence
 * lands in Phase 5 via the `permanentStore` constructor option.
 *
 * Source: https://github.com/NousResearch/hermes-agent/blob/main/tools/approval.py
 */

/** The four user choices, identical to Hermes. */
export type ApprovalChoice = 'once' | 'session' | 'always' | 'deny';

/** Data delivered to the notify callback so it can render a prompt. */
export interface ApprovalRequest {
  /** The raw command string the agent wants to run. */
  command: string;
  /** Human description of the matched dangerous pattern. */
  description: string;
  /** Canonical approval key (same as Hermes `pattern_key` — the description). */
  patternKey: string;
}

/**
 * Callback the gateway (Phase 3 Feishu integration) registers so the engine
 * can push approval prompts to the user. May be async (its returned Promise
 * is awaited and its rejection handled). `approvalId` lets the UI correlate
 * button clicks back to `resolveById`.
 */
export type NotifyCallback = (
  approvalId: string,
  req: ApprovalRequest,
) => void | Promise<void>;

/** Optional persistence hook for permanent approvals (wired in Phase 5). */
export interface PermanentStore {
  load(): Promise<string[]> | string[];
  save(keys: string[]): Promise<void> | void;
}

/** Optional error sink — logger hook for persistence + async notify failures. */
export type ErrorLogger = (message: string, err: unknown) => void;

export interface ApprovalStoreOptions {
  permanentStore?: PermanentStore;
  /** Optional logger used when the notify cb rejects or persistence save fails. */
  onError?: ErrorLogger;
  /**
   * Optional millisecond timeout. If a prompted approval isn't resolved
   * within this window, it is auto-resolved as `'deny'` (fail-closed).
   * Mirrors Hermes's `gateway_timeout` wait-loop. Default: no timeout.
   */
  timeoutMs?: number;
}

/**
 * Fallback logger: write to stderr. Overridable via `ApprovalStoreOptions.onError`
 * so tests (and future bridge integration with pino) can capture errors instead.
 */
const defaultLogger: ErrorLogger = (message, err) => {
  // stderr fallback; production call sites pass a pino-backed logger via options.
  console.error(`[approval-store] ${message}`, err);
};

interface PendingEntry {
  id: string;
  sessionKey: string;
  request: ApprovalRequest;
  resolve: (choice: ApprovalChoice) => void;
  createdAt: number;
  /** Set to true once resolved; guards against late notify fires & timeouts. */
  settled: boolean;
  /** Set if a timeout is armed — cleared on resolution. */
  timeoutHandle?: ReturnType<typeof setTimeout>;
  /**
   * Optional per-entry settlement observer. Invoked for every resolution path
   * (user click via `resolveById`, text command via `resolveNext`, timeout,
   * `unregisterNotify`). Consumers that need to react to out-of-band
   * settlements (e.g. the bridge updating a stale pending card to its
   * resolved state) register a callback via `onSettle(approvalId, cb)`.
   */
  onSettle?: (choice: ApprovalChoice) => void;
}

export class ApprovalStore {
  private readonly permanentStore?: PermanentStore;
  private readonly onError: ErrorLogger;
  private readonly timeoutMs?: number;
  // -----------------------------------------------------------------------
  // Per-session state
  // -----------------------------------------------------------------------

  /** session_key → set of approved pattern keys (Hermes `_session_approved`). */
  private readonly sessionApproved = new Map<string, Set<string>>();

  /** session_keys that are in YOLO mode (Hermes `_session_yolo`). */
  private readonly sessionYolo = new Set<string>();

  /** Globally-approved pattern keys (Hermes `_permanent_approved`). */
  private readonly permanentApproved = new Set<string>();

  // -----------------------------------------------------------------------
  // FIFO approval queue
  // -----------------------------------------------------------------------

  /** session_key → ordered list of pending entries (Hermes `_gateway_queues`). */
  private readonly queues = new Map<string, PendingEntry[]>();

  /** approvalId → entry, for direct resolve-by-id (used by button callbacks). */
  private readonly byId = new Map<string, PendingEntry>();

  /** session_key → notify callback (Hermes `_gateway_notify_cbs`). */
  private readonly notifyCbs = new Map<string, NotifyCallback>();

  private nextId = 1;

  /**
   * Two-arg form kept for backwards compatibility with the early Phase 2
   * draft; the one-arg options form is preferred.
   */
  constructor(options?: ApprovalStoreOptions | PermanentStore) {
    if (options && typeof (options as PermanentStore).load === 'function') {
      // Legacy single-arg PermanentStore.
      this.permanentStore = options as PermanentStore;
      this.onError = defaultLogger;
    } else {
      const opts = (options as ApprovalStoreOptions | undefined) ?? {};
      this.permanentStore = opts.permanentStore;
      this.onError = opts.onError ?? defaultLogger;
      this.timeoutMs = opts.timeoutMs;
    }
  }

  // -----------------------------------------------------------------------
  // Persistence
  // -----------------------------------------------------------------------

  /** Load permanent approvals from the persistence hook (Phase 5). */
  async loadPermanent(): Promise<void> {
    if (!this.permanentStore) return;
    const keys = await this.permanentStore.load();
    this.permanentApproved.clear();
    for (const k of keys) this.permanentApproved.add(k);
  }

  private async savePermanent(): Promise<void> {
    if (!this.permanentStore) return;
    try {
      await this.permanentStore.save([...this.permanentApproved]);
    } catch (err) {
      this.onError('failed to persist permanent approvals', err);
    }
  }

  // -----------------------------------------------------------------------
  // Approval-state queries (fast-path before prompting)
  // -----------------------------------------------------------------------

  /**
   * Should this command be auto-approved without prompting?
   *
   * Mirrors Hermes's pre-prompt checks: YOLO session, session allowlist,
   * permanent allowlist.
   */
  isPreApproved(sessionKey: string, patternKey: string): boolean {
    if (this.sessionYolo.has(sessionKey)) return true;
    if (this.permanentApproved.has(patternKey)) return true;
    const sessionSet = this.sessionApproved.get(sessionKey);
    return sessionSet?.has(patternKey) ?? false;
  }

  // -----------------------------------------------------------------------
  // Notify-callback registration (Phase 3 wiring)
  // -----------------------------------------------------------------------

  registerNotify(sessionKey: string, cb: NotifyCallback): void {
    this.notifyCbs.set(sessionKey, cb);
  }

  /**
   * Unregister the notify callback AND resolve every pending approval as
   * `'deny'` so waiting callers don't hang forever when the session ends.
   * Mirrors Hermes `unregister_gateway_notify` semantics, but defaults to
   * deny (safer than Hermes's `event.set()` with undefined `result`).
   */
  unregisterNotify(sessionKey: string): void {
    this.notifyCbs.delete(sessionKey);
    const queue = this.queues.get(sessionKey);
    if (!queue) return;
    for (const entry of queue) {
      this.byId.delete(entry.id);
      entry.resolve('deny');
    }
    this.queues.delete(sessionKey);
  }

  // -----------------------------------------------------------------------
  // Core: prompt the user and block until answered
  // -----------------------------------------------------------------------

  /**
   * Block (via Promise) until the user resolves this approval request.
   *
   * Enqueues a pending entry, fires the session's notify callback so the UI
   * surfaces the prompt, and returns a Promise that resolves to the user's
   * choice. FIFO is preserved — `resolveNext` pops the oldest entry.
   *
   * If no notify callback is registered, the Promise resolves to `'deny'`
   * immediately (fail-closed — safer than hanging forever).
   */
  promptApproval(sessionKey: string, request: ApprovalRequest): Promise<ApprovalChoice> {
    // Fast-path pre-approval (caller should check first, but double-check here).
    if (this.isPreApproved(sessionKey, request.patternKey)) {
      return Promise.resolve('once');
    }

    const cb = this.notifyCbs.get(sessionKey);
    if (!cb) {
      // No UI registered for this session — fail closed.
      return Promise.resolve('deny');
    }

    return new Promise<ApprovalChoice>((resolve) => {
      const id = `appr_${this.nextId++}_${Date.now().toString(36)}`;
      const entry: PendingEntry = {
        id,
        sessionKey,
        request,
        resolve: (choice) => {
          if (entry.settled) return;
          entry.settled = true;
          if (entry.timeoutHandle) clearTimeout(entry.timeoutHandle);
          this.byId.delete(id);
          // Fire the per-entry observer (if any) before resolving the outer
          // Promise, so UI-layer state (e.g. the bridge's resolved card)
          // settles in lockstep with the agent's view. Observer errors must
          // not block the caller's Promise.
          const observer = entry.onSettle;
          if (observer) {
            try { observer(choice); } catch (err) {
              this.onError('onSettle observer threw', err);
            }
          }
          resolve(choice);
        },
        createdAt: Date.now(),
        settled: false,
      };

      const queue = this.queues.get(sessionKey) ?? [];
      queue.push(entry);
      this.queues.set(sessionKey, queue);
      this.byId.set(id, entry);

      // Arm the fail-closed timeout (if configured) BEFORE we fire the cb,
      // so a UI that never comes back doesn't hang the agent forever.
      if (this.timeoutMs && this.timeoutMs > 0) {
        entry.timeoutHandle = setTimeout(() => {
          if (entry.settled) return;
          this.onError('approval timeout — auto-denying', {
            approvalId: id,
            sessionKey,
            command: request.command,
            timeoutMs: this.timeoutMs,
          });
          this.resolveById(id, 'deny');
        }, this.timeoutMs);
        // Don't keep the Node process alive solely for this timer.
        if (typeof entry.timeoutHandle === 'object' && 'unref' in entry.timeoutHandle) {
          (entry.timeoutHandle as { unref(): void }).unref();
        }
      }

      // Notify asynchronously so the caller gets its Promise first. Guard
      // against (a) the entry being settled between now and the microtask
      // (e.g. unregisterNotify denied it) and (b) async-rejection from cb.
      queueMicrotask(() => {
        if (entry.settled) return;
        try {
          const ret = cb(id, request);
          if (ret && typeof (ret as Promise<void>).then === 'function') {
            Promise.resolve(ret).catch((err) => {
              this.onError('notify cb rejected', err);
              this.resolveById(id, 'deny');
            });
          }
        } catch (err) {
          this.onError('notify cb threw', err);
          this.resolveById(id, 'deny');
        }
      });
    });
  }

  // -----------------------------------------------------------------------
  // Resolution API (driven by UI buttons / text commands)
  // -----------------------------------------------------------------------

  /**
   * Resolve a specific pending approval by id. Returns true if the id was
   * found and resolved, false otherwise. Idempotent — a second call on the
   * same id is a no-op.
   *
   * Also records the approval in session/permanent allowlists when choice
   * warrants it.
   */
  resolveById(approvalId: string, choice: ApprovalChoice): boolean {
    const entry = this.byId.get(approvalId);
    if (!entry) return false;
    this.applyChoice(entry, choice);

    // Remove from the session's FIFO queue.
    const queue = this.queues.get(entry.sessionKey);
    if (queue) {
      const idx = queue.indexOf(entry);
      if (idx >= 0) queue.splice(idx, 1);
      if (queue.length === 0) this.queues.delete(entry.sessionKey);
    }

    entry.resolve(choice);
    return true;
  }

  /**
   * Resolve the oldest pending approval for a session (FIFO).
   * Mirrors Hermes `resolve_gateway_approval(session_key, choice)`.
   *
   * Returns the number of entries resolved (0 or 1).
   */
  resolveNext(sessionKey: string, choice: ApprovalChoice): number {
    const queue = this.queues.get(sessionKey);
    if (!queue || queue.length === 0) return 0;
    const entry = queue.shift()!;
    if (queue.length === 0) this.queues.delete(sessionKey);
    this.byId.delete(entry.id);
    this.applyChoice(entry, choice);
    entry.resolve(choice);
    return 1;
  }

  /**
   * Resolve every pending approval for a session with the same choice.
   * Mirrors Hermes `resolve_gateway_approval(session_key, choice, resolve_all=True)`.
   */
  resolveAll(sessionKey: string, choice: ApprovalChoice): number {
    const queue = this.queues.get(sessionKey);
    if (!queue || queue.length === 0) return 0;
    const entries = queue.splice(0);
    this.queues.delete(sessionKey);
    for (const entry of entries) {
      this.byId.delete(entry.id);
      this.applyChoice(entry, choice);
      entry.resolve(choice);
    }
    return entries.length;
  }

  /**
   * Register a settlement observer for a specific pending approval. The
   * callback runs on every resolution path — button click, text command,
   * timeout, `unregisterNotify`. Returns `true` if the entry was found and
   * the observer attached, `false` if the id is unknown (already settled
   * or never existed).
   *
   * The bridge uses this to update the pending Feishu card to a
   * green/red resolved state whenever the underlying approval settles, so
   * the UI never shows orange after the agent has moved on.
   */
  onSettle(approvalId: string, cb: (choice: ApprovalChoice) => void): boolean {
    const entry = this.byId.get(approvalId);
    if (!entry || entry.settled) return false;
    entry.onSettle = cb;
    return true;
  }

  /**
   * Persist the side-effects of a choice into session/permanent state.
   * `'once'` and `'deny'` have no persisted side-effects — they bind only
   * this single request.
   */
  private applyChoice(entry: PendingEntry, choice: ApprovalChoice): void {
    if (choice === 'session') {
      this.approveForSession(entry.sessionKey, entry.request.patternKey);
    } else if (choice === 'always') {
      this.approvePermanent(entry.request.patternKey);
    }
  }

  // -----------------------------------------------------------------------
  // Explicit allowlist mutators (exposed for /approve-style text commands)
  // -----------------------------------------------------------------------

  approveForSession(sessionKey: string, patternKey: string): void {
    let set = this.sessionApproved.get(sessionKey);
    if (!set) {
      set = new Set();
      this.sessionApproved.set(sessionKey, set);
    }
    set.add(patternKey);
  }

  approvePermanent(patternKey: string): void {
    this.permanentApproved.add(patternKey);
    // Fire-and-forget persistence — errors bubble to caller via unhandled rejection.
    void this.savePermanent();
  }

  revokePermanent(patternKey: string): boolean {
    const removed = this.permanentApproved.delete(patternKey);
    if (removed) void this.savePermanent();
    return removed;
  }

  /**
   * Wipe all per-session state: approvals, YOLO mode, and any pending
   * approvals (resolved as `'deny'`). Mirrors Hermes `clear_session`.
   */
  clearSession(sessionKey: string): void {
    this.sessionApproved.delete(sessionKey);
    this.sessionYolo.delete(sessionKey);
    const queue = this.queues.get(sessionKey);
    if (queue) {
      for (const entry of queue) {
        this.byId.delete(entry.id);
        entry.resolve('deny');
      }
      this.queues.delete(sessionKey);
    }
  }

  setYolo(sessionKey: string, enabled: boolean): void {
    if (enabled) this.sessionYolo.add(sessionKey);
    else this.sessionYolo.delete(sessionKey);
  }

  isYolo(sessionKey: string): boolean {
    return this.sessionYolo.has(sessionKey);
  }

  // -----------------------------------------------------------------------
  // Introspection (for /approvals debug command, tests)
  // -----------------------------------------------------------------------

  getSessionApprovals(sessionKey: string): string[] {
    return [...(this.sessionApproved.get(sessionKey) ?? [])];
  }

  getPermanentApprovals(): string[] {
    return [...this.permanentApproved];
  }

  getPendingCount(sessionKey: string): number {
    return this.queues.get(sessionKey)?.length ?? 0;
  }

  hasPending(sessionKey: string): boolean {
    return this.getPendingCount(sessionKey) > 0;
  }
}

/**
 * Process-wide singleton, matching Hermes's module-level state. Tests that
 * need isolation should instantiate `new ApprovalStore()` directly rather
 * than using this export.
 */
export const approvalStore = new ApprovalStore();
