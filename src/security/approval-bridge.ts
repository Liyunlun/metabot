/**
 * Bridge between `ApprovalStore` and the Feishu message sender.
 *
 * Responsibilities:
 *   - On `ApprovalStore.promptApproval`, send a pending card and remember
 *     the `(approvalId → messageId)` mapping.
 *   - On button click / `/approve` / `/deny` / timeout, update the pending
 *     card to the resolved green/red state.
 *   - Offer a small façade (`handleButtonClick`, `resolveText`, `attachToTask`)
 *     that `MessageBridge` can use without needing to know the store's API.
 *
 * The module is intentionally **decoupled from the Feishu SDK** — it depends
 * on a `CardSender` interface, which `message-bridge` wires up using its
 * existing `MessageSender`. This keeps the file testable with a plain mock.
 */

import { ApprovalStore, type ApprovalChoice, type ApprovalRequest } from './approval-store.js';
import {
  APPROVAL_BUTTON_KIND,
  buildPendingApprovalCard,
  buildResolvedApprovalCard,
} from './approval-card.js';

/**
 * Minimal card-sender surface. Matches the subset of `IMessageSender`
 * (`sendRawCard` / `updateRawCard`) used for approval UI — implemented by
 * `FeishuSenderAdapter` and any other platform that supports raw cards.
 */
export interface CardSender {
  sendCard(chatId: string, cardContent: string): Promise<string | undefined>;
  updateCard(messageId: string, cardContent: string): Promise<boolean>;
}

/** Structured error logger — pino's `.error(obj, msg)` shape is compatible. */
export interface Logger {
  info(obj: Record<string, unknown>, msg?: string): void;
  warn(obj: Record<string, unknown>, msg?: string): void;
  error(obj: Record<string, unknown>, msg?: string): void;
}

/**
 * Payload shape of the button's `value` field. `MessageBridge.handleCardAction`
 * decodes this once it sees `kind === APPROVAL_BUTTON_KIND`.
 */
export interface ApprovalButtonValue {
  kind: typeof APPROVAL_BUTTON_KIND;
  approvalId: string;
  choice: ApprovalChoice;
}

interface InflightApproval {
  chatId: string;
  messageId?: string;
  request: ApprovalRequest;
  resolved: boolean;
  /**
   * Set when a resolution (button click, text command, auto-settle) fires
   * BEFORE `sendCard()` has returned a `messageId`. Without this, the
   * resolved-card update would be dropped because we don't yet know which
   * message to edit, and the pending orange card would stay visible forever
   * once the send eventually lands. When `sendCard().then()` finally sets
   * `messageId`, it consumes this to apply the resolved render.
   *
   * Codex R3 P2: "card send resolves late → resolved result dropped".
   */
  pendingResolution?: {
    choice: ApprovalChoice;
    operator?: string;
    autoResolved: boolean;
  };
}

export class ApprovalBridge {
  /** approvalId → inflight state (so button clicks can find the card messageId). */
  private readonly inflight = new Map<string, InflightApproval>();

  constructor(
    private readonly store: ApprovalStore,
    private readonly sender: CardSender,
    private readonly logger: Logger,
  ) {}

  /**
   * Bind this bridge to a chat session. The returned `detach()` cleans up the
   * notify callback and denies any pending approvals so the Promise layer
   * doesn't leak. Call this at task start, call the returned fn at task end.
   */
  attachToSession(chatId: string): () => void {
    this.store.registerNotify(chatId, (approvalId, request) => {
      const entry: InflightApproval = { chatId, request, resolved: false };
      this.inflight.set(approvalId, entry);

      // Attach a settlement observer so out-of-band resolutions (timeout,
      // `unregisterNotify` on detach, or any store-internal path) also
      // refresh the Feishu card. Button clicks and text commands go
      // through `this.resolve()` which sets `entry.resolved = true` before
      // calling `store.resolveById`, so this observer no-ops for those —
      // avoiding a double card update.
      this.store.onSettle(approvalId, (choice) => {
        this.handleAutoSettle(approvalId, choice);
      });

      const card = buildPendingApprovalCard({ approvalId, request });
      // sendCard is async — we do NOT await it in the notify cb (the cb is
      // sync-ish). If the send fails, we surface via onError and auto-deny
      // so the agent doesn't wait on a message the user will never see.
      //
      // Race handling: the approval can resolve (user clicks fast, text
      // `/approve`, timeout, detach) BEFORE sendCard returns. When that
      // happens, `resolve()` / `handleAutoSettle()` stash a
      // `pendingResolution` on the inflight entry instead of deleting it.
      // Here we consume that stash to apply the resolved card render once
      // the messageId finally lands, so the user never sees a perpetually-
      // orange pending card for an already-settled approval.
      this.sender
        .sendCard(chatId, card)
        .then((messageId) => {
          const current = this.inflight.get(approvalId);
          if (!current) return;
          current.messageId = messageId;
          if (current.resolved && current.pendingResolution) {
            const { choice, operator, autoResolved } = current.pendingResolution;
            this.applyResolvedCard(approvalId, current, choice, operator, autoResolved);
            this.inflight.delete(approvalId);
          }
        })
        .catch((err) => {
          this.logger.error(
            { approvalId, chatId, err: (err as Error).message },
            'approval card send failed — auto-denying',
          );
          const current = this.inflight.get(approvalId);
          this.inflight.delete(approvalId);
          // Only drive a store-side deny if the entry wasn't already resolved
          // by the user path — otherwise we'd double-resolve (harmless but
          // noisy: `resolveById` returns false on the second call).
          if (!current?.resolved) {
            this.store.resolveById(approvalId, 'deny');
          }
        });
    });

    return () => {
      this.store.unregisterNotify(chatId);
      // Clean up inflight entries for this chat. Preserve entries whose
      // `sendCard()` is still in flight with a stashed `pendingResolution` —
      // the send's .then() is about to consume it to render the final card,
      // after which it self-deletes. Purging them here would re-introduce
      // the Codex R3 P2 bug for the detach-while-sending timing.
      for (const [id, entry] of this.inflight) {
        if (entry.chatId !== chatId) continue;
        const sendStillInFlight = !entry.messageId && entry.pendingResolution;
        if (!sendStillInFlight) this.inflight.delete(id);
      }
    };
  }

  /**
   * Handle a card button click. Returns `true` if the value belongs to this
   * bridge and was routed; `false` otherwise (so the caller can try the next
   * handler).
   */
  handleButtonClick(value: unknown, operator?: string): boolean {
    if (!isApprovalValue(value)) return false;
    this.resolve(value.approvalId, value.choice, operator, false);
    return true;
  }

  /**
   * Handle `/approve` / `/deny` text commands. Resolves the oldest pending
   * approval in the given session. Returns the number of approvals resolved.
   */
  resolveNextByText(chatId: string, choice: ApprovalChoice, operator?: string): number {
    // Find the oldest inflight for this chat.
    const entry = [...this.inflight.entries()].find(
      ([, e]) => e.chatId === chatId && !e.resolved,
    );
    if (!entry) return 0;
    this.resolve(entry[0], choice, operator, false);
    return 1;
  }

  // -----------------------------------------------------------------------
  // Internal
  // -----------------------------------------------------------------------

  /**
   * Handle a settlement that did NOT originate from a user button/text
   * action — i.e. store-driven resolution (timeout) or bridge-driven teardown
   * (`unregisterNotify` inside detach). If the inflight entry is still
   * unresolved, we render the resolved card marked `autoResolved: true` so
   * the operator can see the reason.
   */
  private handleAutoSettle(approvalId: string, choice: ApprovalChoice): void {
    const entry = this.inflight.get(approvalId);
    if (!entry || entry.resolved) return;
    entry.resolved = true;

    if (entry.messageId) {
      this.applyResolvedCard(approvalId, entry, choice, undefined, true);
      this.inflight.delete(approvalId);
    } else {
      // sendCard hasn't returned yet — stash so its .then() can finish the
      // render instead of dropping the resolution on the floor.
      entry.pendingResolution = { choice, autoResolved: true };
    }
  }

  private resolve(
    approvalId: string,
    choice: ApprovalChoice,
    operator: string | undefined,
    autoResolved: boolean,
  ): void {
    const entry = this.inflight.get(approvalId);
    if (!entry || entry.resolved) return;
    entry.resolved = true;

    const ok = this.store.resolveById(approvalId, choice);
    if (!ok) {
      // Store had already resolved this (timeout / clearSession) — still update UI.
      this.logger.warn(
        { approvalId, chatId: entry.chatId, choice },
        'approval resolveById returned false (already resolved upstream)',
      );
    }

    // Re-render the card in resolved state.
    if (entry.messageId) {
      this.applyResolvedCard(approvalId, entry, choice, operator, autoResolved);
      this.inflight.delete(approvalId);
    } else {
      // sendCard hasn't completed yet — stash the resolution so the send's
      // .then() can finish the render once the messageId lands. The
      // orange pending card would otherwise stay visible even after the
      // agent has moved on.
      entry.pendingResolution = { choice, operator, autoResolved };
    }
  }

  /**
   * Render the resolved card and push it via `updateCard`. Extracted so the
   * three resolution paths (button/text `resolve`, out-of-band
   * `handleAutoSettle`, late-send consumption of `pendingResolution`) share
   * the same update logic.
   */
  private applyResolvedCard(
    approvalId: string,
    entry: InflightApproval,
    choice: ApprovalChoice,
    operator: string | undefined,
    autoResolved: boolean,
  ): void {
    if (!entry.messageId) return;
    const card = buildResolvedApprovalCard({
      approvalId,
      request: entry.request,
      choice,
      operator,
      autoResolved,
    });
    this.sender.updateCard(entry.messageId, card).catch((err) => {
      this.logger.error(
        { approvalId, messageId: entry.messageId, err: (err as Error).message },
        'failed to update resolved approval card',
      );
    });
  }
}

/** Type guard for the button `value` payload. */
export function isApprovalValue(value: unknown): value is ApprovalButtonValue {
  if (!value || typeof value !== 'object') return false;
  const v = value as Record<string, unknown>;
  return (
    v.kind === APPROVAL_BUTTON_KIND &&
    typeof v.approvalId === 'string' &&
    typeof v.choice === 'string' &&
    ['once', 'session', 'always', 'deny'].includes(v.choice as string)
  );
}
