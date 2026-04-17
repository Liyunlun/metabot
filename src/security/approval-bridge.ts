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
      this.sender
        .sendCard(chatId, card)
        .then((messageId) => {
          const current = this.inflight.get(approvalId);
          if (!current || current.resolved) return;
          current.messageId = messageId;
        })
        .catch((err) => {
          this.logger.error(
            { approvalId, chatId, err: (err as Error).message },
            'approval card send failed — auto-denying',
          );
          this.inflight.delete(approvalId);
          this.store.resolveById(approvalId, 'deny');
        });
    });

    return () => {
      this.store.unregisterNotify(chatId);
      // Clean up any inflight entries for this chat to prevent unbounded growth.
      for (const [id, entry] of this.inflight) {
        if (entry.chatId === chatId) this.inflight.delete(id);
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
      const card = buildResolvedApprovalCard({
        approvalId,
        request: entry.request,
        choice,
        autoResolved: true,
      });
      this.sender.updateCard(entry.messageId, card).catch((err) => {
        this.logger.error(
          { approvalId, messageId: entry.messageId, err: (err as Error).message },
          'failed to update auto-resolved approval card',
        );
      });
    }
    this.inflight.delete(approvalId);
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

    // Re-render the card in resolved state. Skip if we never got a messageId
    // (sendCard hadn't completed by the time of resolution — rare).
    if (entry.messageId) {
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

    this.inflight.delete(approvalId);
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
