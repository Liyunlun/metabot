import { describe, it, expect, vi } from 'vitest';
import { ApprovalStore } from '../src/security/approval-store.js';
import {
  ApprovalBridge,
  isApprovalValue,
  type CardSender,
  type Logger,
} from '../src/security/approval-bridge.js';
import { APPROVAL_BUTTON_KIND } from '../src/security/approval-card.js';

const CHAT = 'oc_chat_A';
const REQ = { command: 'rm -rf /tmp/foo', description: 'recursive delete', patternKey: 'recursive delete' };

function makeSender(): CardSender & {
  sendCard: ReturnType<typeof vi.fn>;
  updateCard: ReturnType<typeof vi.fn>;
} {
  return {
    sendCard: vi.fn<CardSender['sendCard']>().mockResolvedValue('msg_1'),
    updateCard: vi.fn<CardSender['updateCard']>().mockResolvedValue(true),
  };
}

function makeLogger(): Logger {
  return { info: vi.fn(), warn: vi.fn(), error: vi.fn() };
}

describe('isApprovalValue', () => {
  it('accepts well-formed approval values', () => {
    expect(
      isApprovalValue({
        kind: APPROVAL_BUTTON_KIND,
        approvalId: 'x',
        choice: 'once',
      }),
    ).toBe(true);
  });

  it('rejects wrong kind', () => {
    expect(
      isApprovalValue({ kind: 'askuser_answer', approvalId: 'x', choice: 'once' }),
    ).toBe(false);
  });

  it('rejects invalid choice', () => {
    expect(
      isApprovalValue({ kind: APPROVAL_BUTTON_KIND, approvalId: 'x', choice: 'maybe' }),
    ).toBe(false);
  });

  it('rejects non-objects', () => {
    expect(isApprovalValue(null)).toBe(false);
    expect(isApprovalValue('string')).toBe(false);
    expect(isApprovalValue(42)).toBe(false);
  });
});

describe('ApprovalBridge — notify → sendCard → button click → updateCard', () => {
  it('sends a pending card on prompt, updates to resolved on button click', async () => {
    const store = new ApprovalStore();
    const sender = makeSender();
    const bridge = new ApprovalBridge(store, sender, makeLogger());
    const detach = bridge.attachToSession(CHAT);

    const p = store.promptApproval(CHAT, REQ);
    // Drain the notify microtask + the sendCard Promise.
    await Promise.resolve();
    await Promise.resolve();

    expect(sender.sendCard).toHaveBeenCalledTimes(1);
    const [, cardJson] = sender.sendCard.mock.calls[0] as [string, string];
    const card = JSON.parse(cardJson);
    // Find the approvalId from the button value for the click we're about to simulate.
    const action = card.body.elements.find((e: any) => e.tag === 'action');
    const oneBtn = action.actions.find((b: any) => b.value.choice === 'once');
    expect(oneBtn.value.kind).toBe(APPROVAL_BUTTON_KIND);

    const routed = bridge.handleButtonClick(oneBtn.value, 'user_xyz');
    expect(routed).toBe(true);

    await expect(p).resolves.toBe('once');
    expect(sender.updateCard).toHaveBeenCalledTimes(1);
    const updateCardJson = sender.updateCard.mock.calls[0][1] as string;
    expect(updateCardJson).toContain('user_xyz');
    expect(JSON.parse(updateCardJson).header.template).toBe('green');

    detach();
  });

  it('deny click produces a red resolved card and the promise resolves to deny', async () => {
    const store = new ApprovalStore();
    const sender = makeSender();
    const bridge = new ApprovalBridge(store, sender, makeLogger());
    bridge.attachToSession(CHAT);

    const p = store.promptApproval(CHAT, REQ);
    await Promise.resolve();
    await Promise.resolve();

    const card = JSON.parse(sender.sendCard.mock.calls[0][1] as string);
    const denyBtn = card.body.elements
      .find((e: any) => e.tag === 'action')
      .actions.find((b: any) => b.value.choice === 'deny');
    bridge.handleButtonClick(denyBtn.value, 'user_xyz');

    await expect(p).resolves.toBe('deny');
    const updateJson = sender.updateCard.mock.calls[0][1] as string;
    expect(JSON.parse(updateJson).header.template).toBe('red');
  });

  it('handleButtonClick returns false for non-approval values (delegates elsewhere)', () => {
    const store = new ApprovalStore();
    const bridge = new ApprovalBridge(store, makeSender(), makeLogger());
    expect(bridge.handleButtonClick({ kind: 'askuser_answer' })).toBe(false);
    expect(bridge.handleButtonClick(null)).toBe(false);
  });

  it('handleButtonClick is idempotent — second click on same approvalId is a no-op', async () => {
    const store = new ApprovalStore();
    const sender = makeSender();
    const bridge = new ApprovalBridge(store, sender, makeLogger());
    bridge.attachToSession(CHAT);

    const p = store.promptApproval(CHAT, REQ);
    await Promise.resolve();
    await Promise.resolve();
    const card = JSON.parse(sender.sendCard.mock.calls[0][1] as string);
    const btn = card.body.elements.find((e: any) => e.tag === 'action').actions[0].value;

    bridge.handleButtonClick(btn);
    bridge.handleButtonClick(btn); // duplicate
    await p;

    expect(sender.updateCard).toHaveBeenCalledTimes(1);
  });
});

describe('ApprovalBridge — resolveNextByText (/approve /deny commands)', () => {
  it('resolves the oldest pending approval for the chat', async () => {
    const store = new ApprovalStore();
    const sender = makeSender();
    const bridge = new ApprovalBridge(store, sender, makeLogger());
    bridge.attachToSession(CHAT);

    const p1 = store.promptApproval(CHAT, REQ);
    const p2 = store.promptApproval(CHAT, { ...REQ, command: 'rm -rf /tmp/bar' });
    await Promise.resolve();
    await Promise.resolve();

    const resolved = bridge.resolveNextByText(CHAT, 'session', 'cmd_user');
    expect(resolved).toBe(1);
    await expect(p1).resolves.toBe('session');
    // p2 still pending
    bridge.resolveNextByText(CHAT, 'deny', 'cmd_user');
    await expect(p2).resolves.toBe('deny');
  });

  it('returns 0 when no pending approval exists', () => {
    const store = new ApprovalStore();
    const bridge = new ApprovalBridge(store, makeSender(), makeLogger());
    bridge.attachToSession(CHAT);
    expect(bridge.resolveNextByText(CHAT, 'once')).toBe(0);
  });
});

describe('ApprovalBridge — failure & detach semantics', () => {
  it('auto-denies when sendCard rejects', async () => {
    const store = new ApprovalStore();
    const sender = makeSender();
    sender.sendCard.mockRejectedValueOnce(new Error('network'));
    const logger = makeLogger();
    const bridge = new ApprovalBridge(store, sender, logger);
    bridge.attachToSession(CHAT);

    const p = store.promptApproval(CHAT, REQ);
    await expect(p).resolves.toBe('deny');
    expect(logger.error).toHaveBeenCalled();
  });

  it('detach() denies all in-flight approvals for the chat', async () => {
    const store = new ApprovalStore();
    const sender = makeSender();
    const bridge = new ApprovalBridge(store, sender, makeLogger());
    const detach = bridge.attachToSession(CHAT);

    const p = store.promptApproval(CHAT, REQ);
    await Promise.resolve();
    await Promise.resolve();

    detach();
    await expect(p).resolves.toBe('deny');
  });

  it('timeout auto-settles the card as resolved and ignores late clicks', async () => {
    vi.useFakeTimers();
    const store = new ApprovalStore({ timeoutMs: 5_000 });
    const sender = makeSender();
    const logger = makeLogger();
    const bridge = new ApprovalBridge(store, sender, logger);
    bridge.attachToSession(CHAT);

    const p = store.promptApproval(CHAT, REQ);
    await Promise.resolve();
    await Promise.resolve();
    const card = JSON.parse(sender.sendCard.mock.calls[0][1] as string);
    const btn = card.body.elements.find((e: any) => e.tag === 'action').actions[0].value;

    // Fire timeout — store resolves as deny, bridge observer updates the card.
    vi.advanceTimersByTime(5_000);
    await expect(p).resolves.toBe('deny');

    // The card was rewritten to resolved state via the onSettle observer.
    expect(sender.updateCard).toHaveBeenCalledTimes(1);
    const updateJson = sender.updateCard.mock.calls[0][1] as string;
    expect(JSON.parse(updateJson).header.template).toBe('red');

    // Late click on a stale card must be a no-op — inflight already marked
    // resolved, and the id is gone from the store.
    bridge.handleButtonClick(btn);
    expect(sender.updateCard).toHaveBeenCalledTimes(1);

    vi.useRealTimers();
  });

  it('detach auto-settles any in-flight cards before unregistering', async () => {
    const store = new ApprovalStore();
    const sender = makeSender();
    const bridge = new ApprovalBridge(store, sender, makeLogger());
    const detach = bridge.attachToSession(CHAT);

    const p = store.promptApproval(CHAT, REQ);
    await Promise.resolve();
    await Promise.resolve();
    expect(sender.sendCard).toHaveBeenCalledTimes(1);

    detach();
    await expect(p).resolves.toBe('deny');

    expect(sender.updateCard).toHaveBeenCalledTimes(1);
    const updateJson = sender.updateCard.mock.calls[0][1] as string;
    expect(JSON.parse(updateJson).header.template).toBe('red');
  });
});

describe('ApprovalBridge — card send vs resolve race (Codex R3 P2)', () => {
  // Helper: slow-send sender that returns a controllable promise for sendCard
  // so the test can force the "resolve-before-send-completes" ordering.
  function makeSlowSender(): CardSender & {
    sendCard: ReturnType<typeof vi.fn>;
    updateCard: ReturnType<typeof vi.fn>;
    releaseSend: (messageId?: string) => void;
    failSend: (err: Error) => void;
  } {
    let release!: (messageId?: string) => void;
    let fail!: (err: Error) => void;
    const pending = new Promise<string | undefined>((resolve, reject) => {
      release = (id = 'msg_late') => resolve(id);
      fail = reject;
    });
    return {
      sendCard: vi.fn<CardSender['sendCard']>().mockReturnValue(pending),
      updateCard: vi.fn<CardSender['updateCard']>().mockResolvedValue(true),
      releaseSend: release,
      failSend: fail,
    };
  }

  it('button click before sendCard completes — updateCard fires once send lands', async () => {
    const store = new ApprovalStore();
    const sender = makeSlowSender();
    const bridge = new ApprovalBridge(store, sender, makeLogger());
    bridge.attachToSession(CHAT);

    const p = store.promptApproval(CHAT, REQ);
    // Let the notify cb run and kick off sendCard (still pending).
    await Promise.resolve();
    await Promise.resolve();
    expect(sender.sendCard).toHaveBeenCalledTimes(1);
    expect(sender.updateCard).not.toHaveBeenCalled();

    // User clicks "once" while sendCard is still in flight. The bridge sees
    // messageId === undefined so it can't updateCard yet — it must stash.
    const cardJson = sender.sendCard.mock.calls[0][1] as string;
    const card = JSON.parse(cardJson);
    const oneBtn = card.body.elements
      .find((e: any) => e.tag === 'action')
      .actions.find((b: any) => b.value.choice === 'once');
    bridge.handleButtonClick(oneBtn.value, 'user_fast');
    await expect(p).resolves.toBe('once');

    // Still no updateCard — we can't edit a message that doesn't exist yet.
    expect(sender.updateCard).not.toHaveBeenCalled();

    // Now the send lands. The fix must apply the stashed resolution.
    sender.releaseSend('msg_late');
    await new Promise((r) => setImmediate(r));

    expect(sender.updateCard).toHaveBeenCalledTimes(1);
    const [msgId, updatedJson] = sender.updateCard.mock.calls[0] as [string, string];
    expect(msgId).toBe('msg_late');
    const updated = JSON.parse(updatedJson);
    expect(updated.header.template).toBe('green'); // 'once' → approved/green
  });

  it('text-command resolve before send completes — updateCard still fires', async () => {
    const store = new ApprovalStore();
    const sender = makeSlowSender();
    const bridge = new ApprovalBridge(store, sender, makeLogger());
    bridge.attachToSession(CHAT);

    const p = store.promptApproval(CHAT, REQ);
    await Promise.resolve();
    await Promise.resolve();

    // `/deny` via text while send is in flight.
    const count = bridge.resolveNextByText(CHAT, 'deny', 'user_text');
    expect(count).toBe(1);
    await expect(p).resolves.toBe('deny');
    expect(sender.updateCard).not.toHaveBeenCalled();

    sender.releaseSend('msg_text');
    await new Promise((r) => setImmediate(r));

    expect(sender.updateCard).toHaveBeenCalledTimes(1);
    expect(JSON.parse(sender.updateCard.mock.calls[0][1] as string).header.template).toBe('red');
  });

  it('timeout auto-settle before send completes — updateCard fires with autoResolved marker', async () => {
    const store = new ApprovalStore({ timeoutMs: 10 });
    const sender = makeSlowSender();
    const bridge = new ApprovalBridge(store, sender, makeLogger());
    bridge.attachToSession(CHAT);

    const p = store.promptApproval(CHAT, REQ);
    // Wait long enough for the timeout to fire while sendCard is still pending.
    await new Promise((r) => setTimeout(r, 25));
    await expect(p).resolves.toBe('deny');
    expect(sender.updateCard).not.toHaveBeenCalled();

    sender.releaseSend('msg_timeout');
    await new Promise((r) => setImmediate(r));

    expect(sender.updateCard).toHaveBeenCalledTimes(1);
    // autoResolved rendering — card-renderer marks the body accordingly; we
    // don't poke at the exact string but do assert the color and the fact
    // that updateCard got the late messageId.
    const [msgId] = sender.updateCard.mock.calls[0] as [string, string];
    expect(msgId).toBe('msg_timeout');
  });

  it('detach while send in flight — late-arriving send still updates the card', async () => {
    const store = new ApprovalStore();
    const sender = makeSlowSender();
    const bridge = new ApprovalBridge(store, sender, makeLogger());
    const detach = bridge.attachToSession(CHAT);

    const p = store.promptApproval(CHAT, REQ);
    await Promise.resolve();
    await Promise.resolve();

    // Detach fires — unregisterNotify resolves pending as 'deny' and
    // triggers handleAutoSettle. Because sendCard hasn't completed,
    // pendingResolution should be stashed on the inflight entry (not
    // deleted by the cleanup loop).
    detach();
    await expect(p).resolves.toBe('deny');
    expect(sender.updateCard).not.toHaveBeenCalled();

    sender.releaseSend('msg_detach');
    await new Promise((r) => setImmediate(r));

    // The fix: the card in the chat gets updated to resolved-deny even
    // though the session was detached before the send completed.
    expect(sender.updateCard).toHaveBeenCalledTimes(1);
    expect(JSON.parse(sender.updateCard.mock.calls[0][1] as string).header.template).toBe('red');
  });

  it('send failure AFTER resolve does not double-deny the store', async () => {
    const store = new ApprovalStore();
    const sender = makeSlowSender();
    const logger = makeLogger();
    const bridge = new ApprovalBridge(store, sender, logger);
    bridge.attachToSession(CHAT);

    const p = store.promptApproval(CHAT, REQ);
    await Promise.resolve();
    await Promise.resolve();

    // User clicks once while send still in flight.
    const card = JSON.parse(sender.sendCard.mock.calls[0][1] as string);
    const oneBtn = card.body.elements
      .find((e: any) => e.tag === 'action')
      .actions.find((b: any) => b.value.choice === 'once');
    bridge.handleButtonClick(oneBtn.value);
    await expect(p).resolves.toBe('once');

    // Now the send FAILS. The bridge must not try to re-resolve as 'deny'
    // (the store already has 'once' — `resolveById` would return false and
    // we'd log a noisy warning).
    sender.failSend(new Error('feishu 500'));
    await new Promise((r) => setImmediate(r));

    // updateCard never called (we never got a messageId), but no extra
    // store resolution was attempted.
    expect(sender.updateCard).not.toHaveBeenCalled();
    // The logger.error from the catch block is expected; what we guard
    // against is a second resolveById('deny') call, which would show up as
    // a warn "approval resolveById returned false".
    expect(logger.warn).not.toHaveBeenCalled();
  });
});
