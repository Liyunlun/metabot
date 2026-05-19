/**
 * Tests for the Phase 5 approval commands in `CommandHandler`:
 *   - `/approve [once|session|always]`
 *   - `/deny`
 *   - `/approvals`
 *   - `/revoke <pattern>` (and empty-arg help form)
 *   - `/help` documents the new commands
 *
 * We stub out `IMessageSender`, `SessionManager`, `MemoryClient`,
 * `AuditLogger`, and the `ApprovalBridge` so these tests focus on the
 * command parsing and routing behavior added in Phase 5, not on the
 * surrounding platform integration (which is covered separately).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CommandHandler } from '../src/bridge/command-handler.js';
import { approvalStore, buildSessionKey } from '../src/security/approval-store.js';
import type { ApprovalBridge } from '../src/security/approval-bridge.js';
import type { IMessageSender } from '../src/bridge/message-sender.interface.js';
import type { BotConfigBase } from '../src/config.js';
import type { Logger } from '../src/utils/logger.js';

const CHAT = 'chat_X';
const USER = 'user_X';
const SESSION_KEY = buildSessionKey('testbot', CHAT);

interface SentNotice {
  chatId: string;
  title: string;
  body: string;
  color?: string;
}

function makeSender(sent: SentNotice[]): IMessageSender {
  return {
    sendText: vi.fn(async () => undefined),
    sendTextNotice: vi.fn(async (chatId, title, body, color) => {
      sent.push({ chatId, title, body, color });
      return undefined;
    }),
    sendCard: vi.fn(async () => undefined),
    updateCard: vi.fn(async () => true),
  } as unknown as IMessageSender;
}

function makeHandler(options: { bridge?: ApprovalBridge } = {}): {
  handler: CommandHandler;
  sent: SentNotice[];
  bridge: ApprovalBridge;
} {
  const sent: SentNotice[] = [];
  const sender = makeSender(sent);
  const logger: Logger = {
    info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn(), trace: vi.fn(),
    fatal: vi.fn(), child: vi.fn(() => logger),
  } as unknown as Logger;
  const config = { name: 'testbot', claude: {} } as BotConfigBase;
  const sessionManager = { resetSession: vi.fn(), getSession: vi.fn(() => ({ workingDirectory: '/tmp', sessionId: 'abc' })) } as any;
  const memoryClient = {} as any;
  const audit = { log: vi.fn() } as any;
  const bridge: ApprovalBridge =
    options.bridge ?? ({ resolveNextByText: vi.fn(() => 0) } as unknown as ApprovalBridge);

  const handler = new CommandHandler(
    config,
    logger,
    sender,
    sessionManager,
    memoryClient,
    audit,
    () => undefined,
    () => undefined,
  );
  handler.setApprovalBridge(bridge);
  return { handler, sent, bridge };
}

function msg(text: string) {
  return { text, chatId: CHAT, userId: USER } as any;
}

describe('CommandHandler — /approve with scope', () => {
  beforeEach(() => {
    approvalStore.clearSession(SESSION_KEY);
  });

  it('/approve (no arg) routes as "once"', async () => {
    const resolveNextByText = vi.fn(() => 1);
    const bridge = { resolveNextByText } as unknown as ApprovalBridge;
    const { handler } = makeHandler({ bridge });

    await handler.handle(msg('/approve'));
    expect(resolveNextByText).toHaveBeenCalledWith(SESSION_KEY, 'once', USER);
  });

  it('/approve once (explicit) routes as "once"', async () => {
    const resolveNextByText = vi.fn(() => 1);
    const bridge = { resolveNextByText } as unknown as ApprovalBridge;
    const { handler } = makeHandler({ bridge });

    await handler.handle(msg('/approve once'));
    expect(resolveNextByText).toHaveBeenCalledWith(SESSION_KEY, 'once', USER);
  });

  it('/approve session routes as "session"', async () => {
    const resolveNextByText = vi.fn(() => 1);
    const bridge = { resolveNextByText } as unknown as ApprovalBridge;
    const { handler } = makeHandler({ bridge });

    await handler.handle(msg('/approve session'));
    expect(resolveNextByText).toHaveBeenCalledWith(SESSION_KEY, 'session', USER);
  });

  it('/approve always routes as "always"', async () => {
    const resolveNextByText = vi.fn(() => 1);
    const bridge = { resolveNextByText } as unknown as ApprovalBridge;
    const { handler } = makeHandler({ bridge });

    await handler.handle(msg('/approve always'));
    expect(resolveNextByText).toHaveBeenCalledWith(SESSION_KEY, 'always', USER);
  });

  it('/approve ALWAYS is case-insensitive', async () => {
    const resolveNextByText = vi.fn(() => 1);
    const bridge = { resolveNextByText } as unknown as ApprovalBridge;
    const { handler } = makeHandler({ bridge });

    await handler.handle(msg('/approve ALWAYS'));
    expect(resolveNextByText).toHaveBeenCalledWith(SESSION_KEY, 'always', USER);
  });

  it('/approve bogus rejects with an error notice and does NOT call bridge', async () => {
    const resolveNextByText = vi.fn(() => 1);
    const bridge = { resolveNextByText } as unknown as ApprovalBridge;
    const { handler, sent } = makeHandler({ bridge });

    await handler.handle(msg('/approve never'));
    expect(resolveNextByText).not.toHaveBeenCalled();
    expect(sent.at(-1)?.title).toMatch(/Invalid Scope/);
    expect(sent.at(-1)?.color).toBe('red');
  });

  it('/deny routes as "deny" regardless of args', async () => {
    const resolveNextByText = vi.fn(() => 1);
    const bridge = { resolveNextByText } as unknown as ApprovalBridge;
    const { handler } = makeHandler({ bridge });

    await handler.handle(msg('/deny'));
    expect(resolveNextByText).toHaveBeenCalledWith(SESSION_KEY, 'deny', USER);
  });

  it('/approve with no pending approval surfaces a notice', async () => {
    const resolveNextByText = vi.fn(() => 0);
    const bridge = { resolveNextByText } as unknown as ApprovalBridge;
    const { handler, sent } = makeHandler({ bridge });

    await handler.handle(msg('/approve session'));
    expect(sent.at(-1)?.title).toMatch(/No Pending Approval/);
  });
});

describe('CommandHandler — /approvals (list)', () => {
  beforeEach(() => {
    approvalStore.clearSession(SESSION_KEY);
    // Drain any permanent entries from prior tests (module-level singleton).
    for (const k of approvalStore.getPermanentApprovals()) {
      approvalStore.revokePermanent(k);
    }
  });

  it('shows "None" for empty session + permanent allowlist', async () => {
    const { handler, sent } = makeHandler();
    await handler.handle(msg('/approvals'));
    const last = sent.at(-1);
    expect(last?.title).toMatch(/Approvals/);
    expect(last?.body).toMatch(/YOLO Mode.*off/);
    expect(last?.body).toMatch(/Session allowlist\*\* \(0\)/);
    expect(last?.body).toMatch(/Permanent allowlist\*\* \(0\)/);
  });

  it('lists session + permanent entries with counts', async () => {
    approvalStore.approveForSession(SESSION_KEY, 'session-pattern-1');
    approvalStore.approveForSession(SESSION_KEY, 'session-pattern-2');
    approvalStore.approvePermanent('permanent-pattern-A');

    const { handler, sent } = makeHandler();
    await handler.handle(msg('/approvals'));
    const body = sent.at(-1)?.body ?? '';
    expect(body).toMatch(/Session allowlist\*\* \(2\)/);
    expect(body).toContain('session-pattern-1');
    expect(body).toContain('session-pattern-2');
    expect(body).toMatch(/Permanent allowlist\*\* \(1\)/);
    expect(body).toContain('permanent-pattern-A');
  });

  it('reflects YOLO mode when enabled', async () => {
    approvalStore.setYolo(SESSION_KEY, true);
    const { handler, sent } = makeHandler();
    await handler.handle(msg('/approvals'));
    expect(sent.at(-1)?.body).toMatch(/YOLO Mode.*on/);
    approvalStore.setYolo(SESSION_KEY, false);
  });

  it('scopes session allowlist to the current chat only', async () => {
    const OTHER_KEY = buildSessionKey('testbot', 'other_chat');
    approvalStore.approveForSession(OTHER_KEY, 'other-session-pattern');
    const { handler, sent } = makeHandler();
    await handler.handle(msg('/approvals'));
    const body = sent.at(-1)?.body ?? '';
    expect(body).not.toContain('other-session-pattern');
    approvalStore.clearSession(OTHER_KEY);
  });
});

describe('CommandHandler — /revoke', () => {
  beforeEach(() => {
    for (const k of approvalStore.getPermanentApprovals()) {
      approvalStore.revokePermanent(k);
    }
  });

  it('removes an existing permanent entry and confirms', async () => {
    approvalStore.approvePermanent('will-be-revoked');
    const { handler, sent } = makeHandler();
    await handler.handle(msg('/revoke will-be-revoked'));
    expect(approvalStore.getPermanentApprovals()).not.toContain('will-be-revoked');
    expect(sent.at(-1)?.title).toMatch(/Revoked/);
    expect(sent.at(-1)?.color).toBe('green');
  });

  it('reports Not Found for a pattern that is not in the allowlist', async () => {
    const { handler, sent } = makeHandler();
    await handler.handle(msg('/revoke nonexistent'));
    expect(sent.at(-1)?.title).toMatch(/Not Found/);
  });

  it('no-arg form prints usage + current list (empty case)', async () => {
    const { handler, sent } = makeHandler();
    await handler.handle(msg('/revoke'));
    expect(sent.at(-1)?.body).toMatch(/Usage: `\/revoke/);
    expect(sent.at(-1)?.body).toMatch(/empty/i);
  });

  it('no-arg form prints usage + current list (populated case)', async () => {
    approvalStore.approvePermanent('keep-me');
    approvalStore.approvePermanent('me-too');
    const { handler, sent } = makeHandler();
    await handler.handle(msg('/revoke'));
    expect(sent.at(-1)?.body).toContain('keep-me');
    expect(sent.at(-1)?.body).toContain('me-too');
  });

  it('pattern matching is exact (case- and whitespace-sensitive)', async () => {
    approvalStore.approvePermanent('Exact Pattern');
    const { handler, sent } = makeHandler();
    // Wrong case — should miss.
    await handler.handle(msg('/revoke exact pattern'));
    expect(approvalStore.getPermanentApprovals()).toContain('Exact Pattern');
    expect(sent.at(-1)?.title).toMatch(/Not Found/);
    // Exact match with leading space — trimmed before lookup, should hit.
    await handler.handle(msg('/revoke    Exact Pattern'));
    expect(approvalStore.getPermanentApprovals()).not.toContain('Exact Pattern');
  });
});

describe('CommandHandler — /help documents Phase 5 commands', () => {
  it('includes /approvals and /revoke in help output', async () => {
    const { handler, sent } = makeHandler();
    await handler.handle(msg('/help'));
    const body = sent.at(-1)?.body ?? '';
    expect(body).toContain('/approvals');
    expect(body).toContain('/revoke');
    expect(body).toMatch(/\/approve \[session\|always\]/);
  });
});

describe('CommandHandler — approval commands without bridge', () => {
  it('/approve falls through to "Not Available" when bridge is absent', async () => {
    const sent: SentNotice[] = [];
    const sender = makeSender(sent);
    const config = { name: 'testbot', claude: {} } as BotConfigBase;
    const handler = new CommandHandler(
      config,
      { info: vi.fn(), warn: vi.fn(), error: vi.fn(), child: () => ({}) } as unknown as Logger,
      sender,
      { resetSession: vi.fn(), getSession: () => ({} as any) } as any,
      {} as any,
      { log: vi.fn() } as any,
      () => undefined,
      () => undefined,
    );
    // No setApprovalBridge call.
    await handler.handle(msg('/approve always'));
    expect(sent.at(-1)?.title).toMatch(/Not Available/);
  });
});
