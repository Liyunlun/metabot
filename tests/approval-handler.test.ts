import { describe, it, expect, vi } from 'vitest';
import { ApprovalStore } from '../src/security/approval-store.js';
import {
  createApprovalHandler,
  type ApprovalAuditSink,
  type ClassifierLike,
  type Logger,
} from '../src/security/approval-handler.js';
import type { SmartApprovalResult } from '../src/security/smart-approval.js';

const CHAT = 'oc_chat_A';
const CWD = '/home/user/proj';

function makeAudit(): ApprovalAuditSink & { log: ReturnType<typeof vi.fn> } {
  return { log: vi.fn() };
}

function makeLogger(): Logger {
  return { info: vi.fn(), warn: vi.fn(), error: vi.fn() };
}

function classifier(verdict: SmartApprovalResult['verdict'], extras?: Partial<SmartApprovalResult>): ClassifierLike {
  return {
    classify: vi.fn(async () => ({
      verdict,
      reason: verdict,
      latencyMs: 42,
      raw: verdict.toUpperCase(),
      ...extras,
    })),
  };
}

describe('createApprovalHandler — not-flagged commands', () => {
  it('allows commands that do not match any dangerous pattern', async () => {
    const audit = makeAudit();
    const handler = createApprovalHandler({
      chatId: CHAT,
      cwd: CWD,
      botName: 'metabot',
      approvalStore: new ApprovalStore(),
      smartApproval: classifier('approve'),
      cardPromptAvailable: true,
      audit,
      logger: makeLogger(),
    });

    await expect(handler('ls -la')).resolves.toBe('allow');
    // No audit entry for the hot path.
    expect(audit.log).not.toHaveBeenCalled();
  });
});

describe('createApprovalHandler — pre-approval allowlist', () => {
  it('short-circuits to allow when the session already approved the pattern', async () => {
    const store = new ApprovalStore();
    // `rm -rf /tmp/foo` matches the first pattern in the list
    // (`delete in root path`), so pre-approve THAT key specifically.
    store.approveForSession(CHAT, 'delete in root path');
    const audit = makeAudit();
    const cls = classifier('deny'); // would deny if reached — shouldn't be reached.
    const handler = createApprovalHandler({
      chatId: CHAT,
      cwd: CWD,
      botName: 'metabot',
      approvalStore: store,
      smartApproval: cls,
      cardPromptAvailable: true,
      audit,
      logger: makeLogger(),
    });

    await expect(handler('rm -rf /tmp/foo')).resolves.toBe('allow');
    expect(cls.classify).not.toHaveBeenCalled();
    expect(audit.log.mock.calls[0][0].meta?.path).toBe('allowlist_hit');
  });

  it('YOLO mode also short-circuits', async () => {
    const store = new ApprovalStore();
    store.setYolo(CHAT, true);
    const audit = makeAudit();
    const cls = classifier('deny');
    const handler = createApprovalHandler({
      chatId: CHAT,
      cwd: CWD,
      botName: 'metabot',
      approvalStore: store,
      smartApproval: cls,
      cardPromptAvailable: true,
      audit,
      logger: makeLogger(),
    });

    await expect(handler('rm -rf /tmp/foo')).resolves.toBe('allow');
    expect(cls.classify).not.toHaveBeenCalled();
  });
});

describe('createApprovalHandler — hard blacklist', () => {
  it('bypasses the classifier and goes straight to the card for rm -rf /', async () => {
    const store = new ApprovalStore();
    const cls = classifier('approve'); // must NOT be consulted.
    // Register a notify cb so promptApproval doesn't fail closed.
    store.registerNotify(CHAT, (id) => {
      // Simulate user clicking "once".
      queueMicrotask(() => store.resolveById(id, 'once'));
    });
    const audit = makeAudit();
    const handler = createApprovalHandler({
      chatId: CHAT,
      cwd: CWD,
      botName: 'metabot',
      approvalStore: store,
      smartApproval: cls,
      cardPromptAvailable: true,
      audit,
      logger: makeLogger(),
    });

    await expect(handler('rm -rf /')).resolves.toBe('allow');
    expect(cls.classify).not.toHaveBeenCalled();

    const paths = audit.log.mock.calls.map((c: unknown[]) => (c[0] as { meta?: { path?: string } }).meta?.path);
    expect(paths).toContain('hard_blacklist_prompted');
    expect(paths).toContain('user_approved');
  });

  it('SECURITY: session-approved pattern key does NOT auto-allow a hard-blacklisted command sharing it', async () => {
    // `rm -rf /tmp/foo` and `rm -rf /` both match pattern "delete in root path".
    // Approving the former must NEVER cause the latter to skip the card.
    const store = new ApprovalStore();
    store.approveForSession(CHAT, 'delete in root path');
    const cls = classifier('approve'); // must NOT be consulted.
    store.registerNotify(CHAT, (id) => {
      queueMicrotask(() => store.resolveById(id, 'deny')); // user says no
    });
    const audit = makeAudit();
    const handler = createApprovalHandler({
      chatId: CHAT,
      cwd: CWD,
      botName: 'metabot',
      approvalStore: store,
      smartApproval: cls,
      cardPromptAvailable: true,
      audit,
      logger: makeLogger(),
    });

    await expect(handler('rm -rf /')).resolves.toBe('deny');
    expect(cls.classify).not.toHaveBeenCalled();

    const paths = audit.log.mock.calls.map((c: unknown[]) => (c[0] as { meta?: { path?: string } }).meta?.path);
    expect(paths).not.toContain('allowlist_hit');
    expect(paths).toContain('hard_blacklist_prompted');
    expect(paths).toContain('user_denied');
  });

  it('SECURITY: YOLO mode does NOT bypass the hard blacklist', async () => {
    const store = new ApprovalStore();
    store.setYolo(CHAT, true);
    const cls = classifier('approve');
    store.registerNotify(CHAT, (id) => {
      queueMicrotask(() => store.resolveById(id, 'deny'));
    });
    const audit = makeAudit();
    const handler = createApprovalHandler({
      chatId: CHAT,
      cwd: CWD,
      botName: 'metabot',
      approvalStore: store,
      smartApproval: cls,
      cardPromptAvailable: true,
      audit,
      logger: makeLogger(),
    });

    await expect(handler('rm -rf /')).resolves.toBe('deny');
    expect(cls.classify).not.toHaveBeenCalled();

    const paths = audit.log.mock.calls.map((c: unknown[]) => (c[0] as { meta?: { path?: string } }).meta?.path);
    expect(paths).not.toContain('allowlist_hit');
    expect(paths).toContain('hard_blacklist_prompted');
    expect(paths).toContain('user_denied');
  });

  it('SECURITY: no-card platform + hard-blacklisted command + YOLO still denies', async () => {
    const store = new ApprovalStore();
    store.setYolo(CHAT, true);
    const audit = makeAudit();
    const handler = createApprovalHandler({
      chatId: CHAT,
      cwd: CWD,
      botName: 'metabot',
      approvalStore: store,
      smartApproval: classifier('approve'),
      cardPromptAvailable: false,
      audit,
      logger: makeLogger(),
    });

    await expect(handler('rm -rf /')).resolves.toBe('deny');
    const entries = audit.log.mock.calls.map((c: unknown[]) => (c[0] as { meta?: Record<string, unknown> }).meta);
    expect(entries.some((m) => m?.path === 'no_card_denied' && m?.hardBlacklisted === true)).toBe(true);
  });
});

describe('createApprovalHandler — smart classifier', () => {
  it('smart_approved → allow without raising a card', async () => {
    const store = new ApprovalStore();
    const cls = classifier('approve');
    const audit = makeAudit();
    const handler = createApprovalHandler({
      chatId: CHAT,
      cwd: CWD,
      botName: 'metabot',
      approvalStore: store,
      smartApproval: cls,
      cardPromptAvailable: true,
      audit,
      logger: makeLogger(),
    });

    await expect(handler('python -c "print(1)"')).resolves.toBe('allow');
    expect(cls.classify).toHaveBeenCalledTimes(1);
    expect(audit.log.mock.calls[0][0].meta?.path).toBe('smart_approved');
  });

  it('smart_denied → deny without raising a card', async () => {
    const store = new ApprovalStore();
    const cls = classifier('deny');
    const audit = makeAudit();
    const handler = createApprovalHandler({
      chatId: CHAT,
      cwd: CWD,
      botName: 'metabot',
      approvalStore: store,
      smartApproval: cls,
      cardPromptAvailable: true,
      audit,
      logger: makeLogger(),
    });

    await expect(handler('rm -rf /home/user')).resolves.toBe('deny');
    expect(audit.log.mock.calls[0][0].meta?.path).toBe('smart_denied');
  });

  it('passes cwd through to the classifier', async () => {
    const cls = classifier('approve');
    const handler = createApprovalHandler({
      chatId: CHAT,
      cwd: '/special/cwd',
      botName: 'metabot',
      approvalStore: new ApprovalStore(),
      smartApproval: cls,
      cardPromptAvailable: true,
      audit: makeAudit(),
      logger: makeLogger(),
    });
    await handler('python -c "print(1)"');
    expect((cls.classify as ReturnType<typeof vi.fn>).mock.calls[0][0].cwd).toBe('/special/cwd');
  });
});

describe('createApprovalHandler — escalate falls through to the card', () => {
  it('raises card and returns user verdict on escalate', async () => {
    const store = new ApprovalStore();
    const cls = classifier('escalate');
    store.registerNotify(CHAT, (id) => {
      queueMicrotask(() => store.resolveById(id, 'session'));
    });
    const audit = makeAudit();
    const handler = createApprovalHandler({
      chatId: CHAT,
      cwd: CWD,
      botName: 'metabot',
      approvalStore: store,
      smartApproval: cls,
      cardPromptAvailable: true,
      audit,
      logger: makeLogger(),
    });

    await expect(handler('rm -rf /tmp/foo')).resolves.toBe('allow');
    const paths = audit.log.mock.calls.map((c: unknown[]) => (c[0] as { meta?: { path?: string } }).meta?.path);
    expect(paths).toContain('escalated');
    expect(paths).toContain('user_approved');
  });

  it('card deny → returns deny', async () => {
    const store = new ApprovalStore();
    const cls = classifier('escalate');
    store.registerNotify(CHAT, (id) => {
      queueMicrotask(() => store.resolveById(id, 'deny'));
    });
    const audit = makeAudit();
    const handler = createApprovalHandler({
      chatId: CHAT,
      cwd: CWD,
      botName: 'metabot',
      approvalStore: store,
      smartApproval: cls,
      cardPromptAvailable: true,
      audit,
      logger: makeLogger(),
    });

    await expect(handler('rm -rf /tmp/foo')).resolves.toBe('deny');
    const paths = audit.log.mock.calls.map((c: unknown[]) => (c[0] as { meta?: { path?: string } }).meta?.path);
    expect(paths).toContain('user_denied');
  });
});

describe('createApprovalHandler — no card available', () => {
  it('fails closed when the card path is unavailable and the classifier escalates', async () => {
    const cls = classifier('escalate');
    const audit = makeAudit();
    const handler = createApprovalHandler({
      chatId: CHAT,
      cwd: CWD,
      botName: 'metabot',
      approvalStore: new ApprovalStore(),
      smartApproval: cls,
      cardPromptAvailable: false,
      audit,
      logger: makeLogger(),
    });

    await expect(handler('rm -rf /tmp/foo')).resolves.toBe('deny');
    expect(audit.log.mock.calls[0][0].meta?.path).toBe('no_card_denied');
  });

  it('smart_approved still allows even when card is unavailable', async () => {
    const cls = classifier('approve');
    const handler = createApprovalHandler({
      chatId: CHAT,
      cwd: CWD,
      botName: 'metabot',
      approvalStore: new ApprovalStore(),
      smartApproval: cls,
      cardPromptAvailable: false,
      audit: makeAudit(),
      logger: makeLogger(),
    });
    await expect(handler('python -c "print(1)"')).resolves.toBe('allow');
  });
});

describe('createApprovalHandler — audit phase field', () => {
  it('terminal entries carry phase="terminal" and a verdict; prompted markers carry phase="prompted" and no verdict', async () => {
    const store = new ApprovalStore();
    const cls = classifier('escalate');
    store.registerNotify(CHAT, (id) => {
      queueMicrotask(() => store.resolveById(id, 'once'));
    });
    const audit = makeAudit();
    const handler = createApprovalHandler({
      chatId: CHAT,
      cwd: CWD,
      botName: 'metabot',
      approvalStore: store,
      smartApproval: cls,
      cardPromptAvailable: true,
      audit,
      logger: makeLogger(),
    });

    await handler('rm -rf /tmp/foo');

    const entries = audit.log.mock.calls.map((c: unknown[]) => (c[0] as { meta: Record<string, unknown> }).meta);
    // Exactly 2 entries: one 'prompted' marker then one 'terminal' verdict.
    expect(entries).toHaveLength(2);

    const prompted = entries.find((m) => m.phase === 'prompted');
    const terminal = entries.find((m) => m.phase === 'terminal');
    expect(prompted?.path).toBe('escalated');
    expect(prompted?.verdict).toBeUndefined();
    expect(terminal?.path).toBe('user_approved');
    expect(terminal?.verdict).toBe('allow');
  });

  it('allowlist_hit emits a single terminal entry (no prompt marker)', async () => {
    const store = new ApprovalStore();
    store.approveForSession(CHAT, 'recursive delete');
    const audit = makeAudit();
    const handler = createApprovalHandler({
      chatId: CHAT,
      cwd: CWD,
      botName: 'metabot',
      approvalStore: store,
      smartApproval: classifier('deny'),
      cardPromptAvailable: true,
      audit,
      logger: makeLogger(),
    });

    // `rm -rf foo` matches "recursive delete" (not "delete in root path"),
    // so the allowlist hit applies and the handler short-circuits.
    await handler('rm -rf foo');

    const entries = audit.log.mock.calls.map((c: unknown[]) => (c[0] as { meta: Record<string, unknown> }).meta);
    expect(entries).toHaveLength(1);
    expect(entries[0].phase).toBe('terminal');
    expect(entries[0].path).toBe('allowlist_hit');
    expect(entries[0].verdict).toBe('allow');
  });
});

describe('createApprovalHandler — classifier absent', () => {
  it('falls through to the card when no classifier is injected', async () => {
    const store = new ApprovalStore();
    store.registerNotify(CHAT, (id) => {
      queueMicrotask(() => store.resolveById(id, 'once'));
    });
    const audit = makeAudit();
    const handler = createApprovalHandler({
      chatId: CHAT,
      cwd: CWD,
      botName: 'metabot',
      approvalStore: store,
      // smartApproval intentionally undefined
      cardPromptAvailable: true,
      audit,
      logger: makeLogger(),
    });

    await expect(handler('rm -rf /tmp/foo')).resolves.toBe('allow');
    const paths = audit.log.mock.calls.map((c: unknown[]) => (c[0] as { meta?: { path?: string } }).meta?.path);
    expect(paths).toContain('escalated');
    expect(paths).toContain('user_approved');
  });
});
