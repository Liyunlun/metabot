import { describe, it, expect, vi } from 'vitest';
import {
  ApprovalStore,
  type ApprovalRequest,
  type NotifyCallback,
  type PermanentStore,
} from '../src/security/approval-store.js';

const SESSION = 'chat_A';
const OTHER_SESSION = 'chat_B';

function mkRequest(patternKey = 'recursive delete'): ApprovalRequest {
  return { command: 'rm -rf foo', description: patternKey, patternKey };
}

/** Capturing notify cb — returns the ids it has seen, in order. */
function makeNotify(): { cb: NotifyCallback; ids: string[]; reqs: ApprovalRequest[] } {
  const ids: string[] = [];
  const reqs: ApprovalRequest[] = [];
  const cb: NotifyCallback = (id, req) => {
    ids.push(id);
    reqs.push(req);
  };
  return { cb, ids, reqs };
}

describe('ApprovalStore — pre-approval fast path', () => {
  it('returns false for unknown session + pattern', () => {
    const store = new ApprovalStore();
    expect(store.isPreApproved(SESSION, 'recursive delete')).toBe(false);
  });

  it('returns true when YOLO is enabled on the session', () => {
    const store = new ApprovalStore();
    store.setYolo(SESSION, true);
    expect(store.isPreApproved(SESSION, 'any key')).toBe(true);
  });

  it('YOLO toggle off removes the fast-pass', () => {
    const store = new ApprovalStore();
    store.setYolo(SESSION, true);
    store.setYolo(SESSION, false);
    expect(store.isPreApproved(SESSION, 'any key')).toBe(false);
  });

  it('returns true for session-approved pattern on that session only', () => {
    const store = new ApprovalStore();
    store.approveForSession(SESSION, 'recursive delete');
    expect(store.isPreApproved(SESSION, 'recursive delete')).toBe(true);
    expect(store.isPreApproved(OTHER_SESSION, 'recursive delete')).toBe(false);
  });

  it('returns true for permanently-approved pattern across all sessions', () => {
    const store = new ApprovalStore();
    store.approvePermanent('recursive delete');
    expect(store.isPreApproved(SESSION, 'recursive delete')).toBe(true);
    expect(store.isPreApproved(OTHER_SESSION, 'recursive delete')).toBe(true);
  });
});

describe('ApprovalStore — promptApproval flow', () => {
  it('resolves with "deny" immediately when no notify cb is registered', async () => {
    const store = new ApprovalStore();
    await expect(store.promptApproval(SESSION, mkRequest())).resolves.toBe('deny');
  });

  it('resolves with "once" immediately when already pre-approved', async () => {
    const store = new ApprovalStore();
    store.approvePermanent('recursive delete');
    await expect(store.promptApproval(SESSION, mkRequest())).resolves.toBe('once');
  });

  it('fires the notify cb with an approval id and the request', async () => {
    const store = new ApprovalStore();
    const { cb, ids, reqs } = makeNotify();
    store.registerNotify(SESSION, cb);
    const p = store.promptApproval(SESSION, mkRequest());
    // Flush the queued microtask that fires the cb.
    await Promise.resolve();
    expect(ids).toHaveLength(1);
    expect(reqs[0].command).toBe('rm -rf foo');
    store.resolveById(ids[0], 'once');
    await expect(p).resolves.toBe('once');
  });

  it('records session/permanent approval based on the choice', async () => {
    const store = new ApprovalStore();
    const { cb, ids } = makeNotify();
    store.registerNotify(SESSION, cb);

    const p1 = store.promptApproval(SESSION, mkRequest('rm -r'));
    await Promise.resolve();
    store.resolveById(ids[0], 'session');
    await p1;

    const p2 = store.promptApproval(SESSION, mkRequest('SQL DROP'));
    await Promise.resolve();
    store.resolveById(ids[1], 'always');
    await p2;

    const p3 = store.promptApproval(SESSION, mkRequest('git force push'));
    await Promise.resolve();
    store.resolveById(ids[2], 'once');
    await p3;

    expect(store.getSessionApprovals(SESSION)).toEqual(['rm -r']);
    expect(store.getPermanentApprovals()).toEqual(['SQL DROP']);
  });

  it('"deny" choice does NOT record any approval', async () => {
    const store = new ApprovalStore();
    const { cb, ids } = makeNotify();
    store.registerNotify(SESSION, cb);

    const p = store.promptApproval(SESSION, mkRequest('rm -r'));
    await Promise.resolve();
    store.resolveById(ids[0], 'deny');
    await expect(p).resolves.toBe('deny');

    expect(store.getSessionApprovals(SESSION)).toEqual([]);
    expect(store.getPermanentApprovals()).toEqual([]);
  });

  it('resolveById on unknown id returns false', () => {
    const store = new ApprovalStore();
    expect(store.resolveById('nope', 'once')).toBe(false);
  });

  it('resolveById is idempotent — second call returns false', async () => {
    const store = new ApprovalStore();
    const { cb, ids } = makeNotify();
    store.registerNotify(SESSION, cb);
    const p = store.promptApproval(SESSION, mkRequest());
    await Promise.resolve();
    expect(store.resolveById(ids[0], 'once')).toBe(true);
    await p;
    expect(store.resolveById(ids[0], 'once')).toBe(false);
  });

  it('resolves the promise as "deny" if the notify cb throws', async () => {
    const onError = vi.fn();
    const store = new ApprovalStore({ onError });
    const cb: NotifyCallback = () => {
      throw new Error('ui down');
    };
    store.registerNotify(SESSION, cb);
    await expect(store.promptApproval(SESSION, mkRequest())).resolves.toBe('deny');
    expect(onError).toHaveBeenCalledWith('notify cb threw', expect.any(Error));
  });

  it('resolves the promise as "deny" if an async notify cb rejects', async () => {
    const onError = vi.fn();
    const store = new ApprovalStore({ onError });
    const cb: NotifyCallback = async () => {
      throw new Error('send failed');
    };
    store.registerNotify(SESSION, cb);
    await expect(store.promptApproval(SESSION, mkRequest())).resolves.toBe('deny');
    // Drain the catch() handler.
    await Promise.resolve();
    expect(onError).toHaveBeenCalledWith('notify cb rejected', expect.any(Error));
  });
});

describe('ApprovalStore — timeout', () => {
  it('auto-denies when no resolution arrives within timeoutMs', async () => {
    vi.useFakeTimers();
    const onError = vi.fn();
    const store = new ApprovalStore({ onError, timeoutMs: 5_000 });
    const { cb } = makeNotify();
    store.registerNotify(SESSION, cb);

    const p = store.promptApproval(SESSION, mkRequest());
    await Promise.resolve();

    vi.advanceTimersByTime(5_000);
    await expect(p).resolves.toBe('deny');
    expect(onError).toHaveBeenCalledWith(
      'approval timeout — auto-denying',
      expect.objectContaining({ sessionKey: SESSION }),
    );
    vi.useRealTimers();
  });

  it('does not fire timeout when resolved in time', async () => {
    vi.useFakeTimers();
    const store = new ApprovalStore({ timeoutMs: 5_000 });
    const { cb, ids } = makeNotify();
    store.registerNotify(SESSION, cb);

    const p = store.promptApproval(SESSION, mkRequest());
    await Promise.resolve();
    store.resolveById(ids[0], 'once');
    await expect(p).resolves.toBe('once');

    // Advancing past the timeout must not reopen the promise.
    vi.advanceTimersByTime(10_000);
    vi.useRealTimers();
  });
});

describe('ApprovalStore — FIFO queue semantics', () => {
  it('resolveNext resolves the oldest pending approval first', async () => {
    const store = new ApprovalStore();
    const { cb, ids } = makeNotify();
    store.registerNotify(SESSION, cb);

    const p1 = store.promptApproval(SESSION, mkRequest('a'));
    const p2 = store.promptApproval(SESSION, mkRequest('b'));
    const p3 = store.promptApproval(SESSION, mkRequest('c'));
    await Promise.resolve();
    expect(ids).toHaveLength(3);

    expect(store.getPendingCount(SESSION)).toBe(3);
    expect(store.resolveNext(SESSION, 'once')).toBe(1);
    await expect(p1).resolves.toBe('once');
    expect(store.getPendingCount(SESSION)).toBe(2);

    expect(store.resolveNext(SESSION, 'session')).toBe(1);
    await expect(p2).resolves.toBe('session');
    expect(store.getPendingCount(SESSION)).toBe(1);

    expect(store.resolveNext(SESSION, 'deny')).toBe(1);
    await expect(p3).resolves.toBe('deny');
    expect(store.getPendingCount(SESSION)).toBe(0);
  });

  it('resolveNext returns 0 when queue is empty', () => {
    const store = new ApprovalStore();
    expect(store.resolveNext(SESSION, 'once')).toBe(0);
  });

  it('resolveAll resolves every pending approval with the same choice', async () => {
    const store = new ApprovalStore();
    const { cb } = makeNotify();
    store.registerNotify(SESSION, cb);

    const p1 = store.promptApproval(SESSION, mkRequest('a'));
    const p2 = store.promptApproval(SESSION, mkRequest('b'));
    await Promise.resolve();

    expect(store.resolveAll(SESSION, 'once')).toBe(2);
    await expect(p1).resolves.toBe('once');
    await expect(p2).resolves.toBe('once');
    expect(store.getPendingCount(SESSION)).toBe(0);
  });

  it('queue is isolated per session', async () => {
    const store = new ApprovalStore();
    const a = makeNotify();
    const b = makeNotify();
    store.registerNotify(SESSION, a.cb);
    store.registerNotify(OTHER_SESSION, b.cb);

    const pA = store.promptApproval(SESSION, mkRequest('a'));
    const pB = store.promptApproval(OTHER_SESSION, mkRequest('b'));
    await Promise.resolve();

    expect(store.getPendingCount(SESSION)).toBe(1);
    expect(store.getPendingCount(OTHER_SESSION)).toBe(1);

    // Resolving SESSION does not affect OTHER_SESSION.
    store.resolveNext(SESSION, 'once');
    await pA;
    expect(store.getPendingCount(SESSION)).toBe(0);
    expect(store.getPendingCount(OTHER_SESSION)).toBe(1);

    store.resolveNext(OTHER_SESSION, 'deny');
    await expect(pB).resolves.toBe('deny');
  });
});

describe('ApprovalStore — unregister safety', () => {
  it('unregisterNotify resolves all pending approvals as "deny"', async () => {
    const store = new ApprovalStore();
    const { cb } = makeNotify();
    store.registerNotify(SESSION, cb);

    const p1 = store.promptApproval(SESSION, mkRequest('a'));
    const p2 = store.promptApproval(SESSION, mkRequest('b'));
    await Promise.resolve();

    store.unregisterNotify(SESSION);
    await expect(p1).resolves.toBe('deny');
    await expect(p2).resolves.toBe('deny');
    expect(store.getPendingCount(SESSION)).toBe(0);
  });

  it('unregisterNotify of an unknown session is a no-op', () => {
    const store = new ApprovalStore();
    expect(() => store.unregisterNotify('nonexistent')).not.toThrow();
  });

  it('pre-microtask unregister: cb is never invoked, promise denies', async () => {
    const store = new ApprovalStore();
    const cb = vi.fn();
    store.registerNotify(SESSION, cb);

    const p = store.promptApproval(SESSION, mkRequest());
    // Deny and unregister before the queueMicrotask that fires the cb runs.
    store.unregisterNotify(SESSION);

    await expect(p).resolves.toBe('deny');
    // Drain microtasks — cb must have been skipped because entry was settled.
    await Promise.resolve();
    expect(cb).not.toHaveBeenCalled();
  });
});

describe('ApprovalStore — clearSession wipes all per-session state', () => {
  it('clears approvals, YOLO, and pending (resolving them as deny)', async () => {
    const store = new ApprovalStore();
    const { cb } = makeNotify();
    store.registerNotify(SESSION, cb);
    store.approveForSession(SESSION, 'other-pat');

    // Start a pending request *before* enabling YOLO so it actually enqueues.
    const p = store.promptApproval(SESSION, mkRequest('not-approved-yet'));
    await Promise.resolve();
    store.setYolo(SESSION, true);

    expect(store.getPendingCount(SESSION)).toBe(1);

    store.clearSession(SESSION);

    expect(store.getSessionApprovals(SESSION)).toEqual([]);
    expect(store.isYolo(SESSION)).toBe(false);
    expect(store.getPendingCount(SESSION)).toBe(0);
    await expect(p).resolves.toBe('deny');
  });
});

describe('ApprovalStore — byId consistency under mixed resolution', () => {
  it('resolveAll purges byId entries too', async () => {
    const store = new ApprovalStore();
    const { cb, ids } = makeNotify();
    store.registerNotify(SESSION, cb);

    const p1 = store.promptApproval(SESSION, mkRequest('a'));
    const p2 = store.promptApproval(SESSION, mkRequest('b'));
    await Promise.resolve();

    store.resolveAll(SESSION, 'once');
    await p1;
    await p2;

    // Re-resolving either stale id must return false (entry gone).
    expect(store.resolveById(ids[0], 'deny')).toBe(false);
    expect(store.resolveById(ids[1], 'deny')).toBe(false);
  });

  it('resolveNext then resolveById on the same (now stale) id returns false', async () => {
    const store = new ApprovalStore();
    const { cb, ids } = makeNotify();
    store.registerNotify(SESSION, cb);

    const p = store.promptApproval(SESSION, mkRequest());
    await Promise.resolve();

    store.resolveNext(SESSION, 'once');
    await p;

    expect(store.resolveById(ids[0], 'deny')).toBe(false);
  });
});

describe('ApprovalStore — permanent allowlist mutators', () => {
  it('revokePermanent removes a key and returns true', () => {
    const store = new ApprovalStore();
    store.approvePermanent('SQL DROP');
    expect(store.revokePermanent('SQL DROP')).toBe(true);
    expect(store.getPermanentApprovals()).toEqual([]);
  });

  it('revokePermanent on missing key returns false', () => {
    const store = new ApprovalStore();
    expect(store.revokePermanent('not-there')).toBe(false);
  });

  it('clearSession wipes that session but leaves others + permanent intact', () => {
    const store = new ApprovalStore();
    store.approveForSession(SESSION, 'a');
    store.approveForSession(OTHER_SESSION, 'b');
    store.approvePermanent('c');

    store.clearSession(SESSION);
    expect(store.getSessionApprovals(SESSION)).toEqual([]);
    expect(store.getSessionApprovals(OTHER_SESSION)).toEqual(['b']);
    expect(store.getPermanentApprovals()).toEqual(['c']);
  });
});

describe('ApprovalStore — persistence hook', () => {
  it('loadPermanent populates from the store', async () => {
    const pstore: PermanentStore = {
      load: vi.fn().mockResolvedValue(['pat1', 'pat2']),
      save: vi.fn().mockResolvedValue(undefined),
    };
    const store = new ApprovalStore(pstore);
    await store.loadPermanent();
    expect(store.getPermanentApprovals().sort()).toEqual(['pat1', 'pat2']);
  });

  it('approvePermanent triggers save', async () => {
    const save = vi.fn().mockResolvedValue(undefined);
    const pstore: PermanentStore = { load: () => [], save };
    const store = new ApprovalStore(pstore);
    store.approvePermanent('pat1');
    // Drain the microtask that fires save().
    await Promise.resolve();
    expect(save).toHaveBeenCalledWith(['pat1']);
  });

  it('revokePermanent triggers save when it removed a key', async () => {
    const save = vi.fn().mockResolvedValue(undefined);
    const pstore: PermanentStore = { load: () => ['pat1'], save };
    const store = new ApprovalStore(pstore);
    await store.loadPermanent();
    save.mockClear();

    store.revokePermanent('pat1');
    await Promise.resolve();
    expect(save).toHaveBeenCalledWith([]);
  });

  it('revokePermanent does NOT save when key was absent', async () => {
    const save = vi.fn().mockResolvedValue(undefined);
    const pstore: PermanentStore = { load: () => [], save };
    const store = new ApprovalStore(pstore);
    expect(store.revokePermanent('missing')).toBe(false);
    await Promise.resolve();
    expect(save).not.toHaveBeenCalled();
  });

  it('in-memory mode (no permanentStore) still works', async () => {
    const store = new ApprovalStore();
    store.approvePermanent('pat1');
    expect(store.getPermanentApprovals()).toEqual(['pat1']);
    await expect(store.loadPermanent()).resolves.toBeUndefined();
  });

  it('save failure is caught and reported via onError, not thrown', async () => {
    const onError = vi.fn();
    const save = vi.fn().mockRejectedValue(new Error('disk full'));
    const store = new ApprovalStore({
      permanentStore: { load: () => [], save },
      onError,
    });
    store.approvePermanent('pat1');
    // In-memory update still succeeded — failure is strictly a logging concern.
    expect(store.getPermanentApprovals()).toEqual(['pat1']);

    // Drain the rejection + onError handler.
    await new Promise((r) => setImmediate(r));
    expect(onError).toHaveBeenCalledWith(
      'failed to persist permanent approvals',
      expect.any(Error),
    );
  });
});
