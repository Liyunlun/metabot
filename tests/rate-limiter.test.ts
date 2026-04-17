import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { RateLimiter } from '../src/bridge/rate-limiter.js';

describe('RateLimiter', () => {
  beforeEach(() => { vi.useFakeTimers(); });
  afterEach(() => { vi.useRealTimers(); });

  it('executes first call immediately', () => {
    const limiter = new RateLimiter(1000);
    const fn = vi.fn();
    limiter.schedule(fn);
    expect(fn).toHaveBeenCalledOnce();
  });

  it('delays second call within interval', () => {
    const limiter = new RateLimiter(1000);
    const fn1 = vi.fn();
    const fn2 = vi.fn();

    limiter.schedule(fn1);
    expect(fn1).toHaveBeenCalledOnce();

    limiter.schedule(fn2);
    expect(fn2).not.toHaveBeenCalled();

    vi.advanceTimersByTime(1000);
    expect(fn2).toHaveBeenCalledOnce();
  });

  it('replaces pending call with latest', () => {
    const limiter = new RateLimiter(1000);
    const fn1 = vi.fn();
    const fn2 = vi.fn();
    const fn3 = vi.fn();

    limiter.schedule(fn1); // immediate
    limiter.schedule(fn2); // queued
    limiter.schedule(fn3); // replaces fn2

    vi.advanceTimersByTime(1000);
    expect(fn2).not.toHaveBeenCalled();
    expect(fn3).toHaveBeenCalledOnce();
  });

  it('flush executes pending immediately', async () => {
    vi.useRealTimers(); // flush uses real await
    const limiter = new RateLimiter(5000);
    const fn1 = vi.fn();
    const fn2 = vi.fn();

    limiter.schedule(fn1);
    limiter.schedule(fn2);

    await limiter.flush();
    expect(fn2).toHaveBeenCalledOnce();
  });

  it('cancel discards pending', () => {
    const limiter = new RateLimiter(1000);
    const fn1 = vi.fn();
    const fn2 = vi.fn();

    limiter.schedule(fn1);
    limiter.schedule(fn2);

    limiter.cancel();
    vi.advanceTimersByTime(2000);
    expect(fn2).not.toHaveBeenCalled();
  });

  it('cancelAndWait waits for interval', async () => {
    vi.useRealTimers();
    const limiter = new RateLimiter(100);
    const fn = vi.fn();
    limiter.schedule(fn);

    const start = Date.now();
    await limiter.cancelAndWait();
    const elapsed = Date.now() - start;
    // Should have waited roughly the interval
    expect(elapsed).toBeGreaterThanOrEqual(50);
  });

  it('allows call after interval passes', () => {
    const limiter = new RateLimiter(1000);
    const fn1 = vi.fn();
    const fn2 = vi.fn();

    limiter.schedule(fn1);
    vi.advanceTimersByTime(1000);

    limiter.schedule(fn2);
    expect(fn2).toHaveBeenCalledOnce();
  });

  it('flush awaits the in-flight promise returned by the last thunk', async () => {
    // Regression guard: before this fix, a scheduled thunk returning a
    // Promise fired fire-and-forget; flush() returned before the network
    // call landed, letting a subsequent freeze race with the stale update.
    vi.useRealTimers();
    const limiter = new RateLimiter(100);

    let resolveUpdate: () => void = () => {};
    const updatePromise = new Promise<void>((r) => { resolveUpdate = r; });
    const order: string[] = [];

    limiter.schedule(() => {
      order.push('update:start');
      return updatePromise.then(() => { order.push('update:end'); });
    });

    const flushP = limiter.flush();
    // flush must NOT complete while the thunk's promise is unresolved.
    await new Promise((r) => setTimeout(r, 50));
    expect(order).toEqual(['update:start']);

    resolveUpdate();
    await flushP;
    expect(order).toEqual(['update:start', 'update:end']);
  });

  it('flush awaits ALL unsettled thunks, not just the most recent one', async () => {
    // Regression guard for the chaining fix: if thunk A's duration exceeds
    // intervalMs, thunk B can fire on the immediate path while A is still
    // in-flight. Without cumulative tracking, inFlight would be overwritten
    // and flush() could return while A is still racing a subsequent
    // recreateCard freeze — the original bug this PR fixes.
    vi.useRealTimers();
    const limiter = new RateLimiter(50); // short interval so B fires immediately

    let resolveA: () => void = () => {};
    let resolveB: () => void = () => {};
    const a = new Promise<void>((r) => { resolveA = r; });
    const b = new Promise<void>((r) => { resolveB = r; });
    const order: string[] = [];

    limiter.schedule(() => {
      order.push('A:start');
      return a.then(() => order.push('A:end'));
    });
    // Wait past intervalMs so the next schedule goes through the immediate path
    // while A is still unresolved — overlapping in-flight thunks.
    await new Promise((r) => setTimeout(r, 80));
    limiter.schedule(() => {
      order.push('B:start');
      return b.then(() => order.push('B:end'));
    });

    const flushP = limiter.flush();
    let flushResolved = false;
    flushP.then(() => { flushResolved = true; });

    // Resolve B FIRST. Under the old (broken) "track only latest" logic,
    // flush would resolve here because inFlight pointed to B. The fix must
    // still be waiting for A.
    resolveB();
    await new Promise((r) => setTimeout(r, 30));
    expect(flushResolved).toBe(false);
    expect(order).toContain('B:end');
    expect(order).not.toContain('A:end');

    // Now resolve A. flush should finally complete.
    resolveA();
    await flushP;
    expect(order).toContain('A:end');
  });

  it('cancelAndWait awaits in-flight thunk before returning', async () => {
    vi.useRealTimers();
    const limiter = new RateLimiter(50);

    let resolveUpdate: () => void = () => {};
    const updatePromise = new Promise<void>((r) => { resolveUpdate = r; });
    const order: string[] = [];

    limiter.schedule(() => {
      order.push('update:start');
      return updatePromise.then(() => { order.push('update:end'); });
    });

    const cancelP = limiter.cancelAndWait();
    await new Promise((r) => setTimeout(r, 20));
    // cancelAndWait should still be waiting for the in-flight update.
    expect(order).toEqual(['update:start']);

    resolveUpdate();
    await cancelP;
    expect(order).toEqual(['update:start', 'update:end']);
  });
});
