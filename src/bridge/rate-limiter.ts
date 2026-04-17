export class RateLimiter {
  private pending: (() => unknown | Promise<unknown>) | null = null;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private lastSent = 0;
  // Cumulative promise representing "all thunks ever fired that have not
  // been awaited-through by flush/cancelAndWait yet". We chain every fired
  // thunk into this so the ordering guarantee holds even when thunk A is
  // still in-flight while thunk B fires on a later immediate-path call
  // (thunk duration > intervalMs). Without this chaining, inFlight would
  // only track the last thunk and flush() could return while an older
  // stale update is still landing on the server — the bug that made
  // multi-turn frozen cards revert to thinking/running state.
  private inFlight: Promise<unknown> = Promise.resolve();

  constructor(private intervalMs: number = 1500) {}

  // Thunks may return a value or a Promise. For ordering guarantees (see
  // `flush`), callers that want the server side to quiesce must return the
  // underlying Promise from the thunk; a thunk returning undefined will still
  // throttle correctly but offers no ordering guarantee for its work.
  schedule(fn: () => unknown | Promise<unknown>): void {
    const now = Date.now();
    const elapsed = now - this.lastSent;

    if (elapsed >= this.intervalMs) {
      // Can send immediately
      this.lastSent = now;
      this.track(fn());
    } else {
      // Queue for later, replacing any pending update
      this.pending = fn;

      if (!this.timer) {
        const delay = this.intervalMs - elapsed;
        this.timer = setTimeout(() => {
          this.timer = null;
          if (this.pending) {
            this.lastSent = Date.now();
            const pendingFn = this.pending;
            this.pending = null;
            this.track(pendingFn());
          }
        }, delay);
      }
    }
  }

  /**
   * Chain this thunk's result into the cumulative inFlight promise so flush()
   * waits for every unsettled thunk, not just the latest. Thunks still
   * execute concurrently on the network; the chain is only for tracking.
   * Each individual promise is `.catch`-ed to undefined so a rejected thunk
   * never leaves inFlight in a rejected state (which would poison flush and
   * potentially surface as an unhandled rejection).
   */
  private track(result: unknown | Promise<unknown>): void {
    const p = Promise.resolve(result).catch(() => undefined);
    this.inFlight = Promise.all([this.inFlight, p]).then(() => undefined);
  }

  async flush(): Promise<void> {
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    if (this.pending) {
      const fn = this.pending;
      this.pending = null;
      this.lastSent = Date.now();
      this.track(fn());
    }
    // Snapshot the cumulative promise before awaiting so a concurrent
    // schedule() can extend inFlight without us clobbering its work.
    const snapshot = this.inFlight;
    await snapshot;
    if (this.inFlight === snapshot) {
      this.inFlight = Promise.resolve();
    }
  }

  /** Discard any pending update without executing it. */
  cancel(): void {
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    this.pending = null;
  }

  /**
   * Cancel pending update and wait until enough time has passed since the last
   * successfully sent update. Also awaits all in-flight thunks so the next
   * direct send can't lose an ordering race with any of them.
   */
  async cancelAndWait(): Promise<void> {
    this.cancel();
    const snapshot = this.inFlight;
    await snapshot;
    if (this.inFlight === snapshot) {
      this.inFlight = Promise.resolve();
    }
    const elapsed = Date.now() - this.lastSent;
    if (elapsed < this.intervalMs) {
      await new Promise((r) => setTimeout(r, this.intervalMs - elapsed));
    }
  }
}
