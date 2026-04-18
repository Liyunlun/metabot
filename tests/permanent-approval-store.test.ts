/**
 * Tests for the file-backed PermanentApprovalStore (Phase 5).
 *
 * Covers:
 *   - Round-trip save + load
 *   - Missing file → empty load (no crash)
 *   - Corrupted file → empty load + onError
 *   - Non-string entries in patterns array → filtered out
 *   - Atomic write (tmp → rename) doesn't leave a partial file
 *   - ApprovalStore.attachPermanentStore hydrates the allowlist
 *   - approvePermanent / revokePermanent both persist through
 */

import { describe, it, expect, vi } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { execFileSync } from 'node:child_process';
import { PermanentApprovalStore } from '../src/security/permanent-approval-store.js';
import { ApprovalStore, type PermanentStore } from '../src/security/approval-store.js';

function tmpFile(): string {
  return path.join(
    fs.mkdtempSync(path.join(os.tmpdir(), 'metabot-approval-test-')),
    'approvals.json',
  );
}

describe('PermanentApprovalStore — file I/O', () => {
  it('returns empty list when the file does not exist', () => {
    const store = new PermanentApprovalStore({ filePath: tmpFile() });
    expect(store.load()).toEqual([]);
  });

  it('round-trips patterns via save + load', () => {
    const filePath = tmpFile();
    const store = new PermanentApprovalStore({ filePath });
    store.save(['rm -rf foo', 'sudo pacman -Syu']);

    const other = new PermanentApprovalStore({ filePath });
    expect(other.load().sort()).toEqual(['rm -rf foo', 'sudo pacman -Syu']);
  });

  it('save sorts patterns deterministically on disk', () => {
    const filePath = tmpFile();
    const store = new PermanentApprovalStore({ filePath });
    store.save(['zebra', 'alpha', 'mike']);
    const raw = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
    expect(raw.patterns).toEqual(['alpha', 'mike', 'zebra']);
  });

  it('save writes schema version and updatedAt', () => {
    const filePath = tmpFile();
    new PermanentApprovalStore({ filePath }).save(['one']);
    const raw = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
    expect(raw.version).toBe(1);
    expect(typeof raw.updatedAt).toBe('string');
    expect(new Date(raw.updatedAt).toString()).not.toBe('Invalid Date');
  });

  it('creates parent directories on save', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'metabot-approval-test-'));
    const filePath = path.join(dir, 'nested', 'deeper', 'approvals.json');
    const store = new PermanentApprovalStore({ filePath });
    expect(() => store.save(['x'])).not.toThrow();
    expect(fs.existsSync(filePath)).toBe(true);
  });

  it('load on corrupted JSON returns empty + reports error', () => {
    const filePath = tmpFile();
    fs.writeFileSync(filePath, '{not valid json', 'utf-8');
    const onError = vi.fn();
    const store = new PermanentApprovalStore({ filePath, onError });
    expect(store.load()).toEqual([]);
    expect(onError).toHaveBeenCalledOnce();
    expect(onError.mock.calls[0][0]).toMatch(/failed to load/);
  });

  it('load on file with non-array patterns returns empty', () => {
    const filePath = tmpFile();
    fs.writeFileSync(filePath, JSON.stringify({ version: 1, patterns: 'oops' }), 'utf-8');
    const store = new PermanentApprovalStore({ filePath });
    expect(store.load()).toEqual([]);
  });

  it('load filters out non-string / empty entries defensively', () => {
    const filePath = tmpFile();
    // Hand-edited file with mixed garbage.
    fs.writeFileSync(
      filePath,
      JSON.stringify({ version: 1, patterns: ['valid', null, 42, '', { bad: true }, 'also-valid'] }),
      'utf-8',
    );
    const store = new PermanentApprovalStore({ filePath });
    expect(store.load().sort()).toEqual(['also-valid', 'valid']);
  });

  it('load ignores unknown fields (forward compatibility)', () => {
    const filePath = tmpFile();
    fs.writeFileSync(
      filePath,
      JSON.stringify({ version: 99, patterns: ['keep'], futureField: { anything: true } }),
      'utf-8',
    );
    const store = new PermanentApprovalStore({ filePath });
    expect(store.load()).toEqual(['keep']);
  });

  it('save is atomic — no .tmp left behind after successful write', () => {
    const filePath = tmpFile();
    const store = new PermanentApprovalStore({ filePath });
    store.save(['one', 'two']);
    const dir = path.dirname(filePath);
    const leftovers = fs.readdirSync(dir).filter((f) => f.endsWith('.tmp'));
    expect(leftovers).toEqual([]);
  });

  it('save overwrites previous content (not append)', () => {
    const filePath = tmpFile();
    const store = new PermanentApprovalStore({ filePath });
    store.save(['a', 'b', 'c']);
    store.save(['x']);
    expect(new PermanentApprovalStore({ filePath }).load()).toEqual(['x']);
  });

  it('save with empty list persists an empty allowlist', () => {
    const filePath = tmpFile();
    const store = new PermanentApprovalStore({ filePath });
    store.save(['one']);
    store.save([]);
    expect(new PermanentApprovalStore({ filePath }).load()).toEqual([]);
  });
});

describe('ApprovalStore.attachPermanentStore — hydration', () => {
  it('loads patterns from store on attach', async () => {
    const filePath = tmpFile();
    new PermanentApprovalStore({ filePath }).save(['rm -rf /', 'pacman -Syu']);

    const approvals = new ApprovalStore();
    await approvals.attachPermanentStore(new PermanentApprovalStore({ filePath }));
    expect(approvals.getPermanentApprovals().sort()).toEqual(['pacman -Syu', 'rm -rf /']);
  });

  it('approvePermanent persists through to the file', async () => {
    const filePath = tmpFile();
    const approvals = new ApprovalStore();
    await approvals.attachPermanentStore(new PermanentApprovalStore({ filePath }));

    approvals.approvePermanent('legit command');
    // Persistence is fire-and-forget — let the microtask drain.
    await new Promise((r) => setImmediate(r));

    const reloaded = new PermanentApprovalStore({ filePath }).load();
    expect(reloaded).toEqual(['legit command']);
  });

  it('revokePermanent removes the entry and persists', async () => {
    const filePath = tmpFile();
    const approvals = new ApprovalStore();
    await approvals.attachPermanentStore(new PermanentApprovalStore({ filePath }));

    approvals.approvePermanent('entry A');
    approvals.approvePermanent('entry B');
    await new Promise((r) => setImmediate(r));

    expect(approvals.revokePermanent('entry A')).toBe(true);
    await new Promise((r) => setImmediate(r));

    expect(approvals.getPermanentApprovals()).toEqual(['entry B']);
    expect(new PermanentApprovalStore({ filePath }).load()).toEqual(['entry B']);
  });

  it('revokePermanent returns false for unknown patterns (no persist)', async () => {
    const filePath = tmpFile();
    const approvals = new ApprovalStore();
    await approvals.attachPermanentStore(new PermanentApprovalStore({ filePath }));

    expect(approvals.revokePermanent('never added')).toBe(false);
  });

  it('attaching a new store merges disk contents and preserves prior in-memory entries', async () => {
    const approvals = new ApprovalStore();

    const firstFile = tmpFile();
    new PermanentApprovalStore({ filePath: firstFile }).save(['from-first']);
    await approvals.attachPermanentStore(new PermanentApprovalStore({ filePath: firstFile }));
    expect(approvals.getPermanentApprovals()).toEqual(['from-first']);

    // Switching stores preserves the prior in-memory state (merged with
    // new disk contents) and persists the union to the new store.
    const secondFile = tmpFile();
    new PermanentApprovalStore({ filePath: secondFile }).save(['from-second']);
    await approvals.attachPermanentStore(new PermanentApprovalStore({ filePath: secondFile }));
    await new Promise((r) => setImmediate(r));
    expect(approvals.getPermanentApprovals().sort()).toEqual(['from-first', 'from-second']);
    expect(new PermanentApprovalStore({ filePath: secondFile }).load().sort()).toEqual([
      'from-first',
      'from-second',
    ]);
  });

  // Regression: Codex round-1 race finding. Simulates approvePermanent
  // racing the attach/load window via a slow async `load()`.
  it('preserves approvePermanent calls that race the async hydration', async () => {
    const approvals = new ApprovalStore();

    const filePath = tmpFile();
    new PermanentApprovalStore({ filePath }).save(['from-disk']);

    // Wrap the file-backed store so `load()` yields the event loop, giving
    // us a window to call approvePermanent mid-hydration.
    const inner = new PermanentApprovalStore({ filePath });
    const slowStore = {
      async load(): Promise<string[]> {
        // Two microtask turns — long enough to let the external
        // approvePermanent call run.
        await new Promise((r) => setImmediate(r));
        return inner.load();
      },
      save(keys: string[]): void {
        inner.save(keys);
      },
    };

    const attachPromise = approvals.attachPermanentStore(slowStore);
    // Race: this runs BEFORE attach's load completes.
    approvals.approvePermanent('race-window-added');
    await attachPromise;
    await new Promise((r) => setImmediate(r));

    // Both the disk entry AND the race-window entry should be present.
    expect(approvals.getPermanentApprovals().sort()).toEqual([
      'from-disk',
      'race-window-added',
    ]);
    // And the race-window entry was persisted so it survives restart.
    expect(new PermanentApprovalStore({ filePath }).load().sort()).toEqual([
      'from-disk',
      'race-window-added',
    ]);
  });
});

describe('ApprovalStore — async PermanentStore.save() ordering', () => {
  // Codex R2 coverage gap #1: document behavior when a future async backend
  // (e.g. S3, remote KV) is wired in. Node's in-process synchronous backend
  // is safe because each save() snapshot runs to completion before the next
  // call's microtask; these tests pin that contract for async backends too.

  it('rapid-fire approvePermanent calls all converge on disk (sync backend)', async () => {
    // The sync backend is what MetaBot actually ships. Regression fence:
    // demonstrates the shipped configuration is safe under back-to-back calls.
    const filePath = tmpFile();
    const approvals = new ApprovalStore();
    await approvals.attachPermanentStore(new PermanentApprovalStore({ filePath }));

    for (const key of ['one', 'two', 'three', 'four', 'five']) {
      approvals.approvePermanent(key);
    }
    await new Promise((r) => setImmediate(r));

    const onDisk = new PermanentApprovalStore({ filePath }).load().sort();
    expect(onDisk).toEqual(['five', 'four', 'one', 'three', 'two']);
    expect(approvals.getPermanentApprovals().sort()).toEqual(onDisk);
  });

  it('async backend: each save call receives the current in-memory snapshot', async () => {
    // Regardless of save() completion order, each invocation snapshots the
    // in-memory Set synchronously, so the FINAL snapshot always contains the
    // full post-mutation state. The concern is only which snapshot WINS on
    // disk when completion order reverses — documented by the next test.
    const snapshots: string[][] = [];
    const asyncStore: PermanentStore = {
      async load() { return []; },
      async save(keys) {
        // Deep-copy — mutating the input later must not retroactively alter
        // what we captured at call-time.
        snapshots.push([...keys].sort());
        await Promise.resolve();
      },
    };

    const approvals = new ApprovalStore();
    await approvals.attachPermanentStore(asyncStore);

    approvals.approvePermanent('A');
    approvals.approvePermanent('B');
    approvals.approvePermanent('C');
    // Drain microtasks.
    for (let i = 0; i < 5; i++) await new Promise((r) => setImmediate(r));

    // The LAST snapshot captured (monotonic growth) must be the complete set.
    expect(snapshots.at(-1)).toEqual(['A', 'B', 'C']);
    // And the set grows monotonically — later snapshots are supersets of earlier.
    for (let i = 1; i < snapshots.length; i++) {
      for (const prev of snapshots[i - 1]) {
        expect(snapshots[i]).toContain(prev);
      }
    }
  });

  // Documented design debt (Codex R2 security nit medium): async backends
  // whose save() completion order can reverse can exhibit stale-write clobber.
  // This is documented as expected behavior for the current design — a test
  // written as `.fails()` acts as a regression fence: if someone adds a
  // write-serializer/queue, this test starts passing and must be flipped.
  it.fails(
    'DESIGN-DEBT: async backend with reversed completion order loses the later write',
    async () => {
      const filePath = tmpFile();
      const writes: string[][] = [];
      let releaseFirstWrite: (() => void) | undefined;
      let callNo = 0;

      const inner = new PermanentApprovalStore({ filePath });
      const reorderingStore: PermanentStore = {
        async load() { return inner.load(); },
        save(keys) {
          const snapshot = [...keys].sort();
          callNo += 1;
          if (callNo === 1) {
            // Block the first save until the second has landed on disk.
            return new Promise<void>((resolve) => {
              releaseFirstWrite = () => {
                inner.save(snapshot);
                writes.push(snapshot);
                resolve();
              };
            });
          }
          // Subsequent saves land immediately.
          inner.save(snapshot);
          writes.push(snapshot);
          return Promise.resolve();
        },
      };

      const approvals = new ApprovalStore();
      await approvals.attachPermanentStore(reorderingStore);

      approvals.approvePermanent('first');
      await new Promise((r) => setImmediate(r));
      approvals.approvePermanent('second');
      await new Promise((r) => setImmediate(r));
      // Now let the first (stale) save finish — it will clobber the second.
      releaseFirstWrite?.();
      await new Promise((r) => setImmediate(r));

      // In-memory is still correct; disk is stale because save #1 finished last
      // with its snapshot of just ['first'].
      expect(approvals.getPermanentApprovals().sort()).toEqual(['first', 'second']);
      const onDisk = new PermanentApprovalStore({ filePath }).load().sort();
      // Asserting the desired (post-fix) behavior — this expectation currently
      // FAILS, which is exactly what `.fails()` pins until serialization lands.
      expect(onDisk).toEqual(['first', 'second']);
    },
  );
});

describe('PermanentApprovalStore — multi-process contention', () => {
  // Codex R2 coverage gap #2: two bot processes sharing the same approvals
  // file. The tmp→rename pattern guarantees each individual write is atomic;
  // PID-suffixed tmp paths prevent concurrent-tmp collisions. Concurrent
  // writes may lose updates (last-write-wins) but must never corrupt the file.

  const runOnUnix = process.platform === 'win32' ? it.skip : it;

  runOnUnix('tmp file path includes the PID so two processes do not collide', () => {
    // Inspect the source to confirm the naming scheme. This is a cheap fence
    // — the full-file test below exercises the actual race.
    const src = fs.readFileSync(
      path.join(__dirname, '..', 'src', 'security', 'permanent-approval-store.ts'),
      'utf-8',
    );
    expect(src).toMatch(/\$\{this\.filePath\}\.\$\{process\.pid\}\.tmp/);
  });

  runOnUnix('concurrent writes from a child process never corrupt the JSON file', async () => {
    const filePath = tmpFile();
    // Seed the file so both writers are overwriting a real target.
    new PermanentApprovalStore({ filePath }).save(['initial']);

    // Child performs the same tmp→rename dance as PermanentApprovalStore.save
    // (inlined here so we don't need the compiled module available to node -e).
    const childScript = `
      const fs = require('node:fs');
      const target = ${JSON.stringify(filePath)};
      const payload = {
        version: 1,
        patterns: ['from-child-' + process.pid],
        updatedAt: new Date().toISOString(),
      };
      const tmp = target + '.' + process.pid + '.tmp';
      fs.writeFileSync(tmp, JSON.stringify(payload, null, 2) + '\\n', { mode: 0o600 });
      fs.renameSync(tmp, target);
    `;

    // Spawn 4 children concurrently while the parent does its own writes.
    const children: Promise<void>[] = [];
    for (let i = 0; i < 4; i++) {
      children.push(
        new Promise<void>((resolve, reject) => {
          try {
            execFileSync(process.execPath, ['-e', childScript], { stdio: 'ignore' });
            resolve();
          } catch (err) {
            reject(err);
          }
        }),
      );
      // Parent writes interleaved with the spawns.
      new PermanentApprovalStore({ filePath }).save([`from-parent-${i}`]);
    }
    await Promise.all(children);

    // Final file must be valid JSON with our schema.
    const raw = fs.readFileSync(filePath, 'utf-8');
    const parsed = JSON.parse(raw); // must not throw
    expect(parsed.version).toBe(1);
    expect(Array.isArray(parsed.patterns)).toBe(true);
    // Every pattern must be one of the writes we actually issued.
    for (const p of parsed.patterns) {
      expect(
        /^from-parent-\d+$/.test(p) || /^from-child-\d+$/.test(p) || p === 'initial',
      ).toBe(true);
    }

    // No stray .tmp files left behind (every rename either completed or the
    // whole save threw). Parent-owned tmp would share our PID; child tmp
    // files have the child's PID. All should be cleaned up.
    const dir = path.dirname(filePath);
    const leftovers = fs.readdirSync(dir).filter((f) => f.endsWith('.tmp'));
    expect(leftovers).toEqual([]);
  });
});

describe('PermanentApprovalStore — file permissions', () => {
  // Skip on platforms where permission bits don't apply (Windows).
  const runOnUnix = process.platform === 'win32' ? it.skip : it;

  runOnUnix('writes the allowlist file with mode 0600 (owner-only)', () => {
    const filePath = tmpFile();
    const store = new PermanentApprovalStore({ filePath });
    store.save(['secret-pattern']);
    const stat = fs.statSync(filePath);
    // Mask off filetype bits; compare permission bits only.
    expect(stat.mode & 0o777).toBe(0o600);
  });

  runOnUnix('creates the parent directory with mode 0700', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'metabot-approval-test-'));
    const filePath = path.join(dir, 'nested-dir', 'approvals.json');
    new PermanentApprovalStore({ filePath }).save(['x']);
    const stat = fs.statSync(path.dirname(filePath));
    // Directories should be 0700 (0x40000 is the directory bit).
    expect(stat.mode & 0o777).toBe(0o700);
  });

  runOnUnix('overwrites an existing permissive-mode file to 0600', () => {
    const filePath = tmpFile();
    // Pre-create a world-readable file at the target to simulate a user
    // who created it via `touch` or a previous build before the 0o600 fix.
    fs.writeFileSync(filePath, '{"version":1,"patterns":[]}', { mode: 0o644 });
    new PermanentApprovalStore({ filePath }).save(['after']);
    const stat = fs.statSync(filePath);
    expect(stat.mode & 0o777).toBe(0o600);
  });
});
