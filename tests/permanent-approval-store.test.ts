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
import { PermanentApprovalStore } from '../src/security/permanent-approval-store.js';
import { ApprovalStore } from '../src/security/approval-store.js';

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

  it('attaching a new store replaces the existing allowlist from disk', async () => {
    const approvals = new ApprovalStore();

    const firstFile = tmpFile();
    new PermanentApprovalStore({ filePath: firstFile }).save(['from-first']);
    await approvals.attachPermanentStore(new PermanentApprovalStore({ filePath: firstFile }));
    expect(approvals.getPermanentApprovals()).toEqual(['from-first']);

    const secondFile = tmpFile();
    new PermanentApprovalStore({ filePath: secondFile }).save(['from-second']);
    await approvals.attachPermanentStore(new PermanentApprovalStore({ filePath: secondFile }));
    expect(approvals.getPermanentApprovals()).toEqual(['from-second']);
  });
});
