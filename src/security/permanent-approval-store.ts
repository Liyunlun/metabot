/**
 * File-backed implementation of the `PermanentStore` contract from
 * `approval-store.ts`. Persists the permanent-allowlist pattern keys across
 * bot restarts so a user's `/approve always` decisions survive reboot.
 *
 * Hermes parallel: `load_permanent_allowlist` / `save_permanent_allowlist`
 * in `tools/approval.py` (backed by `config.yaml["command_allowlist"]`).
 * We use a standalone JSON file under `~/.metabot/` because MetaBot's
 * config format is TypeScript `config.ts`, not YAML.
 *
 * File schema (stable, forward-compatible via `version`):
 *
 *     {
 *       "version": 1,
 *       "patterns": ["rm -rf …", "sudo pacman …"],
 *       "updatedAt": "2026-04-18T12:34:56.789Z"
 *     }
 *
 * Writes are atomic via `tmp → rename`, so a crash mid-save cannot leave a
 * partial file. Corrupted or unreadable files are treated as empty + logged
 * (fail-open for load, fail-closed for save — safer defaults for an
 * allowlist: a lost allowlist re-prompts the user; a silent load-failure
 * that pretended patterns existed would be worse).
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import type { PermanentStore } from './approval-store.js';

/** Schema version — bump if the file format changes incompatibly. */
const CURRENT_VERSION = 1;

/**
 * JSON shape written to disk. Unknown/future fields are ignored on load so
 * rollbacks work across minor version bumps.
 */
interface PersistedFile {
  version: number;
  patterns: string[];
  updatedAt?: string;
}

export interface PermanentApprovalStoreOptions {
  /**
   * Override the on-disk path. Defaults to `~/.metabot/approvals.json`.
   * Tests pass a tmpdir path to avoid touching the real user directory.
   */
  filePath?: string;
  /** Optional logger — called on load/save failures. */
  onError?: (message: string, err: unknown) => void;
}

const DEFAULT_FILE = path.join(os.homedir(), '.metabot', 'approvals.json');

export class PermanentApprovalStore implements PermanentStore {
  private readonly filePath: string;
  private readonly onError: (message: string, err: unknown) => void;

  constructor(options: PermanentApprovalStoreOptions = {}) {
    this.filePath = options.filePath ?? DEFAULT_FILE;
    this.onError =
      options.onError ??
      ((message, err) => {
        // Fallback to stderr so boot-time issues are visible even without a
        // pino logger; production call sites pass a logger-backed onError.
        console.error(`[permanent-approval-store] ${message}`, err);
      });
  }

  /** Synchronous read — called once at startup before the bot serves traffic. */
  load(): string[] {
    try {
      if (!fs.existsSync(this.filePath)) return [];
      const raw = fs.readFileSync(this.filePath, 'utf-8');
      const parsed = JSON.parse(raw) as Partial<PersistedFile>;
      if (!parsed || !Array.isArray(parsed.patterns)) return [];
      // Filter out non-string entries defensively — a hand-edited file could
      // contain nulls/objects that would otherwise flow into the allowlist.
      return parsed.patterns.filter((p): p is string => typeof p === 'string' && p.length > 0);
    } catch (err) {
      this.onError('failed to load permanent approvals', err);
      return [];
    }
  }

  /**
   * Atomic write — serialize to a sibling tmp file then rename over the
   * target. Ensures a crash/kill during save cannot corrupt the existing
   * allowlist.
   *
   * Permissions: file is written with mode `0o600` (owner-only read/write)
   * and the containing directory is created `0o700`. The allowlist reflects
   * the user's security decisions and can include command patterns that
   * reveal intent ("sudo pacman -Syu", "rm -rf /home/me/proj") — treat it
   * as sensitive and keep it out of group/world read.
   */
  save(keys: string[]): void {
    const payload: PersistedFile = {
      version: CURRENT_VERSION,
      patterns: [...keys].sort(),
      updatedAt: new Date().toISOString(),
    };
    const dir = path.dirname(this.filePath);
    try {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      const tmp = `${this.filePath}.${process.pid}.tmp`;
      // Pass mode explicitly — without it, the created file inherits
      // `0o666 & ~umask` (0o644 on typical systems), making the allowlist
      // world-readable.
      fs.writeFileSync(tmp, `${JSON.stringify(payload, null, 2)}\n`, {
        encoding: 'utf-8',
        mode: 0o600,
      });
      fs.renameSync(tmp, this.filePath);
      // If the rename inherited permissive perms from a pre-existing file
      // (renames preserve the destination's mode on some platforms), force
      // 0o600. chmod is a no-op if already 0o600.
      try {
        fs.chmodSync(this.filePath, 0o600);
      } catch {
        // Ignore chmod failures — the write itself succeeded.
      }
    } catch (err) {
      this.onError('failed to save permanent approvals', err);
      // Re-throw so approvalStore.savePermanent's catch can log at that layer
      // too. The allowlist in memory is still correct; just not persisted.
      throw err;
    }
  }
}
