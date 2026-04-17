/**
 * Hard blacklist — commands so catastrophic that an LLM classifier cannot
 * be trusted to judge them. These bypass smart approval entirely and always
 * go straight to the Phase 3 user-approval card.
 *
 * MetaBot-specific safety layer (Hermes doesn't have this); rationale: Sonnet
 * rarely but occasionally approves extreme commands when the pattern reason
 * looks benign in isolation. For the very top of the risk distribution —
 * unrecoverable disk/filesystem ops and fork bombs — we want humans in the
 * loop unconditionally.
 *
 * Patterns operate on the *normalized* command (ANSI-stripped, NFKC) so
 * obfuscation via escape sequences or Unicode homoglyphs doesn't bypass
 * them. Callers must pass the normalized form (see
 * `normalizeCommandForDetection` in `dangerous-patterns.ts`).
 */

/**
 * Regex list matched against the normalized command.
 *
 * Keep this list TIGHT — every entry here permanently denies the user the
 * "smart auto-allow" experience for commands that match it. The bar for
 * inclusion is: "a false approval here could wipe a disk, destroy the
 * filesystem, or render the machine unreachable."
 */
const HARD_BLACKLIST_PATTERNS: ReadonlyArray<{ regex: RegExp; reason: string }> = [
  // rm -rf / (and trailing-slash variants). We match a bare `/` as the only
  // argument (plus optional trailing comment) to avoid catching legitimate
  // paths like `rm -rf /tmp/foo` — those go through the pattern detector
  // and smart approval as usual.
  //
  // The flag group accepts:
  //   - short clusters   (-rf, -Rf, -r, -f, -rv …)
  //   - long flags       (--recursive, --force, --no-preserve-root, …)
  //   - POSIX end-of-options (--)
  // Covers variants like `rm -rf /`, `rm -rf -- /`, `rm --recursive /`,
  // `rm --no-preserve-root -rf /`, `rm --recursive --force /`.
  {
    regex: /^\s*rm\s+(?:(?:-[a-zA-Z]+|--[a-zA-Z][a-zA-Z-]*|--)\s+)+\/\s*(?:#.*)?$/,
    reason: 'rm -rf / (root filesystem delete)',
  },
  {
    regex: /^\s*rm\s+(?:(?:-[a-zA-Z]+|--[a-zA-Z][a-zA-Z-]*|--)\s+)+\/\*\s*(?:#.*)?$/,
    reason: 'rm -rf /* (root glob delete)',
  },

  // dd writing to a raw block device — classic "disk wipe" shape. Covers
  // /dev/sdX, /dev/nvmeXnY, /dev/hdX, /dev/vdX, /dev/xvdX.
  { regex: /\bdd\b[^\n]*\bof\s*=\s*\/dev\/(?:sd|nvme|hd|vd|xvd)/, reason: 'dd to raw block device' },

  // Classic bash fork bomb — no legitimate use. Tolerates whitespace
  // variants the normalizer may not collapse.
  { regex: /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/, reason: 'fork bomb' },

  // mkfs on a real device path. `mkfs.ext4 disk.img` (file image) is not
  // caught — that's handled by the pattern set + smart approval.
  { regex: /\bmkfs(?:\.[a-z0-9]+)?\s+\/dev\//, reason: 'mkfs on /dev/*' },
];

export interface HardBlacklistResult {
  blacklisted: boolean;
  /** Human-readable reason (for audit logs); only set when blacklisted. */
  reason?: string;
}

/**
 * Check whether a (normalized) command matches any hard-blacklist pattern.
 * Callers should pass the output of `normalizeCommandForDetection()` to
 * neutralize ANSI / Unicode obfuscation before calling.
 */
export function isHardBlacklisted(normalizedCommand: string): HardBlacklistResult {
  for (const { regex, reason } of HARD_BLACKLIST_PATTERNS) {
    if (regex.test(normalizedCommand)) {
      return { blacklisted: true, reason };
    }
  }
  return { blacklisted: false };
}
