/**
 * Dangerous command detection — pattern list + normalization.
 *
 * 1:1 port of Hermes Agent's `tools/approval.py` DANGEROUS_PATTERNS plus
 * `_normalize_command_for_detection` (ANSI strip + NFKC + null-byte removal).
 *
 * Source: https://github.com/NousResearch/hermes-agent/blob/main/tools/approval.py
 *
 * This module is intentionally **pure** — no approval state, no UI, no IO.
 * It answers one question: "does this command string match any dangerous
 * pattern, and if so, which one?" Everything else (four-tier approval,
 * Feishu cards, Smart Approval via Haiku) lives in sibling modules.
 */

// ---------------------------------------------------------------------------
// Sensitive write targets — referenced by several patterns below.
// ---------------------------------------------------------------------------

const SSH_SENSITIVE_PATH = String.raw`(?:~|\$home|\$\{home\})/\.ssh(?:/|$)`;

const METABOT_ENV_PATH =
  String.raw`(?:~\/\.metabot/|` +
  String.raw`(?:\$home|\$\{home\})/\.metabot/|` +
  String.raw`(?:\$metabot_home|\$\{metabot_home\})/)` +
  String.raw`\.env\b`;

const SENSITIVE_WRITE_TARGET =
  String.raw`(?:/etc/|/dev/sd|` +
  SSH_SENSITIVE_PATH +
  String.raw`|` +
  METABOT_ENV_PATH +
  String.raw`)`;

// ---------------------------------------------------------------------------
// Dangerous pattern list. Each entry is [regex source, human description].
// Matching is performed case-insensitive with dotall semantics (see detect).
// Ordering matches Hermes for ease of cross-referencing.
// ---------------------------------------------------------------------------

export interface DangerousPattern {
  /** Regex source string (no leading/trailing slashes). */
  regex: string;
  /** Human-readable description — also used as the canonical approval key. */
  description: string;
}

export const DANGEROUS_PATTERNS: DangerousPattern[] = [
  { regex: String.raw`\brm\s+(-[^\s]*\s+)*/`, description: 'delete in root path' },
  { regex: String.raw`\brm\s+-[^\s]*r`, description: 'recursive delete' },
  { regex: String.raw`\brm\s+--recursive\b`, description: 'recursive delete (long flag)' },
  {
    regex: String.raw`\bchmod\s+(-[^\s]*\s+)*(777|666|o\+[rwx]*w|a\+[rwx]*w)\b`,
    description: 'world/other-writable permissions',
  },
  {
    regex: String.raw`\bchmod\s+--recursive\b.*(777|666|o\+[rwx]*w|a\+[rwx]*w)`,
    description: 'recursive world/other-writable (long flag)',
  },
  { regex: String.raw`\bchown\s+(-[^\s]*)?R\s+root`, description: 'recursive chown to root' },
  { regex: String.raw`\bchown\s+--recursive\b.*root`, description: 'recursive chown to root (long flag)' },
  { regex: String.raw`\bmkfs\b`, description: 'format filesystem' },
  { regex: String.raw`\bdd\s+.*if=`, description: 'disk copy' },
  { regex: String.raw`>\s*/dev/sd`, description: 'write to block device' },
  { regex: String.raw`\bDROP\s+(TABLE|DATABASE)\b`, description: 'SQL DROP' },
  { regex: String.raw`\bDELETE\s+FROM\b(?!.*\bWHERE\b)`, description: 'SQL DELETE without WHERE' },
  { regex: String.raw`\bTRUNCATE\s+(TABLE)?\s*\w`, description: 'SQL TRUNCATE' },
  { regex: String.raw`>\s*/etc/`, description: 'overwrite system config' },
  {
    regex: String.raw`\bsystemctl\s+(-[^\s]+\s+)*(stop|restart|disable|mask)\b`,
    description: 'stop/restart system service',
  },
  { regex: String.raw`\bkill\s+-9\s+-1\b`, description: 'kill all processes' },
  { regex: String.raw`\bpkill\s+-9\b`, description: 'force kill processes' },
  { regex: String.raw`:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:`, description: 'fork bomb' },
  {
    regex: String.raw`\b(bash|sh|zsh|ksh)\s+-[^\s]*c(\s+|$)`,
    description: 'shell command via -c/-lc flag',
  },
  {
    regex: String.raw`\b(python[23]?|perl|ruby|node)\s+-[ec]\s+`,
    description: 'script execution via -e/-c flag',
  },
  { regex: String.raw`\b(curl|wget)\b.*\|\s*(ba)?sh\b`, description: 'pipe remote content to shell' },
  {
    regex: String.raw`\b(bash|sh|zsh|ksh)\s+<\s*<?\s*\(\s*(curl|wget)\b`,
    description: 'execute remote script via process substitution',
  },
  {
    regex: String.raw`\btee\b.*["']?` + SENSITIVE_WRITE_TARGET,
    description: 'overwrite system file via tee',
  },
  {
    regex: String.raw`>>?\s*["']?` + SENSITIVE_WRITE_TARGET,
    description: 'overwrite system file via redirection',
  },
  { regex: String.raw`\bxargs\s+.*\brm\b`, description: 'xargs with rm' },
  { regex: String.raw`\bfind\b.*-exec\s+(/\S*/)?rm\b`, description: 'find -exec rm' },
  { regex: String.raw`\bfind\b.*-delete\b`, description: 'find -delete' },

  // MetaBot lifecycle protection: prevent the agent from killing its own
  // gateway/pm2 process. Hermes protects `hermes gateway stop/restart`;
  // we protect `pm2 stop/restart metabot` and `metabot` process kills.
  {
    regex: String.raw`\bpm2\s+(stop|restart|delete|kill)\b.*\bmetabot\b`,
    description: 'stop/restart metabot via pm2 (kills running agents)',
  },
  {
    regex: String.raw`\b(pkill|killall)\b.*\bmetabot\b`,
    description: 'kill metabot process (self-termination)',
  },
  {
    regex: String.raw`\bkill\b.*\$\(\s*pgrep\b`,
    description: 'kill process via pgrep expansion (self-termination)',
  },
  {
    regex: String.raw`\bkill\b.*\`\s*pgrep\b`,
    description: 'kill process via backtick pgrep expansion (self-termination)',
  },

  // File copy/move/edit into sensitive system paths
  { regex: String.raw`\b(cp|mv|install)\b.*\s/etc/`, description: 'copy/move file into /etc/' },
  { regex: String.raw`\bsed\s+-[^\s]*i.*\s/etc/`, description: 'in-place edit of system config' },
  {
    regex: String.raw`\bsed\s+--in-place\b.*\s/etc/`,
    description: 'in-place edit of system config (long flag)',
  },

  // Script execution via heredoc — bypasses the -e/-c flag patterns above.
  {
    regex: String.raw`\b(python[23]?|perl|ruby|node)\s+<<`,
    description: 'script execution via heredoc',
  },

  // Git destructive operations
  { regex: String.raw`\bgit\s+reset\s+--hard\b`, description: 'git reset --hard (destroys uncommitted changes)' },
  { regex: String.raw`\bgit\s+push\b.*--force\b`, description: 'git force push (rewrites remote history)' },
  { regex: String.raw`\bgit\s+push\b.*-f\b`, description: 'git force push short flag (rewrites remote history)' },
  { regex: String.raw`\bgit\s+clean\s+-[^\s]*f`, description: 'git clean with force (deletes untracked files)' },
  { regex: String.raw`\bgit\s+branch\s+-D\b`, description: 'git branch force delete' },

  // Script execution after chmod +x
  {
    regex: String.raw`\bchmod\s+\+x\b.*[;&|]+\s*\./`,
    description: 'chmod +x followed by immediate execution',
  },
];

// ---------------------------------------------------------------------------
// Normalization — strips ANSI escapes, null bytes, and applies Unicode NFKC
// so that obfuscation techniques (fullwidth Latin, ANSI-colored binaries,
// null-byte injection) cannot bypass pattern detection.
// ---------------------------------------------------------------------------

/**
 * ECMA-48 compliant ANSI escape stripper. Covers:
 *  - CSI sequences: `ESC [ ... final-byte`
 *  - OSC sequences: `ESC ] ... BEL` or `ESC ] ... ESC \`
 *  - DCS / SOS / PM / APC: `ESC P/X/^/_ ... ESC \`
 *  - Single-char escapes: `ESC <any>` (cursor, charset, etc.)
 *  - 8-bit C1 controls: `\x9B` (CSI), `\x9D` (OSC), etc.
 */
/* eslint-disable no-control-regex -- this function's entire purpose is to match control bytes */
function stripAnsi(input: string): string {
  // Handle 8-bit C1 controls first by mapping them to their 7-bit equivalents
  // so the subsequent regex passes catch them uniformly.
  let s = input
    .replace(/\x9B/g, '\x1B[')
    .replace(/\x9D/g, '\x1B]')
    .replace(/\x90/g, '\x1BP')
    .replace(/\x98/g, '\x1BX')
    .replace(/\x9E/g, '\x1B^')
    .replace(/\x9F/g, '\x1B_');

  // OSC: ESC ] ... (BEL | ESC \)
  s = s.replace(/\x1B\][\s\S]*?(?:\x07|\x1B\\)/g, '');
  // DCS / SOS / PM / APC: ESC P/X/^/_ ... ESC \
  s = s.replace(/\x1B[PX^_][\s\S]*?\x1B\\/g, '');
  // CSI: ESC [ <params> <final-byte 0x40-0x7E>
  s = s.replace(/\x1B\[[\x30-\x3F]*[\x20-\x2F]*[\x40-\x7E]/g, '');
  // Remaining single-char escapes: ESC <byte>
  s = s.replace(/\x1B[@-Z\\-_]/g, '');

  return s;
}
/* eslint-enable no-control-regex */

/**
 * Normalize a command string before dangerous-pattern matching.
 *
 *  1. Strip ANSI escape sequences (so colored output can't hide patterns).
 *  2. Remove null bytes (defends against `rm\x00 -rf /`).
 *  3. Unicode NFKC normalization (fullwidth `ｒｍ` → `rm`, compatibility
 *     decomposition of lookalike chars).
 *
 * Mirrors Hermes `_normalize_command_for_detection`.
 */
export function normalizeCommandForDetection(command: string): string {
  let out = stripAnsi(command);
  // eslint-disable-next-line no-control-regex -- null-byte stripping is the whole point
  out = out.replace(/\x00/g, '');
  out = out.normalize('NFKC');
  return out;
}

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

export interface DangerousMatch {
  matched: true;
  /** Canonical approval key (same as `description`). */
  patternKey: string;
  /** Human-readable description of the matched pattern. */
  description: string;
  /** The regex source that matched (useful for debugging/logging). */
  regex: string;
}

export interface NoDangerousMatch {
  matched: false;
}

export type DetectResult = DangerousMatch | NoDangerousMatch;

/**
 * Check whether `command` matches any dangerous pattern.
 *
 * Matching happens on the normalized, lowercased string with case-insensitive
 * and dotall semantics — matching Hermes exactly. Returns the *first* match
 * (list ordering is intentional — most specific patterns come first).
 */
export function detectDangerousCommand(command: string): DetectResult {
  const normalized = normalizeCommandForDetection(command).toLowerCase();
  for (const { regex, description } of DANGEROUS_PATTERNS) {
    // `s` flag = dotall (mirrors Python re.DOTALL).
    // `i` flag is technically redundant since we lowercased, but preserving
    // it matches Hermes exactly and is harmless.
    const re = new RegExp(regex, 'is');
    if (re.test(normalized)) {
      return { matched: true, patternKey: description, description, regex };
    }
  }
  return { matched: false };
}
