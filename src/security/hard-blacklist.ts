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
 * Strip harmless command wrappers from the front of a command line so the
 * hard-blacklist regexes see the real operation. Without this, a caller
 * can trivially bypass the blacklist with `sudo rm -rf /` or
 * `env FOO=bar dd of=/dev/sda …`, because the regexes that care about the
 * first token (rm, dd, mkfs) wouldn't match.
 *
 * We only peel wrappers that DO NOT change what the inner command does —
 * `sudo` escalates but the inner command's filesystem effect is unchanged;
 * `env VAR=val` sets environment but doesn't substitute the command; `nice`,
 * `nohup`, `timeout`, `stdbuf`, `taskset`, `chrt`, `ionice`, `command`, and
 * shell builtin `time` are all transparent w.r.t. the destructive payload.
 *
 * Aliased forms like `\rm` (leading backslash bypasses shell aliases but
 * executes the same binary) are also peeled.
 *
 * We iterate so stacks like `sudo -E env PATH=/bin nice rm -rf /` reduce
 * all the way down.
 */
function stripCommandPrefix(cmd: string): string {
  let s = cmd.trimStart();
  // Bounded loop — attacker cannot make us spin; each iteration either
  // strips at least one char or breaks.
  for (let i = 0; i < 16; i++) {
    const before = s;

    // `\rm`, `\dd`, `\mkfs.ext4` — leading backslash bypasses shell aliases
    // but executes the same binary. Strip the backslash so the regexes match.
    s = s.replace(/^\\(?=[a-zA-Z])/, '');

    // sudo [flags] [--]  — bare boolean flags (-E, -n, -i, -s, -b, -H, -A,
    // -k, -K) plus value-taking flags (-u USER, -g GROUP, -p PROMPT, -C FD,
    // -R CHROOT, -T TIMEOUT, -h HOST, -t TYPE, -r ROLE). Trailing `--`
    // (POSIX end-of-options) is optional.
    s = s.replace(
      // Sudo flags split into three classes so we don't greedily eat the
      // real command as a flag value:
      //   (1) Value-taking short flags: -u, -g, -p, -C, -R, -T, -h, -t, -r
      //   (2) Value-taking long flags (whitelist): --user, --group,
      //       --prompt, --chroot, --host, --type, --role, --close-from,
      //       --other-user, --shell (each accepts `=VAL` or `\s+VAL`)
      //   (3) All other flags (boolean): short cluster `-[a-zA-Z]+`,
      //       long `--word[=val]` without space-separated value
      // Using `\s+VAL` on every long flag would eat `rm -rf /` after
      // `sudo --non-interactive rm -rf /`, so the whitelist is load-bearing.
      /^sudo(?:\s+(?:-[ugpCRThtr]\s+\S+|--(?:user|group|prompt|chroot|host|type|role|close-from|other-user|shell)(?:=\S+|\s+\S+)|--[a-zA-Z][a-zA-Z-]*(?:=\S+)?|-[a-zA-Z]+))*(?:\s+--)?\s+/,
      '',
    );

    // env [-flags] [-u NAME] [KEY=VALUE ...] [--]  — peel env invocation,
    // value-taking `-u NAME`, KEY=VALUE assignments (including quoted
    // values like `FOO='a b'` or `FOO="hello"`), and an optional trailing
    // `--`.
    s = s.replace(
      // The value is a sequence of atoms: single-quoted, double-quoted,
      // backslash-escaped char, or bare non-space/non-quote runs. This
      // matches the shell's word concatenation rule, so `FOO='a b'c`,
      // `FOO="x y"z`, and `FOO=a\ bc` (value = `a bc`) are all peeled
      // as a single prefix rather than leaving adjacent text stuck to
      // the payload.
      /^env(?:\s+(?:-u\s+\S+|--unset(?:=\S+|\s+\S+)|-[a-zA-Z]+|--[a-zA-Z][a-zA-Z-]*(?:=\S+)?))*(?:\s+[A-Za-z_][A-Za-z0-9_]*=(?:'[^']*'|"[^"]*"|\\.|[^\s'"\\])*)*(?:\s+--)?\s+/,
      '',
    );

    // Bare KEY=VALUE assignments without `env` — POSIX allows this as
    // a shell prefix (`FOO=bar BAZ=qux rm -rf /`). The value is a
    // concatenation of single-quoted, double-quoted, backslash-escaped,
    // and bare atoms, e.g. `FOO='a b'c` or `FOO=a\ bc`; accept any
    // sequence of such atoms.
    s = s.replace(/^[A-Za-z_][A-Za-z0-9_]*=(?:'[^']*'|"[^"]*"|\\.|[^\s'"\\])*\s+/, '');

    // Transparent wrappers that take flags+args then hand off to the real cmd.
    // `nice -n 10`, `ionice -c 3`, `timeout 5s`, `timeout --preserve-status 5`,
    // `taskset 0x1`, `chrt -r 99`, `stdbuf -oL`, `nohup`, `command`, `time`.
    // `command [--]`, `nohup [--]` — peel with optional end-of-options.
    s = s.replace(/^(?:nohup|command)(?:\s+--)?\s+/, '');
    // `time` — POSIX/GNU flags (`-p`, `-v`, `--portability`, `--verbose`).
    // Allow any sequence of short/long boolean flags plus optional `--`.
    s = s.replace(/^time(?:\s+(?:-[a-zA-Z]+|--[a-zA-Z][a-zA-Z-]*))*(?:\s+--)?\s+/, '');
    s = s.replace(/^nice(?:\s+-n\s*-?\d+|\s+-\d+)?\s+/, '');
    s = s.replace(/^ionice(?:\s+-[cnt]\s*\d+|\s+-[cnt]\d+)*\s+/, '');
    // `timeout [OPTIONS] DURATION` — value-taking options `-k DURATION`,
    // `-s SIGNAL`, `--kill-after[=|SP]VAL`, `--signal[=|SP]VAL`, plus
    // boolean flags (`--preserve-status`, `--foreground`, `-v`).
    s = s.replace(
      // Short value-taking flags accept both detached (`-k 5s`) and
      // attached (`-k5s`) spellings — `\s*` instead of `\s+` handles both
      // without breaking when the flag value is a separate token. Optional
      // bare `--` end-of-options before the duration argument.
      /^timeout(?:\s+(?:-[ks]\s*\S+|--kill-after(?:=\S+|\s+\S+)|--signal(?:=\S+|\s+\S+)|-[a-zA-Z]+|--[a-zA-Z][a-zA-Z-]*))*(?:\s+--)?\s+\S+\s+/,
      '',
    );
    s = s.replace(/^taskset(?:\s+-[a-zA-Z]+)?\s+\S+\s+/, '');
    s = s.replace(/^chrt(?:\s+-[a-zA-Z]+)*(?:\s+-?\d+)?\s+/, '');
    s = s.replace(/^stdbuf(?:\s+-[ioe]\s*\S+)+\s+/, '');

    if (s === before) break;
  }
  return s;
}

/**
 * Regex list matched against the *wrapper-stripped, normalized* command.
 *
 * Keep this list TIGHT — every entry here permanently denies the user the
 * "smart auto-allow" experience for commands that match it. The bar for
 * inclusion is: "a false approval here could wipe a disk, destroy the
 * filesystem, or render the machine unreachable."
 *
 * All regexes run on the stripped command, so `^` means "the first token
 * of the real operation", not "absolute start of user input".
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
  // `rm --no-preserve-root -rf /`, `rm --recursive --force /`, and
  // wrapper-prefixed forms like `sudo rm -rf /` (via stripCommandPrefix).
  {
    regex: /^\s*rm\s+(?:(?:-[a-zA-Z]+|--[a-zA-Z][a-zA-Z-]*|--)\s+)+\/\s*(?:#.*)?$/,
    reason: 'rm -rf / (root filesystem delete)',
  },
  {
    regex: /^\s*rm\s+(?:(?:-[a-zA-Z]+|--[a-zA-Z][a-zA-Z-]*|--)\s+)+\/\*\s*(?:#.*)?$/,
    reason: 'rm -rf /* (root glob delete)',
  },

  // dd writing to a real block device. Negative-list approach: any
  // `/dev/<x>` is catastrophic EXCEPT a small safe set (null, zero,
  // stdin/stdout/stderr, tty, random/urandom, full) — writing to those is
  // either harmless or nonsensical-but-safe. Covers /dev/sdX, /dev/nvmeXnY,
  // /dev/dm-0, /dev/md0, /dev/mmcblk0, /dev/mapper/*, /dev/loopX, /dev/disk0,
  // /dev/hdX, /dev/vdX, /dev/xvdX, etc. Accepts optional quotes around the
  // device path (single, double, or none).
  {
    regex: /\bdd\b[^\n]*\bof\s*=\s*['"]?\/dev\/(?!(?:null|zero|stdin|stdout|stderr|tty|full|random|urandom)(?:['"]?(?:\s|$)))/,
    reason: 'dd to raw block device',
  },

  // Classic bash fork bomb — no legitimate use. Tolerates whitespace
  // variants the normalizer may not collapse.
  { regex: /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/, reason: 'fork bomb' },

  // mkfs on a real device path. `mkfs.ext4 disk.img` (file image) is not
  // caught — that's handled by the pattern set + smart approval. Accepts
  // optional flags (`-t ext4`, `-F`, `--type=ext4`) between mkfs and the
  // device, and optional quoting, so `mkfs -t ext4 /dev/sda`,
  // `mkfs.ext4 "/dev/sda"`, and `mkfs --type=ext4 /dev/sda` are all caught.
  {
    // Flag clusters accept both `=VALUE` and space-separated `VALUE` forms
    // for short (`-t ext4`) and long (`--type ext4`, `--type=ext4`) options,
    // as well as boolean-only flags (`-F`, `--force`). Regex backtracking
    // handles the case where the device path would otherwise be consumed
    // as a flag value.
    regex: /\bmkfs(?:\.[a-z0-9]+)?(?:\s+(?:-[a-zA-Z]+(?:=\S+|\s+\S+)?|--[a-zA-Z][a-zA-Z-]*(?:=\S+|\s+\S+)?))*\s+['"]?\/dev\//,
    reason: 'mkfs on /dev/*',
  },
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
 *
 * Wrappers (`sudo`, `env KEY=val`, `nice`, `timeout`, …) are peeled from the
 * front before pattern matching, so `sudo rm -rf /` and `env FOO=bar dd
 * of=/dev/sda` are caught the same as the bare forms. We test both the
 * stripped and original command so patterns that intentionally look at the
 * original shape (e.g. fork bomb embedded mid-line) still fire.
 */
export function isHardBlacklisted(normalizedCommand: string): HardBlacklistResult {
  const stripped = stripCommandPrefix(normalizedCommand);
  for (const { regex, reason } of HARD_BLACKLIST_PATTERNS) {
    if (regex.test(stripped) || regex.test(normalizedCommand)) {
      return { blacklisted: true, reason };
    }
  }
  return { blacklisted: false };
}
