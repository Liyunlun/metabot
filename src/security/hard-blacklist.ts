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

    // Absolute-path invocation of a blacklisted command: `/bin/rm -rf /`,
    // `/usr/bin/dd ...`, `/sbin/mkfs.ext4 ...`. The real binary is resolved
    // by the path, not by $PATH; peel the directory so the regexes see the
    // bare command name. Only peel the common system bin dirs — arbitrary
    // paths could hint at a non-standard wrapper (a `my-rm` in some dev
    // checkout is not guaranteed to behave like `rm`).
    s = s.replace(
      /^(?:\/usr\/local\/bin\/|\/usr\/local\/sbin\/|\/usr\/bin\/|\/usr\/sbin\/|\/bin\/|\/sbin\/)(?=(?:rm|dd|mkfs(?:\.[a-z0-9]+)?)(?:\s|$))/,
      '',
    );

    // BusyBox / Toybox multi-call wrappers: `busybox rm -rf /`, `toybox dd …`.
    // The first arg is the applet name (which is the real operation), so the
    // wrapper is transparent w.r.t. the payload.
    s = s.replace(/^(?:busybox|toybox)\s+(?=(?:rm|dd|mkfs(?:\.[a-z0-9]+)?)(?:\s|$))/, '');

    // `exec` — shell builtin that replaces the current process with the
    // following command; transparent for our purposes. Strip optional flags.
    s = s.replace(/^exec(?:\s+-[aclins]+)?\s+/, '');

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
/**
 * Match a root-sentinel argument: `/`, `"/"`, `'/'`, `/.`, `/*`. Used in
 * `rm -rf <args>` detection so the pattern fires whether `/` appears as the
 * sole arg, the first of several (`rm -rf / tmp` — still catastrophic),
 * anywhere in the line, or in a quoted form. `/.` and `/./` are caught
 * because `rm` resolves them to the root directory.
 */
const ROOT_ARG_RE = /(?:"\/"|'\/'|\/\.?\/?|\/\*)/.source;

const HARD_BLACKLIST_PATTERNS: ReadonlyArray<{ regex: RegExp; reason: string }> = [
  // rm -rf / (and variants). We match when ANY argument token is a root
  // sentinel (`/`, `"/"`, `'/'`, `/.`, `/*`) so the pattern fires even when
  // the user slipped an extra positional arg in (`rm -rf / tmp` — still
  // catastrophic) or quoted the root (`rm -rf "/"`). Benign paths like
  // `rm -rf /tmp/foo` don't match because the token has more characters
  // after `/`.
  //
  // The flag group accepts:
  //   - short clusters   (-rf, -Rf, -r, -f, -rv …)
  //   - long flags       (--recursive, --force, --no-preserve-root, …)
  //   - POSIX end-of-options (--)
  // Covers variants like `rm -rf /`, `rm -rf -- /`, `rm --recursive /`,
  // `rm --no-preserve-root -rf /`, `rm --recursive --force /`, and
  // wrapper-prefixed forms like `sudo rm -rf /`, `/bin/rm -rf /`,
  // `busybox rm -rf /` (all via stripCommandPrefix).
  {
    regex: new RegExp(
      // Require at least one flag (so `rm /` without `-r` doesn't match —
      // that's a different pattern class). Then look for a root-sentinel
      // arg anywhere in the remaining command line, delimited by whitespace,
      // EOL, or a comment. Other positional args (safe or not) are allowed
      // before/after it.
      `^\\s*rm(?:\\s+(?:-[a-zA-Z]+|--[a-zA-Z][a-zA-Z-]*|--))+(?:\\s+(?!(?:-|#))\\S+)*\\s+${ROOT_ARG_RE}(?:\\s|$|#)`,
    ),
    reason: 'rm -rf / (root filesystem delete)',
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

  // M4 — dd/mkfs with a /dev/<device> path anywhere in the line, in EITHER
  // order. Catches the shell-variable bypass (`target=/dev/sda; dd of=$target`
  // or `bash -c "X=/dev/sda dd of=$X"`) by requiring both a dd/mkfs token
  // AND a literal `/dev/<unsafe>` in the line without forcing them to be
  // syntactically adjacent. Accepts the catastrophic-devices list negated so
  // `echo /dev/null | dd …` stays out. A residual false-positive class
  // exists (e.g. a comment like `# saw /dev/sda once` next to an unrelated
  // `dd if=/tmp/foo`), but for catastrophic ops we prefer false positives
  // over silent bypasses — a prompted human resolves it in one tap.
  {
    // dd/mkfs BEFORE /dev/<unsafe>
    regex: /\b(?:dd|mkfs(?:\.[a-z0-9]+)?)\b[^\n]*?\/dev\/(?!(?:null|zero|stdin|stdout|stderr|tty|full|random|urandom)\b)[a-z]/i,
    reason: 'dd/mkfs co-located with /dev/* (possible shell-var indirection)',
  },
  {
    // /dev/<unsafe> BEFORE dd/mkfs — covers variable-assignment-then-use
    // (`T=/dev/sda; dd of=$T`) and `bash -c` payloads where the unsafe path
    // precedes the destructive token.
    regex: /\/dev\/(?!(?:null|zero|stdin|stdout|stderr|tty|full|random|urandom)\b)[a-z][^\n]*?\b(?:dd|mkfs(?:\.[a-z0-9]+)?)\b/i,
    reason: 'dd/mkfs co-located with /dev/* (possible shell-var indirection)',
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
