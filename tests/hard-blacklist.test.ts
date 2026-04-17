import { describe, it, expect } from 'vitest';
import { isHardBlacklisted } from '../src/security/hard-blacklist.js';
import { normalizeCommandForDetection } from '../src/security/dangerous-patterns.js';

/** Convenience: pipe through the normalizer first, just like production. */
const check = (cmd: string) => isHardBlacklisted(normalizeCommandForDetection(cmd));

describe('hard blacklist — rm -rf / variants', () => {
  it('catches bare `rm -rf /`', () => {
    expect(check('rm -rf /').blacklisted).toBe(true);
  });

  it('catches `rm -rf /` with trailing comment', () => {
    expect(check('rm -rf /   # cleanup').blacklisted).toBe(true);
  });

  it('catches `rm -rf /*`', () => {
    expect(check('rm -rf /*').blacklisted).toBe(true);
  });

  it('catches `rm -Rf /` (uppercase R)', () => {
    expect(check('rm -Rf /').blacklisted).toBe(true);
  });

  // Flag-variant coverage (Codex round-2 finding: previous regex missed these).
  it('catches `rm -rf -- /` (POSIX end-of-options)', () => {
    expect(check('rm -rf -- /').blacklisted).toBe(true);
  });

  it('catches `rm --recursive /` (long flag)', () => {
    expect(check('rm --recursive /').blacklisted).toBe(true);
  });

  it('catches `rm --recursive --force /` (multiple long flags)', () => {
    expect(check('rm --recursive --force /').blacklisted).toBe(true);
  });

  it('catches `rm --no-preserve-root -rf /` (hyphenated long flag)', () => {
    expect(check('rm --no-preserve-root -rf /').blacklisted).toBe(true);
  });

  it('catches `rm -r -f -- /*` (split short flags + end-of-options on root glob)', () => {
    expect(check('rm -r -f -- /*').blacklisted).toBe(true);
  });

  it('does NOT catch `rm -rf /tmp/foo`', () => {
    expect(check('rm -rf /tmp/foo').blacklisted).toBe(false);
  });

  it('does NOT catch `rm -rf ./build`', () => {
    expect(check('rm -rf ./build').blacklisted).toBe(false);
  });

  it('does NOT catch `rm --recursive /tmp/foo`', () => {
    expect(check('rm --recursive /tmp/foo').blacklisted).toBe(false);
  });
});

describe('hard blacklist — dd to raw block devices', () => {
  it('catches dd if=/dev/zero of=/dev/sda', () => {
    expect(check('dd if=/dev/zero of=/dev/sda').blacklisted).toBe(true);
  });

  it('catches dd of=/dev/nvme0n1', () => {
    expect(check('dd if=/dev/urandom of=/dev/nvme0n1 bs=1M').blacklisted).toBe(true);
  });

  it('catches dd of=/dev/hdb1', () => {
    expect(check('dd if=image.iso of=/dev/hdb1').blacklisted).toBe(true);
  });

  it('does NOT catch dd writing to a regular file', () => {
    expect(check('dd if=input.img of=output.img bs=4M').blacklisted).toBe(false);
  });

  it('does NOT catch dd writing to /dev/null', () => {
    expect(check('dd if=/dev/zero of=/dev/null count=1').blacklisted).toBe(false);
  });
});

describe('hard blacklist — fork bomb', () => {
  it('catches the canonical bash fork bomb', () => {
    expect(check(':(){ :|:& };:').blacklisted).toBe(true);
  });

  it('catches whitespace variants', () => {
    expect(check(': ( ) { : | : & } ; :').blacklisted).toBe(true);
  });
});

describe('hard blacklist — mkfs on devices', () => {
  it('catches mkfs.ext4 /dev/sdb1', () => {
    expect(check('mkfs.ext4 /dev/sdb1').blacklisted).toBe(true);
  });

  it('catches bare mkfs /dev/sdc', () => {
    expect(check('mkfs /dev/sdc').blacklisted).toBe(true);
  });

  it('does NOT catch mkfs on a loopback image file', () => {
    expect(check('mkfs.ext4 disk.img').blacklisted).toBe(false);
  });

  // Codex round-11 finding — mkfs with option flags before the device.
  it('catches `mkfs -t ext4 /dev/sda` (-t flag + fstype)', () => {
    expect(check('mkfs -t ext4 /dev/sda').blacklisted).toBe(true);
  });

  it('catches `mkfs -t ext4 -F /dev/sda` (multiple flags)', () => {
    expect(check('mkfs -t ext4 -F /dev/sda').blacklisted).toBe(true);
  });

  it('catches `mkfs --type=ext4 /dev/sda` (long flag with value)', () => {
    expect(check('mkfs --type=ext4 /dev/sda').blacklisted).toBe(true);
  });

  it('catches `mkfs.ext4 -F /dev/sda` (typed mkfs with flag)', () => {
    expect(check('mkfs.ext4 -F /dev/sda').blacklisted).toBe(true);
  });

  // Codex round-12 finding — space-separated long-flag value.
  it('catches `mkfs --type ext4 /dev/sda` (GNU long-flag spacing)', () => {
    expect(check('mkfs --type ext4 /dev/sda').blacklisted).toBe(true);
  });

  it('catches `mkfs --type ext4 -L label /dev/sda` (long + short with values)', () => {
    expect(check('mkfs --type ext4 -L label /dev/sda').blacklisted).toBe(true);
  });
});

describe('hard blacklist — obfuscation resistance via normalization', () => {
  it('catches fullwidth-letter rm -rf / after NFKC normalization', () => {
    // "ｒｍ -ｒｆ /" — fullwidth Latin letters collapse to ASCII
    expect(check('ｒｍ -ｒｆ /').blacklisted).toBe(true);
  });

  it('catches ANSI-colored rm -rf / after escape-stripping', () => {
    // Red-colored `rm` with reset at the end
    expect(check('\x1b[31mrm\x1b[0m -rf /').blacklisted).toBe(true);
  });
});

describe('hard blacklist — unrelated commands stay clear', () => {
  it('does not flag `ls /`', () => {
    expect(check('ls /').blacklisted).toBe(false);
  });

  it('does not flag `echo hello`', () => {
    expect(check('echo hello').blacklisted).toBe(false);
  });

  it('does not flag `python -c "print(1)"`', () => {
    expect(check('python -c "print(1)"').blacklisted).toBe(false);
  });
});

// Codex round-4 findings — wrapper-prefix bypass, quoted devices,
// broader block-device list, mixed-case env scrub.
describe('hard blacklist — wrapper-prefix bypass (Codex round 4)', () => {
  it('catches `sudo rm -rf /`', () => {
    expect(check('sudo rm -rf /').blacklisted).toBe(true);
  });

  it('catches `sudo -E rm -rf /` (sudo with flags)', () => {
    expect(check('sudo -E rm -rf /').blacklisted).toBe(true);
  });

  it('catches `sudo -u root rm -rf /` (sudo with -u user)', () => {
    expect(check('sudo -u root rm -rf /').blacklisted).toBe(true);
  });

  it('catches `env FOO=bar dd if=/dev/zero of=/dev/sda`', () => {
    expect(check('env FOO=bar dd if=/dev/zero of=/dev/sda').blacklisted).toBe(true);
  });

  it('catches bare KEY=VAL prefix (`FOO=bar rm -rf /`)', () => {
    expect(check('FOO=bar rm -rf /').blacklisted).toBe(true);
  });

  it('catches chained wrappers (`sudo -E env PATH=/bin nice rm -rf /`)', () => {
    expect(check('sudo -E env PATH=/bin nice rm -rf /').blacklisted).toBe(true);
  });

  it('catches `nohup rm -rf /`', () => {
    expect(check('nohup rm -rf /').blacklisted).toBe(true);
  });

  it('catches `timeout 10 rm -rf /`', () => {
    expect(check('timeout 10 rm -rf /').blacklisted).toBe(true);
  });

  it('catches `\\rm -rf /` (backslash alias bypass)', () => {
    expect(check('\\rm -rf /').blacklisted).toBe(true);
  });

  it('catches `sudo mkfs.ext4 /dev/sda`', () => {
    expect(check('sudo mkfs.ext4 /dev/sda').blacklisted).toBe(true);
  });

  it('does NOT catch `sudo ls /tmp` (wrapper over benign cmd)', () => {
    expect(check('sudo ls /tmp').blacklisted).toBe(false);
  });

  it('does NOT catch `env FOO=bar echo hello`', () => {
    expect(check('env FOO=bar echo hello').blacklisted).toBe(false);
  });

  // Codex round-5 findings — end-of-options `--` after wrapper and
  // quoted KEY=VAL values.
  it('catches `sudo -- rm -rf /` (end-of-options after sudo)', () => {
    expect(check('sudo -- rm -rf /').blacklisted).toBe(true);
  });

  it('catches `sudo -E -- rm -rf /` (flag + end-of-options)', () => {
    expect(check('sudo -E -- rm -rf /').blacklisted).toBe(true);
  });

  it('catches `env -- dd if=/dev/zero of=/dev/sda`', () => {
    expect(check('env -- dd if=/dev/zero of=/dev/sda').blacklisted).toBe(true);
  });

  it('catches `env FOO=bar -- rm -rf /` (assignments then --)', () => {
    expect(check('env FOO=bar -- rm -rf /').blacklisted).toBe(true);
  });

  it("catches `FOO='a b' rm -rf /` (single-quoted KEY=VAL)", () => {
    expect(check("FOO='a b' rm -rf /").blacklisted).toBe(true);
  });

  it('catches `FOO="a b" rm -rf /` (double-quoted KEY=VAL)', () => {
    expect(check('FOO="a b" rm -rf /').blacklisted).toBe(true);
  });

  it("catches `env FOO='x y' rm -rf /` (env + quoted value)", () => {
    expect(check("env FOO='x y' rm -rf /").blacklisted).toBe(true);
  });

  // Codex nit — concatenated shell words (quoted atom + unquoted atom).
  // Regex uses a zero-or-more atom sequence; these assert it handles the
  // concatenation forms and doesn't stop at the closing quote.
  it("catches `FOO='a b'c rm -rf /` (single-quoted + unquoted concat)", () => {
    expect(check("FOO='a b'c rm -rf /").blacklisted).toBe(true);
  });

  it('catches `FOO="a b"c rm -rf /` (double-quoted + unquoted concat)', () => {
    expect(check('FOO="a b"c rm -rf /').blacklisted).toBe(true);
  });

  it("catches `env FOO=\"x y\"z rm -rf /` (env + double-quoted concat)", () => {
    expect(check('env FOO="x y"z rm -rf /').blacklisted).toBe(true);
  });

  it("catches `env FOO='x y'z rm -rf /` (env + single-quoted concat)", () => {
    expect(check("env FOO='x y'z rm -rf /").blacklisted).toBe(true);
  });

  it("catches `FOO=a'b c'd rm -rf /` (unquoted + quoted + unquoted concat)", () => {
    expect(check("FOO=a'b c'd rm -rf /").blacklisted).toBe(true);
  });

  it('catches `FOO="a"\'b\'c rm -rf /` (double + single + unquoted concat)', () => {
    expect(check('FOO="a"\'b\'c rm -rf /').blacklisted).toBe(true);
  });

  // Codex round-5 nit — claimed wrappers need actual tests.
  it('catches `command rm -rf /`', () => {
    expect(check('command rm -rf /').blacklisted).toBe(true);
  });

  it('catches `time rm -rf /`', () => {
    expect(check('time rm -rf /').blacklisted).toBe(true);
  });

  it('catches `ionice -c 3 rm -rf /`', () => {
    expect(check('ionice -c 3 rm -rf /').blacklisted).toBe(true);
  });

  it('catches `taskset 0x1 rm -rf /`', () => {
    expect(check('taskset 0x1 rm -rf /').blacklisted).toBe(true);
  });

  it('catches `chrt -r 99 rm -rf /`', () => {
    expect(check('chrt -r 99 rm -rf /').blacklisted).toBe(true);
  });

  it('catches `stdbuf -oL rm -rf /`', () => {
    expect(check('stdbuf -oL rm -rf /').blacklisted).toBe(true);
  });

  // Codex round-8 nit — `--` end-of-options form for command/nohup/time wrappers.
  it('catches `command -- rm -rf /`', () => {
    expect(check('command -- rm -rf /').blacklisted).toBe(true);
  });

  it('catches `nohup -- rm -rf /`', () => {
    expect(check('nohup -- rm -rf /').blacklisted).toBe(true);
  });

  it('catches `time -- rm -rf /`', () => {
    expect(check('time -- rm -rf /').blacklisted).toBe(true);
  });

  // Codex round-6 finding — concatenated shell word value
  // (`FOO='a b'c` = value `a bc` after shell concatenation).
  it("catches `FOO='a b'c rm -rf /` (concatenated quoted+bare value)", () => {
    expect(check("FOO='a b'c rm -rf /").blacklisted).toBe(true);
  });

  it('catches `FOO="a b"c rm -rf /` (concatenated double-quoted+bare value)', () => {
    expect(check('FOO="a b"c rm -rf /').blacklisted).toBe(true);
  });

  it("catches `env FOO='x y'z rm -rf /` (env + concatenated value)", () => {
    expect(check("env FOO='x y'z rm -rf /").blacklisted).toBe(true);
  });

  it("catches `A='x'\"y\" rm -rf /` (single-quoted + double-quoted adjacent atoms)", () => {
    // Shell concatenates adjacent quoted segments into one word, so the
    // value here is `xy`. The regex must eat the whole assignment so
    // `rm` becomes the first token.
    expect(check("A='x'\"y\" rm -rf /").blacklisted).toBe(true);
  });

  // Codex round-7 finding — backslash-escaped space in KEY=VAL.
  it("catches `FOO=a\\ bc rm -rf /` (backslash-escaped space in value)", () => {
    expect(check('FOO=a\\ bc rm -rf /').blacklisted).toBe(true);
  });

  it("catches `env FOO=a\\ bc rm -rf /` (env + backslash-escaped space)", () => {
    expect(check('env FOO=a\\ bc rm -rf /').blacklisted).toBe(true);
  });

  it("catches `FOO=a\\'b rm -rf /` (backslash-escaped quote in value)", () => {
    expect(check("FOO=a\\'b rm -rf /").blacklisted).toBe(true);
  });

  // Codex round-8 finding — `--` end-of-options after transparent wrappers.
  it('catches `command -- rm -rf /`', () => {
    expect(check('command -- rm -rf /').blacklisted).toBe(true);
  });

  it('catches `nohup -- rm -rf /`', () => {
    expect(check('nohup -- rm -rf /').blacklisted).toBe(true);
  });

  it('catches `time -- rm -rf /`', () => {
    expect(check('time -- rm -rf /').blacklisted).toBe(true);
  });

  // Codex round-9 findings — `time -p` (POSIX format) and timeout with
  // value-taking options.
  it('catches `time -p rm -rf /` (POSIX time format)', () => {
    expect(check('time -p rm -rf /').blacklisted).toBe(true);
  });

  it('catches `time -v rm -rf /` (GNU verbose)', () => {
    expect(check('time -v rm -rf /').blacklisted).toBe(true);
  });

  it('catches `time --verbose rm -rf /`', () => {
    expect(check('time --verbose rm -rf /').blacklisted).toBe(true);
  });

  it('catches `timeout -k 5s 30s rm -rf /` (kill-after)', () => {
    expect(check('timeout -k 5s 30s rm -rf /').blacklisted).toBe(true);
  });

  it('catches `timeout --signal KILL 30s rm -rf /` (long flag with value)', () => {
    expect(check('timeout --signal KILL 30s rm -rf /').blacklisted).toBe(true);
  });

  it('catches `timeout --signal=KILL 30s rm -rf /` (long flag = value)', () => {
    expect(check('timeout --signal=KILL 30s rm -rf /').blacklisted).toBe(true);
  });

  it('catches `timeout --preserve-status 30s rm -rf /` (boolean long flag)', () => {
    expect(check('timeout --preserve-status 30s rm -rf /').blacklisted).toBe(true);
  });

  // Codex round-10 finding — attached short-arg spellings for timeout.
  it('catches `timeout -k5s 30s rm -rf /` (attached -k value)', () => {
    expect(check('timeout -k5s 30s rm -rf /').blacklisted).toBe(true);
  });

  it('catches `timeout -sKILL 30s rm -rf /` (attached -s value)', () => {
    expect(check('timeout -sKILL 30s rm -rf /').blacklisted).toBe(true);
  });

  // Codex round-13 finding — bare `--` end-of-options before timeout duration.
  it('catches `timeout -- 30s rm -rf /` (end-of-options before duration)', () => {
    expect(check('timeout -- 30s rm -rf /').blacklisted).toBe(true);
  });

  it('catches `timeout --preserve-status -- 30s rm -rf /` (flag + --)', () => {
    expect(check('timeout --preserve-status -- 30s rm -rf /').blacklisted).toBe(true);
  });

  // Codex round-14 nit — benign controls for the broadened wrapper regexes,
  // ensuring the sudo long-flag and `timeout --` peel doesn't false-positive
  // on harmless payloads.
  it('does NOT catch `sudo --non-interactive ls /tmp` (benign after long flag)', () => {
    expect(check('sudo --non-interactive ls /tmp').blacklisted).toBe(false);
  });

  it('does NOT catch `sudo --user root ls /tmp` (benign after --user VAL)', () => {
    expect(check('sudo --user root ls /tmp').blacklisted).toBe(false);
  });

  it('does NOT catch `timeout -- 30s echo ok` (benign after timeout --)', () => {
    expect(check('timeout -- 30s echo ok').blacklisted).toBe(false);
  });

  it('does NOT catch `timeout --preserve-status -- 30s ls /tmp`', () => {
    expect(check('timeout --preserve-status -- 30s ls /tmp').blacklisted).toBe(false);
  });

  it('does NOT catch `env --unset PATH ls /tmp` (benign after env long flag)', () => {
    expect(check('env --unset PATH ls /tmp').blacklisted).toBe(false);
  });

  // Codex round-12 finding — env long flags.
  it('catches `env --ignore-environment rm -rf /` (env long boolean flag)', () => {
    expect(check('env --ignore-environment rm -rf /').blacklisted).toBe(true);
  });

  it('catches `env --unset PATH rm -rf /` (env --unset with space value)', () => {
    expect(check('env --unset PATH rm -rf /').blacklisted).toBe(true);
  });

  it('catches `env --unset=PATH rm -rf /` (env --unset=value)', () => {
    expect(check('env --unset=PATH rm -rf /').blacklisted).toBe(true);
  });

  // Codex round-13 findings — sudo long options, timeout bare --.
  it('catches `sudo --user root rm -rf /` (sudo long flag with value)', () => {
    expect(check('sudo --user root rm -rf /').blacklisted).toBe(true);
  });

  it('catches `sudo --user=root rm -rf /` (sudo --user=value)', () => {
    expect(check('sudo --user=root rm -rf /').blacklisted).toBe(true);
  });

  it('catches `sudo --non-interactive rm -rf /` (sudo boolean long flag)', () => {
    expect(check('sudo --non-interactive rm -rf /').blacklisted).toBe(true);
  });

  it('catches `sudo --non-interactive mkfs.ext4 /dev/sda`', () => {
    expect(check('sudo --non-interactive mkfs.ext4 /dev/sda').blacklisted).toBe(true);
  });

  it('catches `timeout -- 30s rm -rf /` (timeout bare end-of-options)', () => {
    expect(check('timeout -- 30s rm -rf /').blacklisted).toBe(true);
  });

  // Codex round-14 nit — negative controls for the broadened wrapper
  // regexes to guard against over-stripping regressions.
  it('does NOT catch `sudo --non-interactive ls /tmp`', () => {
    expect(check('sudo --non-interactive ls /tmp').blacklisted).toBe(false);
  });

  it('does NOT catch `sudo --user root ls /tmp`', () => {
    expect(check('sudo --user root ls /tmp').blacklisted).toBe(false);
  });

  it('does NOT catch `timeout -- 30s echo ok`', () => {
    expect(check('timeout -- 30s echo ok').blacklisted).toBe(false);
  });

  it('does NOT catch `env --ignore-environment ls /tmp`', () => {
    expect(check('env --ignore-environment ls /tmp').blacklisted).toBe(false);
  });

  it('does NOT catch `mkfs --type ext4 disk.img` (loopback image, not device)', () => {
    expect(check('mkfs --type ext4 disk.img').blacklisted).toBe(false);
  });
});

describe('hard blacklist — quoted device paths (Codex round 4)', () => {
  it('catches `mkfs.ext4 "/dev/sda"` (double-quoted)', () => {
    expect(check('mkfs.ext4 "/dev/sda"').blacklisted).toBe(true);
  });

  it("catches `mkfs.ext4 '/dev/sda'` (single-quoted)", () => {
    expect(check("mkfs.ext4 '/dev/sda'").blacklisted).toBe(true);
  });

  it('catches `dd if=/dev/zero of="/dev/sda"` (quoted dd target)', () => {
    expect(check('dd if=/dev/zero of="/dev/sda"').blacklisted).toBe(true);
  });
});

describe('hard blacklist — broader block-device list (Codex round 4)', () => {
  it('catches dd of=/dev/dm-0 (LVM/device-mapper)', () => {
    expect(check('dd if=/dev/zero of=/dev/dm-0 bs=1M').blacklisted).toBe(true);
  });

  it('catches dd of=/dev/md0 (mdraid)', () => {
    expect(check('dd if=/dev/zero of=/dev/md0').blacklisted).toBe(true);
  });

  it('catches dd of=/dev/mmcblk0 (eMMC/SD)', () => {
    expect(check('dd if=/dev/zero of=/dev/mmcblk0').blacklisted).toBe(true);
  });

  it('catches dd of=/dev/mapper/vg0-root (LVM mapper)', () => {
    expect(check('dd if=/dev/zero of=/dev/mapper/vg0-root').blacklisted).toBe(true);
  });

  it('catches dd of=/dev/loop0 (loopback device)', () => {
    expect(check('dd if=image.iso of=/dev/loop0').blacklisted).toBe(true);
  });

  it('does NOT catch dd of=/dev/stdout', () => {
    expect(check('dd if=input of=/dev/stdout').blacklisted).toBe(false);
  });

  it('does NOT catch dd of=/dev/stderr', () => {
    expect(check('dd if=input of=/dev/stderr').blacklisted).toBe(false);
  });

  it('does NOT catch dd of=/dev/tty', () => {
    expect(check('dd if=input of=/dev/tty').blacklisted).toBe(false);
  });
});

describe('hard blacklist — reason string is human readable', () => {
  it('returns a description when blacklisted', () => {
    const r = check('rm -rf /');
    expect(r.blacklisted).toBe(true);
    expect(r.reason).toMatch(/root filesystem/i);
  });

  it('returns undefined reason when not blacklisted', () => {
    const r = check('ls -la');
    expect(r.blacklisted).toBe(false);
    expect(r.reason).toBeUndefined();
  });
});
