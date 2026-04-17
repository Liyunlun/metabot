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
