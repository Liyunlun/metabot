/**
 * Full ECMA-48 ANSI escape sequence stripper.
 *
 * 1:1 port of Hermes Agent's `tools/ansi_strip.py` so that
 * `dangerous-patterns.ts` normalization matches Hermes exactly.
 *
 * Covers:
 *   - CSI sequences (incl. private-mode `?`, colon params, intermediates)
 *   - OSC (BEL `\x07` and ST `ESC \` terminators)
 *   - DCS / SOS / PM / APC string sequences
 *   - nF multi-byte escapes (ESC + intermediates 0x20-0x2f + final 0x30-0x7e)
 *   - Fp / Fe / Fs single-byte escapes
 *   - 8-bit CSI (`0x9B ...`)
 *   - 8-bit OSC (`0x9D ... BEL|0x9C`)
 *   - Any stray 8-bit C1 control (`0x80-0x9F`)
 *
 * Source: https://github.com/NousResearch/hermes-agent/blob/main/tools/ansi_strip.py
 */

/* eslint-disable no-control-regex -- this module's entire job is matching control bytes */

const ANSI_ESCAPE_RE = new RegExp(
  [
    '\\x1b',
    '(?:',
    '\\[[\\x30-\\x3f]*[\\x20-\\x2f]*[\\x40-\\x7e]', // CSI sequence
    '|\\][\\s\\S]*?(?:\\x07|\\x1b\\\\)', //           OSC (BEL or ST)
    '|[PX^_][\\s\\S]*?(?:\\x1b\\\\)', //              DCS / SOS / PM / APC
    '|[\\x20-\\x2f]+[\\x30-\\x7e]', //                 nF escape sequences
    '|[\\x30-\\x7e]', //                                Fp/Fe/Fs single-byte
    ')',
    '|\\x9b[\\x30-\\x3f]*[\\x20-\\x2f]*[\\x40-\\x7e]', // 8-bit CSI
    '|\\x9d[\\s\\S]*?(?:\\x07|\\x9c)', //                 8-bit OSC
    '|[\\x80-\\x9f]', //                                   other 8-bit C1
  ].join(''),
  'g',
);

// Fast-path: skip regex entirely when no ESC or 8-bit C1 bytes are present.
const HAS_ESCAPE_RE = /[\x1b\x80-\x9f]/;

/**
 * Remove ANSI escape sequences from `text`.
 *
 * Returns the input unchanged on the fast path (no ESC or C1 bytes present),
 * so it is cheap to call defensively on any string.
 */
export function stripAnsi(text: string): string {
  if (!text || !HAS_ESCAPE_RE.test(text)) return text;
  return text.replace(ANSI_ESCAPE_RE, '');
}

/* eslint-enable no-control-regex */
