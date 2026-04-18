import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { SDKMessage } from '@anthropic-ai/claude-agent-sdk';
import {
  SmartApprovalClassifier,
  buildClassifierPrompt,
  buildExplainPrompt,
  parseVerdict,
  parseClassifierResponse,
  parseExplanationResponse,
  buildClassifierEnv,
  type QueryFn,
  type Logger,
} from '../src/security/smart-approval.js';

function makeLogger(): Logger {
  return { info: vi.fn(), warn: vi.fn(), error: vi.fn() };
}

/** Canned stream producing a single assistant text response, then a result terminator. */
function cannedStream(text: string): AsyncIterable<SDKMessage> {
  async function* gen(): AsyncGenerator<SDKMessage> {
    yield {
      type: 'assistant',
      message: { content: [{ type: 'text', text }] },
    } as unknown as SDKMessage;
    yield { type: 'result' } as unknown as SDKMessage;
  }
  return gen();
}

/** Stream that blocks forever — used to drive the timeout path. */
function hangingStream(abort: AbortController): AsyncIterable<SDKMessage> {
  return {
    [Symbol.asyncIterator](): AsyncIterator<SDKMessage> {
      return {
        next(): Promise<IteratorResult<SDKMessage>> {
          return new Promise((_, reject) => {
            abort.signal.addEventListener('abort', () => reject(new Error('AbortError')));
          });
        },
      };
    },
  };
}

const REQ = { command: 'python -c "print(1)"', description: 'script via -c', cwd: '/tmp/x' };

describe('buildClassifierPrompt', () => {
  it('includes command, description, and working directory', () => {
    const p = buildClassifierPrompt({
      command: 'rm -rf /tmp/foo',
      description: 'recursive delete',
      cwd: '/home/user/proj',
    });
    expect(p).toContain('Command: rm -rf /tmp/foo');
    expect(p).toContain('Flagged reason: recursive delete');
    expect(p).toContain('Working directory: /home/user/proj');
    // Hermes false-positive example preserved verbatim:
    expect(p).toContain("python -c \"print('hello')\"");
    expect(p).toContain('APPROVE, DENY, or ESCALATE');
  });
});

describe('parseVerdict', () => {
  it('maps APPROVE → approve', () => {
    expect(parseVerdict('APPROVE')).toBe('approve');
  });
  it('maps lowercase approve → approve', () => {
    expect(parseVerdict('approve')).toBe('approve');
  });
  it('maps DENY → deny', () => {
    expect(parseVerdict('DENY')).toBe('deny');
  });
  it('maps ESCALATE → escalate', () => {
    expect(parseVerdict('ESCALATE')).toBe('escalate');
  });
  it('falls back to escalate on unrecognized tokens', () => {
    expect(parseVerdict('maybe')).toBe('escalate');
  });
  it('falls back to escalate on empty input', () => {
    expect(parseVerdict('')).toBe('escalate');
  });
  it('APPROVE as a standalone token is accepted with surrounding words', () => {
    expect(parseVerdict('I would APPROVE this')).toBe('approve');
  });

  // --- Hardened parser: ambiguous / multi-token / embedded cases ---

  it('SECURITY: mixed DENY + approve text escalates (not approve)', () => {
    expect(parseVerdict('DENY — do not approve')).toBe('escalate');
  });

  it('SECURITY: "I cannot APPROVE this, DENY" escalates', () => {
    expect(parseVerdict('I cannot APPROVE this, DENY')).toBe('escalate');
  });

  it('SECURITY: all three tokens escalate', () => {
    expect(parseVerdict('APPROVE DENY ESCALATE')).toBe('escalate');
  });

  it('SECURITY: "ESCALATE, do not auto-approve" escalates (approve is not a standalone token)', () => {
    expect(parseVerdict('ESCALATE, do not auto-approve')).toBe('escalate');
  });

  it('SECURITY: DISAPPROVE is NOT parsed as APPROVE (word boundary)', () => {
    expect(parseVerdict('DISAPPROVE')).toBe('escalate');
  });

  it('SECURITY: ANTIDENY is NOT parsed as DENY (word boundary)', () => {
    expect(parseVerdict('ANTIDENY')).toBe('escalate');
  });
});

describe('buildExplainPrompt', () => {
  it('is verdict-free (does not ask for APPROVE/DENY/ESCALATE)', () => {
    const p = buildExplainPrompt({
      command: 'rm -rf /',
      description: 'delete in root path',
      cwd: '/home/user/proj',
    });
    expect(p).toContain('Command: rm -rf /');
    expect(p).toContain('Flagged reason: delete in root path');
    expect(p).toContain('Working directory: /home/user/proj');
    expect(p).toContain('summary');
    expect(p).toContain('risks');
    expect(p).toContain('reversible');
    // Explain prompt must NOT nudge the model toward a verdict — these
    // commands always reach the user regardless of LLM opinion.
    expect(p).not.toMatch(/\bAPPROVE\b/);
    expect(p).not.toMatch(/\bDENY\b/);
    expect(p).not.toMatch(/\bESCALATE\b/);
  });
});

describe('parseClassifierResponse', () => {
  it('parses a well-formed JSON object into verdict + explanation', () => {
    const r = parseClassifierResponse(
      JSON.stringify({
        verdict: 'DENY',
        summary: '递归删除 /tmp 下的文件',
        risks: ['可能误删未备份数据', '可能影响正在运行的进程'],
        reversible: 'no',
      }),
    );
    expect(r.verdict).toBe('deny');
    expect(r.explanation).toBeDefined();
    expect(r.explanation!.summary).toBe('递归删除 /tmp 下的文件');
    expect(r.explanation!.risks).toHaveLength(2);
    expect(r.explanation!.reversible).toBe('no');
  });

  it('tolerates prose around the JSON block', () => {
    const r = parseClassifierResponse(
      'Here is my analysis:\n{"verdict":"APPROVE","summary":"打印字符串","risks":[],"reversible":"yes"}\nThanks!',
    );
    expect(r.verdict).toBe('approve');
    expect(r.explanation?.summary).toBe('打印字符串');
    expect(r.explanation?.risks).toEqual([]);
    expect(r.explanation?.reversible).toBe('yes');
  });

  it('falls back to plain-text verdict parsing when no JSON present', () => {
    const r = parseClassifierResponse('APPROVE');
    expect(r.verdict).toBe('approve');
    expect(r.explanation).toBeUndefined();
  });

  it('on malformed JSON falls back to plain-text verdict parsing (no explanation)', () => {
    // JSON fails to parse → we hand the raw string to parseVerdict, which
    // finds APPROVE as a standalone token. The operator still gets a sane
    // verdict even if the model returned an incomplete JSON object. There's
    // no `explanation` though (coerceExplanation never ran).
    const r = parseClassifierResponse('{"verdict": "APPROVE", malformed');
    expect(r.verdict).toBe('approve');
    expect(r.explanation).toBeUndefined();
  });

  it('malformed JSON with no verdict word → escalate', () => {
    const r = parseClassifierResponse('{oops totally broken');
    expect(r.verdict).toBe('escalate');
    expect(r.explanation).toBeUndefined();
  });

  it('coerces unknown reversibility values to "unknown"', () => {
    const r = parseClassifierResponse(
      JSON.stringify({
        verdict: 'ESCALATE',
        summary: 's',
        risks: ['r'],
        reversible: 'maybe',
      }),
    );
    expect(r.explanation?.reversible).toBe('unknown');
  });

  it('filters out non-string risk entries', () => {
    const r = parseClassifierResponse(
      JSON.stringify({
        verdict: 'DENY',
        summary: 's',
        risks: ['valid', 42, null, '   ', 'another valid'],
        reversible: 'no',
      }),
    );
    expect(r.explanation?.risks).toEqual(['valid', 'another valid']);
  });

  it('returns no explanation when summary + risks are both empty', () => {
    const r = parseClassifierResponse(
      JSON.stringify({ verdict: 'APPROVE', summary: '', risks: [], reversible: 'yes' }),
    );
    expect(r.verdict).toBe('approve');
    expect(r.explanation).toBeUndefined();
  });

  it('empty string → escalate', () => {
    expect(parseClassifierResponse('').verdict).toBe('escalate');
  });
});

describe('parseExplanationResponse', () => {
  it('parses a JSON explanation block', () => {
    const exp = parseExplanationResponse(
      JSON.stringify({
        summary: '格式化 /dev/sda',
        risks: ['永久丢失所有数据'],
        reversible: 'no',
      }),
    );
    expect(exp).toBeDefined();
    expect(exp!.summary).toBe('格式化 /dev/sda');
    expect(exp!.reversible).toBe('no');
  });

  it('returns undefined for plain text (no JSON block)', () => {
    expect(parseExplanationResponse('Sorry, cannot comply.')).toBeUndefined();
  });

  it('returns undefined for malformed JSON', () => {
    expect(parseExplanationResponse('{broken')).toBeUndefined();
  });

  it('returns undefined when the JSON is empty of content', () => {
    expect(parseExplanationResponse('{"summary":"","risks":[]}')).toBeUndefined();
  });
});

describe('SmartApprovalClassifier.classify', () => {
  it('returns approve when the query yields APPROVE', async () => {
    const query: QueryFn = () => cannedStream('APPROVE');
    const c = new SmartApprovalClassifier(
      { enabled: true, timeoutMs: 5000 },
      () => 'claude-sonnet-4-6',
      makeLogger(),
      query,
    );
    const r = await c.classify(REQ);
    expect(r.verdict).toBe('approve');
    expect(r.raw).toBe('APPROVE');
    expect(r.latencyMs).toBeGreaterThanOrEqual(0);
  });

  it('returns deny when the query yields DENY', async () => {
    const query: QueryFn = () => cannedStream('DENY');
    const c = new SmartApprovalClassifier(
      { enabled: true, timeoutMs: 5000 },
      () => 'claude-sonnet-4-6',
      makeLogger(),
      query,
    );
    const r = await c.classify(REQ);
    expect(r.verdict).toBe('deny');
  });

  it('returns escalate when the query yields ESCALATE', async () => {
    const query: QueryFn = () => cannedStream('ESCALATE');
    const c = new SmartApprovalClassifier(
      { enabled: true, timeoutMs: 5000 },
      () => 'claude-sonnet-4-6',
      makeLogger(),
      query,
    );
    const r = await c.classify(REQ);
    expect(r.verdict).toBe('escalate');
  });

  it('escalates on unrecognized text with reason "unrecognized response"', async () => {
    const query: QueryFn = () => cannedStream('maybe later');
    const c = new SmartApprovalClassifier(
      { enabled: true, timeoutMs: 5000 },
      () => 'claude-sonnet-4-6',
      makeLogger(),
      query,
    );
    const r = await c.classify(REQ);
    expect(r.verdict).toBe('escalate');
    expect(r.reason).toBe('unrecognized response');
  });

  it('escalates on empty response', async () => {
    const query: QueryFn = () => cannedStream('   ');
    const logger = makeLogger();
    const c = new SmartApprovalClassifier(
      { enabled: true, timeoutMs: 5000 },
      () => 'claude-sonnet-4-6',
      logger,
      query,
    );
    const r = await c.classify(REQ);
    expect(r.verdict).toBe('escalate');
    expect(r.reason).toBe('empty response');
    expect(logger.warn).toHaveBeenCalled();
  });

  it('escalates when the query throws', async () => {
    const query: QueryFn = () => ({
      [Symbol.asyncIterator](): AsyncIterator<SDKMessage> {
        return {
          next(): Promise<IteratorResult<SDKMessage>> {
            return Promise.reject(new Error('boom'));
          },
        };
      },
    });
    const logger = makeLogger();
    const c = new SmartApprovalClassifier(
      { enabled: true, timeoutMs: 5000 },
      () => 'claude-sonnet-4-6',
      logger,
      query,
    );
    const r = await c.classify(REQ);
    expect(r.verdict).toBe('escalate');
    expect(r.reason).toBe('classifier error');
    expect(logger.warn).toHaveBeenCalled();
  });

  it('escalates on timeout', async () => {
    const query: QueryFn = ({ abortController }) => hangingStream(abortController);
    const logger = makeLogger();
    const c = new SmartApprovalClassifier(
      { enabled: true, timeoutMs: 20 },
      () => 'claude-sonnet-4-6',
      logger,
      query,
    );
    const r = await c.classify(REQ);
    expect(r.verdict).toBe('escalate');
    expect(r.reason).toBe('classifier timeout');
  });

  it('short-circuits to escalate when disabled', async () => {
    const query: QueryFn = vi.fn(() => cannedStream('APPROVE'));
    const c = new SmartApprovalClassifier(
      { enabled: false, timeoutMs: 5000 },
      () => 'claude-sonnet-4-6',
      makeLogger(),
      query as QueryFn,
    );
    const r = await c.classify(REQ);
    expect(r.verdict).toBe('escalate');
    expect(r.reason).toBe('smart approval disabled');
    expect(query).not.toHaveBeenCalled();
  });

  it('escalates when no model is configured (getModel returns undefined)', async () => {
    const query: QueryFn = vi.fn(() => cannedStream('APPROVE'));
    const c = new SmartApprovalClassifier(
      { enabled: true, timeoutMs: 5000 },
      () => undefined,
      makeLogger(),
      query as QueryFn,
    );
    const r = await c.classify(REQ);
    expect(r.verdict).toBe('escalate');
    expect(r.reason).toBe('no model configured');
    expect(query).not.toHaveBeenCalled();
  });

  it('passes the configured model through to the query fn', async () => {
    const spy = vi.fn<QueryFn>(() => cannedStream('APPROVE'));
    const c = new SmartApprovalClassifier(
      { enabled: true, timeoutMs: 5000 },
      () => 'claude-opus-4-7',
      makeLogger(),
      spy,
    );
    await c.classify(REQ);
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy.mock.calls[0][0].model).toBe('claude-opus-4-7');
  });

  it('populates explanation when the query yields structured JSON', async () => {
    const json = JSON.stringify({
      verdict: 'DENY',
      summary: '递归删除 /home 下所有文件',
      risks: ['用户数据永久丢失'],
      reversible: 'no',
    });
    const c = new SmartApprovalClassifier(
      { enabled: true, timeoutMs: 5000 },
      () => 'claude-sonnet-4-6',
      makeLogger(),
      () => cannedStream(json),
    );
    const r = await c.classify(REQ);
    expect(r.verdict).toBe('deny');
    expect(r.explanation).toBeDefined();
    expect(r.explanation!.summary).toBe('递归删除 /home 下所有文件');
    expect(r.explanation!.reversible).toBe('no');
  });

  it('omits explanation when the query returns a bare verdict word', async () => {
    const c = new SmartApprovalClassifier(
      { enabled: true, timeoutMs: 5000 },
      () => 'claude-sonnet-4-6',
      makeLogger(),
      () => cannedStream('APPROVE'),
    );
    const r = await c.classify(REQ);
    expect(r.verdict).toBe('approve');
    expect(r.explanation).toBeUndefined();
  });
});

describe('SmartApprovalClassifier.explain', () => {
  it('returns the parsed explanation on a valid JSON response', async () => {
    const json = JSON.stringify({
      summary: '强制删除所有根目录文件',
      risks: ['系统不可启动', '数据丢失不可恢复'],
      reversible: 'no',
    });
    const c = new SmartApprovalClassifier(
      { enabled: true, timeoutMs: 5000 },
      () => 'claude-sonnet-4-6',
      makeLogger(),
      () => cannedStream(json),
    );
    const exp = await c.explain(REQ);
    expect(exp).toBeDefined();
    expect(exp!.summary).toBe('强制删除所有根目录文件');
    expect(exp!.risks).toHaveLength(2);
    expect(exp!.reversible).toBe('no');
  });

  it('returns undefined on timeout', async () => {
    const logger = makeLogger();
    const c = new SmartApprovalClassifier(
      { enabled: true, timeoutMs: 20 },
      () => 'claude-sonnet-4-6',
      logger,
      ({ abortController }) => hangingStream(abortController),
    );
    const exp = await c.explain(REQ);
    expect(exp).toBeUndefined();
    expect(logger.warn).toHaveBeenCalled();
  });

  it('returns undefined when disabled', async () => {
    const spy = vi.fn<QueryFn>(() => cannedStream('{"summary":"x","risks":[],"reversible":"yes"}'));
    const c = new SmartApprovalClassifier(
      { enabled: false, timeoutMs: 5000 },
      () => 'claude-sonnet-4-6',
      makeLogger(),
      spy,
    );
    const exp = await c.explain(REQ);
    expect(exp).toBeUndefined();
    expect(spy).not.toHaveBeenCalled();
  });

  it('returns undefined when no model is configured', async () => {
    const spy = vi.fn<QueryFn>(() => cannedStream('{}'));
    const c = new SmartApprovalClassifier(
      { enabled: true, timeoutMs: 5000 },
      () => undefined,
      makeLogger(),
      spy,
    );
    const exp = await c.explain(REQ);
    expect(exp).toBeUndefined();
    expect(spy).not.toHaveBeenCalled();
  });

  it('returns undefined when the query throws', async () => {
    const logger = makeLogger();
    const c = new SmartApprovalClassifier(
      { enabled: true, timeoutMs: 5000 },
      () => 'claude-sonnet-4-6',
      logger,
      () => ({
        [Symbol.asyncIterator](): AsyncIterator<SDKMessage> {
          return {
            next(): Promise<IteratorResult<SDKMessage>> {
              return Promise.reject(new Error('boom'));
            },
          };
        },
      }),
    );
    const exp = await c.explain(REQ);
    expect(exp).toBeUndefined();
    expect(logger.warn).toHaveBeenCalled();
  });
});

describe('buildClassifierEnv — secret scrub', () => {
  const saved: Record<string, string | undefined> = {};
  const keys = [
    // MetaBot-namespaced
    'METABOT_API_SECRET', 'FEISHU_APP_SECRET', 'TELEGRAM_BOT_TOKEN',
    'WECHAT_BOT_TOKEN', 'MEMORY_SECRET',
    // Volc / Volcengine
    'VOLC_ACCESS_KEY_ID', 'VOLC_SECRET_KEY',
    'VOLC_RTC_APP_ID', 'VOLC_RTC_APP_KEY',
    'VOLCENGINE_TTS_APPID', 'VOLCENGINE_TTS_ACCESS_KEY',
    // Anthropic
    'ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN',
    // Generic suffixes
    'OPENAI_API_KEY', 'SSH_KEY', 'AWS_ACCESS_KEY_ID',
    // Should SURVIVE (benign)
    'HOME', 'PATH', 'LANG', 'XDG_RUNTIME_DIR',
  ];

  beforeEach(() => {
    for (const k of keys) {
      saved[k] = process.env[k];
      // Only set the "should be scrubbed" ones so they can be proven missing
      if (!['HOME', 'PATH', 'LANG', 'XDG_RUNTIME_DIR'].includes(k)) {
        process.env[k] = `secret-${k}`;
      }
    }
    // Ensure benign ones exist
    if (!process.env.HOME) process.env.HOME = '/tmp/test-home';
    if (!process.env.PATH) process.env.PATH = '/usr/bin';
  });

  afterEach(() => {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  });

  it('strips METABOT_/FEISHU_/TELEGRAM_/WECHAT_/MEMORY_ prefixes', () => {
    const env = buildClassifierEnv();
    expect(env.METABOT_API_SECRET).toBeUndefined();
    expect(env.FEISHU_APP_SECRET).toBeUndefined();
    expect(env.TELEGRAM_BOT_TOKEN).toBeUndefined();
    expect(env.WECHAT_BOT_TOKEN).toBeUndefined();
    expect(env.MEMORY_SECRET).toBeUndefined();
  });

  it('strips VOLC_* and VOLCENGINE_* credentials (Codex round-2 finding)', () => {
    const env = buildClassifierEnv();
    expect(env.VOLC_ACCESS_KEY_ID).toBeUndefined();
    expect(env.VOLC_SECRET_KEY).toBeUndefined();
    expect(env.VOLC_RTC_APP_ID).toBeUndefined();
    expect(env.VOLC_RTC_APP_KEY).toBeUndefined();
    expect(env.VOLCENGINE_TTS_APPID).toBeUndefined();
    expect(env.VOLCENGINE_TTS_ACCESS_KEY).toBeUndefined();
  });

  it('strips ANTHROPIC_API_KEY and ANTHROPIC_AUTH_TOKEN', () => {
    const env = buildClassifierEnv();
    expect(env.ANTHROPIC_API_KEY).toBeUndefined();
    expect(env.ANTHROPIC_AUTH_TOKEN).toBeUndefined();
  });

  it('strips generic secret suffixes (_API_KEY, _KEY, _KEY_ID, _TOKEN, _SECRET)', () => {
    const env = buildClassifierEnv();
    expect(env.OPENAI_API_KEY).toBeUndefined();
    expect(env.SSH_KEY).toBeUndefined();
    expect(env.AWS_ACCESS_KEY_ID).toBeUndefined();
  });

  it('preserves benign env vars needed for OAuth credential resolution', () => {
    const env = buildClassifierEnv();
    expect(env.HOME).toBeDefined();
    expect(env.PATH).toBeDefined();
  });

  // Codex round-4 finding: SECRET_ENV_DENYLIST was case-sensitive, so
  // lowercase / mixed-case secret env names (.env exports from some tools)
  // slipped through. buildClassifierEnv now canonicalizes to upper-case
  // before matching.
  it('SECURITY: strips lowercase secret names (`openai_api_key`)', () => {
    process.env.openai_api_key = 'sk-lowercase-leak';
    try {
      const env = buildClassifierEnv();
      expect(env.openai_api_key).toBeUndefined();
    } finally {
      delete process.env.openai_api_key;
    }
  });

  it('SECURITY: strips mixed-case Feishu secrets (`Feishu_App_Secret`)', () => {
    process.env.Feishu_App_Secret = 'mixed-case-leak';
    try {
      const env = buildClassifierEnv();
      expect(env.Feishu_App_Secret).toBeUndefined();
    } finally {
      delete process.env.Feishu_App_Secret;
    }
  });

  it('SECURITY: strips lowercase anthropic_api_key', () => {
    process.env.anthropic_api_key = 'sk-ant-lowercase';
    try {
      const env = buildClassifierEnv();
      expect(env.anthropic_api_key).toBeUndefined();
    } finally {
      delete process.env.anthropic_api_key;
    }
  });

  it('SECURITY: strips mixed-case _TOKEN suffix (`GitHub_Token`)', () => {
    process.env.GitHub_Token = 'ghp_mixedcase';
    try {
      const env = buildClassifierEnv();
      expect(env.GitHub_Token).toBeUndefined();
    } finally {
      delete process.env.GitHub_Token;
    }
  });
});
