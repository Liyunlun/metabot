import { describe, it, expect } from 'vitest';
import { buildCardV2 } from '../src/feishu/card-builder-v2.js';
import type { CardState } from '../src/types.js';

function findFooterContent(card: any): string {
  const colSet = card.body.elements.find((e: any) => e.tag === 'column_set');
  if (!colSet) return '';
  return colSet.columns[0].elements[0].content as string;
}

describe('buildCardV2 header', () => {
  it('renders elapsed time in title while running', () => {
    const state: CardState = {
      status: 'running',
      userPrompt: 'task',
      responseText: 'working',
      toolCalls: [],
      startTime: Date.now() - 5_000,
    };
    const json = JSON.parse(buildCardV2(state));
    expect(json.header.title.content).toMatch(/Running\.\.\. \(\d+s\)/);
  });

  it('renders elapsed time in title while thinking', () => {
    const state: CardState = {
      status: 'thinking',
      userPrompt: 'task',
      responseText: '',
      toolCalls: [],
      startTime: Date.now() - 12_000,
    };
    const json = JSON.parse(buildCardV2(state));
    expect(json.header.title.content).toMatch(/Thinking\.\.\. \(\d+s\)/);
  });

  it('formats elapsed > 60s as MmSs', () => {
    const state: CardState = {
      status: 'running',
      userPrompt: 'task',
      responseText: 'working',
      toolCalls: [],
      startTime: Date.now() - 125_000,
    };
    const json = JSON.parse(buildCardV2(state));
    expect(json.header.title.content).toMatch(/\(2m\d+s\)/);
  });

  it('does not render elapsed in title on complete', () => {
    const state: CardState = {
      status: 'complete',
      userPrompt: 'task',
      responseText: 'done',
      toolCalls: [],
      startTime: Date.now() - 5_000,
    };
    const json = JSON.parse(buildCardV2(state));
    expect(json.header.title.content).not.toMatch(/\(\d+s\)/);
  });

  it('overrides title with cardTitle when set', () => {
    const state: CardState = {
      status: 'complete',
      userPrompt: 'task',
      responseText: '',
      toolCalls: [],
      cardTitle: 'Turn 1',
    };
    const json = JSON.parse(buildCardV2(state));
    expect(json.header.title.content).toBe('🟢 Turn 1');
  });

  it('cardTitle takes precedence over elapsed', () => {
    const state: CardState = {
      status: 'running',
      userPrompt: 'task',
      responseText: '',
      toolCalls: [],
      startTime: Date.now() - 30_000,
      cardTitle: '📊 Result',
    };
    const json = JSON.parse(buildCardV2(state));
    expect(json.header.title.content).toBe('🔵 📊 Result');
  });
});

describe('buildCardV2 thinking placeholder', () => {
  it('shows elapsed suffix in thinking placeholder', () => {
    const state: CardState = {
      status: 'thinking',
      userPrompt: 'task',
      responseText: '',
      toolCalls: [],
      startTime: Date.now() - 3_000,
    };
    const json = JSON.parse(buildCardV2(state));
    const md = json.body.elements.find((e: any) => e.tag === 'markdown' && /Thinking/.test(e.content));
    expect(md.content).toMatch(/_Thinking\.\.\. \(\d+s\)_/);
  });

  it('shows plain thinking placeholder when no startTime', () => {
    const state: CardState = {
      status: 'thinking',
      userPrompt: 'task',
      responseText: '',
      toolCalls: [],
    };
    const json = JSON.parse(buildCardV2(state));
    const md = json.body.elements.find((e: any) => e.tag === 'markdown' && /Thinking/.test(e.content));
    expect(md.content).toBe('_Thinking..._');
  });
});

describe('buildCardV2 stats footer', () => {
  it('renders all v1 footer fields on complete', () => {
    const state: CardState = {
      status: 'complete',
      userPrompt: 'task',
      responseText: 'done',
      toolCalls: [],
      model: 'claude-opus-4-7',
      thinking: 'adaptive',
      effort: 'max',
      totalTokens: 152700,
      contextWindow: 200000,
      sessionCostUsd: 38.58,
      durationMs: 21000,
      numTurns: 3,
      workingDirectory: '/home/user/lyl/Research',
      sessionId: '260a4c39-b47e-4534-88ca-bb4ac5b5b83a',
    };
    const json = JSON.parse(buildCardV2(state));
    const content = findFooterContent(json);
    expect(content).toContain('opus-4-7');
    expect(content).toContain('thinking:adaptive');
    expect(content).toContain('effort:max');
    expect(content).toContain('ctx: 152.7k/200k (76%)');
    expect(content).toContain('$38.58');
    expect(content).toContain('21.0s');
    expect(content).toContain('3 turns');
    expect(content).toContain('📁');
    expect(content).toContain('Research');
    expect(content).toContain('🔑 260a4c39');
  });

  it('renders model + ctx during running', () => {
    const state: CardState = {
      status: 'running',
      userPrompt: 'task',
      responseText: 'working',
      toolCalls: [],
      model: 'claude-opus-4-7',
      totalTokens: 1000,
      contextWindow: 200000,
    };
    const json = JSON.parse(buildCardV2(state));
    const content = findFooterContent(json);
    expect(content).toContain('opus-4-7');
    expect(content).toContain('ctx:');
  });

  it('does not render cost/duration during running', () => {
    const state: CardState = {
      status: 'running',
      userPrompt: 'task',
      responseText: 'working',
      toolCalls: [],
      sessionCostUsd: 1.23,
    };
    const json = JSON.parse(buildCardV2(state));
    const content = findFooterContent(json);
    expect(content).not.toContain('$1.23');
  });

  it('shortens long workingDirectory paths', () => {
    const state: CardState = {
      status: 'complete',
      userPrompt: 'task',
      responseText: '',
      toolCalls: [],
      workingDirectory: '/very/long/path/to/some/deeply/nested/project/dir',
    };
    const json = JSON.parse(buildCardV2(state));
    const content = findFooterContent(json);
    expect(content).toMatch(/📁 \.\.\.\/project\/dir/);
  });

  it('omits footer entirely when no fields set', () => {
    const state: CardState = {
      status: 'thinking',
      userPrompt: 'task',
      responseText: '',
      toolCalls: [],
    };
    const json = JSON.parse(buildCardV2(state));
    const colSet = json.body.elements.find((e: any) => e.tag === 'column_set');
    expect(colSet).toBeUndefined();
  });
});
