import { describe, it, expect } from 'vitest';
import {
  APPROVAL_BUTTON_KIND,
  buildPendingApprovalCard,
  buildResolvedApprovalCard,
} from '../src/security/approval-card.js';

const REQ = {
  command: 'rm -rf /tmp/foo',
  description: 'recursive delete',
  patternKey: 'recursive delete',
};

function parseCard(json: string): any {
  return JSON.parse(json);
}

describe('buildPendingApprovalCard', () => {
  it('uses orange template for the "awaiting" state', () => {
    const card = parseCard(buildPendingApprovalCard({ approvalId: 'a_1', request: REQ }));
    expect(card.header.template).toBe('orange');
    expect(card.header.title.content).toContain('危险命令');
  });

  it('embeds the matched pattern description and the command', () => {
    const json = buildPendingApprovalCard({ approvalId: 'a_1', request: REQ });
    expect(json).toContain('recursive delete');
    expect(json).toContain('rm -rf /tmp/foo');
  });

  it('emits exactly 4 buttons in choice order: once, session, always, deny', () => {
    const card = parseCard(buildPendingApprovalCard({ approvalId: 'a_1', request: REQ }));
    const action = card.elements.find((e: any) => e.tag === 'action');
    expect(action).toBeTruthy();
    expect(action.actions).toHaveLength(4);
    expect(action.actions.map((b: any) => b.value.choice)).toEqual([
      'once',
      'session',
      'always',
      'deny',
    ]);
  });

  it('each button carries the APPROVAL_BUTTON_KIND tag + approvalId', () => {
    const card = parseCard(buildPendingApprovalCard({ approvalId: 'a_42', request: REQ }));
    const action = card.elements.find((e: any) => e.tag === 'action');
    for (const btn of action.actions) {
      expect(btn.value.kind).toBe(APPROVAL_BUTTON_KIND);
      expect(btn.value.approvalId).toBe('a_42');
    }
  });

  it('deny button uses "danger" style, others use "primary"', () => {
    const card = parseCard(buildPendingApprovalCard({ approvalId: 'a_1', request: REQ }));
    const action = card.elements.find((e: any) => e.tag === 'action');
    const denyBtn = action.actions.find((b: any) => b.value.choice === 'deny');
    const onceBtn = action.actions.find((b: any) => b.value.choice === 'once');
    expect(denyBtn.type).toBe('danger');
    expect(onceBtn.type).toBe('primary');
  });

  it('truncates extremely long commands', () => {
    const longCmd = 'echo "' + 'A'.repeat(5000) + '"';
    const json = buildPendingApprovalCard({
      approvalId: 'a_1',
      request: { ...REQ, command: longCmd },
    });
    expect(json).toContain('truncated');
    // Card body should not contain the full 5000-char payload.
    expect(json.length).toBeLessThan(longCmd.length + 2000);
  });

  it('escapes backticks in the command so the markdown fence survives', () => {
    const cmd = 'echo `whoami`';
    const json = buildPendingApprovalCard({
      approvalId: 'a_1',
      request: { ...REQ, command: cmd },
    });
    expect(json).toContain('\\\\`whoami\\\\`'); // JSON-escaped "\\`whoami\\`"
  });

  describe('LLM-generated explanation', () => {
    const explainedReq = {
      ...REQ,
      explanation: {
        summary: '递归删除 /tmp/foo 及其子目录',
        risks: ['可能误删未备份的数据', '无法通过回收站恢复'],
        reversible: 'no' as const,
      },
    };

    it('renders summary, risks, and reversibility when explanation is provided', () => {
      const json = buildPendingApprovalCard({ approvalId: 'a_1', request: explainedReq });
      expect(json).toContain('这条命令做什么');
      expect(json).toContain('递归删除 /tmp/foo');
      expect(json).toContain('潜在风险');
      expect(json).toContain('可能误删未备份的数据');
      expect(json).toContain('无法通过回收站恢复');
      expect(json).toContain('可逆性');
      expect(json).toContain('不可逆');
    });

    it('still emits 4 buttons when explanation is present', () => {
      const card = parseCard(
        buildPendingApprovalCard({ approvalId: 'a_1', request: explainedReq }),
      );
      const action = card.elements.find((e: any) => e.tag === 'action');
      expect(action.actions).toHaveLength(4);
    });

    it('omits the explanation block entirely when not provided (no empty section)', () => {
      const json = buildPendingApprovalCard({ approvalId: 'a_1', request: REQ });
      expect(json).not.toContain('这条命令做什么');
      expect(json).not.toContain('潜在风险');
      expect(json).not.toContain('可逆性');
    });

    it('handles each reversibility bucket', () => {
      for (const [bucket, label] of [
        ['yes', '可逆'],
        ['no', '不可逆'],
        ['partial', '部分可逆'],
        ['unknown', '未知'],
      ] as const) {
        const json = buildPendingApprovalCard({
          approvalId: 'a_1',
          request: {
            ...REQ,
            explanation: { summary: 's', risks: [], reversible: bucket },
          },
        });
        expect(json).toContain(label);
      }
    });

    it('renders summary-only explanation without an empty risks list', () => {
      const json = buildPendingApprovalCard({
        approvalId: 'a_1',
        request: {
          ...REQ,
          explanation: { summary: '只是打印一行', risks: [], reversible: 'yes' },
        },
      });
      expect(json).toContain('这条命令做什么');
      expect(json).toContain('只是打印一行');
      // An empty risks list must not produce an orphan bullet heading.
      expect(json).not.toContain('潜在风险');
    });
  });
});

describe('buildResolvedApprovalCard', () => {
  it('green template for "once"/"session"/"always", red for "deny"', () => {
    for (const c of ['once', 'session', 'always'] as const) {
      const card = parseCard(
        buildResolvedApprovalCard({ approvalId: 'a_1', request: REQ, choice: c }),
      );
      expect(card.header.template).toBe('green');
    }
    const deny = parseCard(
      buildResolvedApprovalCard({ approvalId: 'a_1', request: REQ, choice: 'deny' }),
    );
    expect(deny.header.template).toBe('red');
  });

  it('includes operator and resolvedAt timestamp in the footer', () => {
    const at = Date.UTC(2026, 3, 17, 12, 0, 0);
    const json = buildResolvedApprovalCard({
      approvalId: 'a_1',
      request: REQ,
      choice: 'once',
      operator: 'user_abc',
      resolvedAt: at,
    });
    expect(json).toContain('user_abc');
    expect(json).toContain(new Date(at).toISOString());
  });

  it('indicates autoResolved in the footer when set', () => {
    const json = buildResolvedApprovalCard({
      approvalId: 'a_1',
      request: REQ,
      choice: 'deny',
      autoResolved: true,
    });
    expect(json).toContain('超时自动处理');
  });

  it('does NOT emit any button/action element (cannot be clicked again)', () => {
    const card = parseCard(
      buildResolvedApprovalCard({ approvalId: 'a_1', request: REQ, choice: 'once' }),
    );
    const action = card.elements.find((e: any) => e.tag === 'action');
    expect(action).toBeUndefined();
  });

  it('preserves the LLM explanation on the resolved card for audit review', () => {
    const json = buildResolvedApprovalCard({
      approvalId: 'a_1',
      request: {
        ...REQ,
        explanation: {
          summary: '递归删除命令',
          risks: ['数据丢失'],
          reversible: 'no',
        },
      },
      choice: 'deny',
    });
    expect(json).toContain('这条命令做什么');
    expect(json).toContain('递归删除命令');
    expect(json).toContain('不可逆');
  });
});
