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
});
