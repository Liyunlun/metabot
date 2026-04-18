/**
 * Feishu interactive cards for dangerous-command approval.
 *
 * Three states — all produced as plain JSON strings ready for
 * `messageSender.sendCard` / `updateCard`:
 *
 *   1. `buildPendingApprovalCard`   — orange header + 4 buttons (Once / Session
 *                                     / Always / Deny). Sent when the engine
 *                                     first prompts the user.
 *   2. `buildResolvedApprovalCard`  — green header ("✅ Allowed") or red header
 *                                     ("🚫 Denied"), operator + timestamp, no
 *                                     buttons. Replaces the pending card.
 *
 * The card visual language (orange/green/red) mirrors Hermes's
 * `send_exec_approval` in `gateway/platforms/feishu.py`.
 *
 * Buttons carry `value: { kind: 'dangerous_approval', approvalId, choice }`
 * so `MessageBridge.handleCardAction` can route clicks back to
 * `approvalStore.resolveById`.
 */

import type { ApprovalChoice, ApprovalRequest, CommandExplanation } from './approval-store.js';

/** Kind tag for the Feishu button `value` — matched in `handleCardAction`. */
export const APPROVAL_BUTTON_KIND = 'dangerous_approval';

/** Map choice → button label + type (Feishu's built-in button styles). */
const BUTTON_SPEC: Array<{ choice: ApprovalChoice; label: string; type: string }> = [
  { choice: 'once', label: '✅ 仅本次', type: 'primary' },
  { choice: 'session', label: '✅ 本会话', type: 'primary' },
  { choice: 'always', label: '✅ 永久允许', type: 'primary' },
  { choice: 'deny', label: '🚫 拒绝', type: 'danger' },
];

/** Truncate a command preview so long heredocs / inline scripts don't blow up the card. */
const MAX_COMMAND_PREVIEW = 1500;
function previewCommand(cmd: string): string {
  if (cmd.length <= MAX_COMMAND_PREVIEW) return cmd;
  return cmd.slice(0, MAX_COMMAND_PREVIEW) + `\n… (truncated, ${cmd.length - MAX_COMMAND_PREVIEW} more chars)`;
}

function escapeBackticks(s: string): string {
  return s.replace(/`/g, '\\`');
}

/**
 * Human-readable labels for the reversibility bucket. Chinese-first to match
 * the existing card copy (`危险命令需要确认`, `匹配规则`, …).
 */
const REVERSIBILITY_LABEL: Record<CommandExplanation['reversible'], string> = {
  yes: '✅ 可逆（容易撤销）',
  no: '❌ 不可逆（无法撤销）',
  partial: '⚠️ 部分可逆（恢复成本高）',
  unknown: '❓ 未知',
};

/**
 * Render the LLM-generated explanation as a markdown block. Returns an empty
 * string when `explanation` is missing — the caller decides whether to emit
 * the element at all. Kept defensive: each field is optional on the wire
 * (LLM may omit risks, produce an empty summary, etc.).
 */
function renderExplanation(explanation: CommandExplanation | undefined): string {
  if (!explanation) return '';
  const sections: string[] = [];
  const summary = explanation.summary.trim();
  if (summary) {
    sections.push(`**📋 这条命令做什么：** ${summary}`);
  }
  if (explanation.risks.length > 0) {
    const bullets = explanation.risks.map((r) => `- ${r}`).join('\n');
    sections.push(`**⚠️ 潜在风险：**\n${bullets}`);
  }
  sections.push(`**🔄 可逆性：** ${REVERSIBILITY_LABEL[explanation.reversible]}`);
  return sections.join('\n\n');
}

export interface PendingApprovalCardInput {
  approvalId: string;
  request: ApprovalRequest;
}

/**
 * Build the orange "awaiting approval" card.
 */
export function buildPendingApprovalCard(input: PendingApprovalCardInput): string {
  const { approvalId, request } = input;
  const cmdPreview = previewCommand(request.command);

  const explanationBlock = renderExplanation(request.explanation);

  const elements: Array<Record<string, unknown>> = [
    {
      tag: 'markdown',
      content:
        `**匹配规则：** ${request.description}\n\n` +
        `**命令：**\n\`\`\`bash\n${escapeBackticks(cmdPreview)}\n\`\`\``,
    },
  ];

  // Insert the LLM-generated explanation (summary / risks / reversibility)
  // right under the command block so it's the first thing the operator
  // reads. Omitted entirely when the classifier didn't produce one — we
  // don't want a visibly-empty "explanation" placeholder.
  if (explanationBlock) {
    elements.push({ tag: 'hr' });
    elements.push({ tag: 'markdown', content: explanationBlock });
  }

  elements.push(
    { tag: 'hr' },
    {
      tag: 'action',
      layout: 'flow',
      actions: BUTTON_SPEC.map(({ choice, label, type }) => ({
        tag: 'button',
        text: { tag: 'plain_text', content: label },
        type,
        value: {
          kind: APPROVAL_BUTTON_KIND,
          approvalId,
          choice,
        },
      })),
    },
    {
      tag: 'markdown',
      content:
        '_一次（Once）：仅本次放行_ · _本会话（Session）：匹配同一规则不再弹窗_ · ' +
        '_永久（Always）：跨会话保存_ · _拒绝（Deny）：阻断执行_',
    },
  );

  const card = {
    config: { wide_screen_mode: true, update_multi: true },
    header: {
      title: { tag: 'plain_text', content: '⚠️ 危险命令需要确认' },
      template: 'orange',
    },
    elements,
  };
  return JSON.stringify(card);
}

export interface ResolvedApprovalCardInput {
  approvalId: string;
  request: ApprovalRequest;
  choice: ApprovalChoice;
  /** User ID / name that resolved this approval. Shown in the footer. */
  operator?: string;
  /** Resolution timestamp (ms since epoch). Defaults to `Date.now()`. */
  resolvedAt?: number;
  /** Set to true when the timeout auto-denied (vs a user click). */
  autoResolved?: boolean;
}

const CHOICE_HEADERS: Record<ApprovalChoice, { title: string; template: string }> = {
  once: { title: '✅ 已允许（仅本次）', template: 'green' },
  session: { title: '✅ 已允许（本会话）', template: 'green' },
  always: { title: '✅ 已永久允许', template: 'green' },
  deny: { title: '🚫 已拒绝', template: 'red' },
};

/**
 * Build the green/red "resolved" card that replaces the pending one after a
 * button click, `/approve`, `/deny`, or a fail-closed auto-deny.
 */
export function buildResolvedApprovalCard(input: ResolvedApprovalCardInput): string {
  const {
    approvalId,
    request,
    choice,
    operator,
    resolvedAt = Date.now(),
    autoResolved = false,
  } = input;

  const { title, template } = CHOICE_HEADERS[choice];
  const cmdPreview = previewCommand(request.command);
  const explanationBlock = renderExplanation(request.explanation);

  const footerLines = [
    operator ? `**操作人：** ${operator}` : null,
    `**时间：** ${new Date(resolvedAt).toISOString()}`,
    autoResolved ? '_（超时自动处理）_' : null,
    `_approval id: ${approvalId}_`,
  ].filter(Boolean);

  const elements: Array<Record<string, unknown>> = [
    {
      tag: 'markdown',
      content:
        `**匹配规则：** ${request.description}\n\n` +
        `**命令：**\n\`\`\`bash\n${escapeBackticks(cmdPreview)}\n\`\`\``,
    },
  ];

  // Preserve the LLM explanation on the resolved card too — useful for
  // audit/review so a reviewer later can see exactly what the operator was
  // told before they decided.
  if (explanationBlock) {
    elements.push({ tag: 'hr' });
    elements.push({ tag: 'markdown', content: explanationBlock });
  }

  elements.push(
    { tag: 'hr' },
    { tag: 'markdown', content: footerLines.join('\n') },
  );

  const card = {
    config: { wide_screen_mode: true, update_multi: true },
    header: {
      title: { tag: 'plain_text', content: title },
      template,
    },
    elements,
  };
  return JSON.stringify(card);
}
