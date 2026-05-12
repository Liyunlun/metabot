import type { BotConfigBase } from '../config.js';
import type { Logger } from '../utils/logger.js';
import type { IncomingMessage } from '../types.js';
import type { IMessageSender } from './message-sender.interface.js';
import { resolveEngineName, SessionManager } from '../engines/index.js';
import type { EngineName } from '../engines/index.js';
import { MemoryClient } from '../memory/memory-client.js';
import { AuditLogger } from '../utils/audit-logger.js';
import type { DocSync } from '../sync/doc-sync.js';
import { ensureSkillInstalled, ensureSkillsInstalled } from '../utils/skill-installer.js';
import { approvalStore, buildSessionKey } from '../security/approval-store.js';
import type { ApprovalBridge } from '../security/approval-bridge.js';

const CONTRIBUTION_SKILLS = ['report-bug', 'fix-issue', 'request-feature'];

export class CommandHandler {
  private docSync: DocSync | null = null;
  private approvalBridge: ApprovalBridge | null = null;

  constructor(
    private config: BotConfigBase,
    private logger: Logger,
    private sender: IMessageSender,
    private sessionManager: SessionManager,
    private memoryClient: MemoryClient,
    private audit: AuditLogger,
    private getRunningTask: (chatId: string) => { startTime: number } | undefined,
    private stopTask: (chatId: string) => void,
  ) {}

  /** Set the doc sync service (optional, only available for Feishu bots). */
  setDocSync(docSync: DocSync): void {
    this.docSync = docSync;
  }

  /**
   * Bind the dangerous-command approval bridge (optional — only wired on
   * platforms that support raw cards, currently Feishu). When unset, the
   * /approve /deny /yolo commands respond with a "not supported" notice.
   */
  setApprovalBridge(bridge: ApprovalBridge): void {
    this.approvalBridge = bridge;
  }

  /** Returns true if the message was handled as a command, false otherwise. */
  async handle(msg: IncomingMessage): Promise<boolean> {
    const { text } = msg;
    if (!text.startsWith('/')) return false;

    const { userId, chatId } = msg;
    const [cmd] = text.split(/\s+/);

    this.audit.log({ event: 'command', botName: this.config.name, chatId, userId, prompt: cmd });

    switch (cmd.toLowerCase()) {
      case '/help':
        await this.sender.sendTextNotice(chatId, '📖 Help', [
          '**Available Commands:**',
          '`/reset` - Clear session, start fresh',
          '`/stop` - Abort current running task',
          '`/status` - Show current session info',
          '`/model` - Show current engine/model; `/model list` - Available options',
          '`/model claude`, `/model kimi`, or `/model codex` - Switch engine (resets session)',
          '`/model <name>` - Set model for current engine',
          '`/memory` - Memory document commands',
          '`/model [opus|sonnet|haiku]` - View or switch Claude model',
          '`/effort [low|medium|high|max]` - View or switch effort level',
          '`/approve [session|always]` - Approve oldest pending command (once/session/permanent)',
          '`/deny` - Reject oldest pending command',
          '`/yolo [on|off]` - Auto-approve dangerous commands (use carefully)',
          '`/approvals` - List current session + permanent allowlist',
          '`/revoke <pattern>` - Remove a pattern from the permanent allowlist',
          '`/help` - Show this help message',
          '',
          '**Usage:**',
          'Send any text message to start a conversation with the configured agent engine.',
          'Each chat has an independent session with a fixed working directory.',
          '',
          '**Memory Commands:**',
          '`/memory list` - Show folder tree',
          '`/memory search <query>` - Search documents',
          '`/memory status` - Server health check',
          '',
          '**Sync Commands:**',
          '`/sync` - Sync MetaMemory to Feishu Wiki',
          '`/sync status` - Show sync status',
          '',
          '**Contributing:**',
          '`/report-bug <description>` - Report a bug (creates GitHub issue)',
          '`/request-feature <idea>` - Request a feature (creates GitHub issue)',
          '`/fix-issue <number|list>` - Pick and fix a GitHub issue (creates PR)',
        ].join('\n'));
        return true;

      case '/reset':
        this.sessionManager.resetSession(chatId);
        // Also clear per-chat approval state (YOLO, session allowlist, any
        // queued pending approvals). Permanent allowlist is global and
        // intentionally survives /reset.
        approvalStore.clearSession(buildSessionKey(this.config.name, chatId));
        await this.sender.sendTextNotice(chatId, '✅ Session Reset', 'Conversation cleared. Working directory preserved.', 'green');
        return true;

      case '/stop': {
        const task = this.getRunningTask(chatId);
        if (task) {
          this.audit.log({ event: 'task_stopped', botName: this.config.name, chatId, userId, durationMs: Date.now() - task.startTime });
          this.stopTask(chatId);
          await this.sender.sendTextNotice(chatId, '🛑 Stopped', 'Current task has been aborted.', 'orange');
        } else {
          await this.sender.sendTextNotice(chatId, 'ℹ️ No Running Task', 'There is no task to stop.', 'blue');
        }
        return true;
      }

      case '/status': {
        const session = this.sessionManager.getSession(chatId);
        const isRunning = !!this.getRunningTask(chatId);
        const botEngine = resolveEngineName(this.config);
        const activeEngine = session.engine ?? botEngine;
        const defaultModel = this.defaultModelForEngine(activeEngine) || '_default_';
        const activeModel = session.model || defaultModel;
        await this.sender.sendTextNotice(chatId, '📊 Status', [
          `**User:** \`${userId}\``,
          `**Engine:** \`${activeEngine}\`${session.engine ? ' (session override)' : ''}`,
          `**Working Directory:** \`${session.workingDirectory}\``,
          `**Session:** ${session.sessionId ? `\`${session.sessionId.slice(0, 8)}...\`` : '_None_'}`,
          `**Model:** \`${activeModel}\`${session.model ? ' (session override)' : ''}`,
          `**Running:** ${isRunning ? 'Yes ⏳' : 'No'}`,
          `**Model:** \`${this.config.claude.model || 'default'}\``,
          `**Effort:** ${this.config.claude.effort || 'max'}`,
        ].join('\n'));
        return true;
      }

      case '/effort': {
        const VALID_LEVELS = ['low', 'medium', 'high', 'max'] as const;
        const arg = text.slice('/effort'.length).trim().toLowerCase();
        if (!arg) {
          const current = this.config.claude.effort || 'max';
          await this.sender.sendTextNotice(chatId, '⚡ Effort Level', `Current: **${current}**\n\nUsage: \`/effort low|medium|high|max\``, 'blue');
        } else if (VALID_LEVELS.includes(arg as any)) {
          const prev = this.config.claude.effort || 'max';
          this.config.claude.effort = arg as typeof VALID_LEVELS[number];
          await this.sender.sendTextNotice(chatId, '✅ Effort Level Changed', `**${prev}** → **${arg}**`, 'green');
        } else {
          await this.sender.sendTextNotice(chatId, '❌ Invalid Effort Level', `\`${arg}\` is not valid. Use: \`low\`, \`medium\`, \`high\`, or \`max\``, 'red');
        }
        return true;
      }

      case '/approve':
      case '/deny': {
        // Resolve the oldest pending dangerous-command approval in this chat.
        // `/approve` defaults to a one-shot 'once' allow; `/approve session`
        // adds to the session allowlist; `/approve always` adds to the
        // permanent allowlist (persisted across restarts via Phase 5).
        if (!this.approvalBridge) {
          await this.sender.sendTextNotice(chatId, 'ℹ️ Not Available', 'Approval commands are not supported on this platform.', 'blue');
          return true;
        }
        let choice: 'once' | 'session' | 'always' | 'deny';
        if (cmd.toLowerCase() === '/deny') {
          choice = 'deny';
        } else {
          // Parse optional scope: `/approve`, `/approve session`, `/approve always`.
          const arg = text.slice('/approve'.length).trim().toLowerCase();
          if (arg === '' || arg === 'once') {
            choice = 'once';
          } else if (arg === 'session' || arg === 'always') {
            choice = arg;
          } else {
            await this.sender.sendTextNotice(
              chatId,
              '❌ Invalid Scope',
              `\`${arg}\` is not valid. Use: \`/approve\` (once), \`/approve session\`, or \`/approve always\`.`,
              'red',
            );
            return true;
          }
        }
        const resolved = this.approvalBridge.resolveNextByText(buildSessionKey(this.config.name, chatId), choice, userId);
        if (resolved === 0) {
          await this.sender.sendTextNotice(chatId, 'ℹ️ No Pending Approval', 'There is no dangerous-command approval waiting in this chat.', 'blue');
        }
        return true;
      }

      case '/approvals': {
        // List the current approval state for this chat: session allowlist,
        // permanent allowlist, and YOLO status. Intentionally does NOT show
        // other chats' session approvals — each chat is its own session.
        const sessionKey = buildSessionKey(this.config.name, chatId);
        const sessionKeys = approvalStore.getSessionApprovals(sessionKey);
        const permanentKeys = approvalStore.getPermanentApprovals();
        const yolo = approvalStore.isYolo(sessionKey);
        const lines: string[] = [];
        lines.push(`**YOLO Mode:** ${yolo ? '🤠 on' : 'off'}`);
        lines.push('');
        lines.push(`**Session allowlist** (${sessionKeys.length}):`);
        if (sessionKeys.length === 0) {
          lines.push('_None_');
        } else {
          for (const k of sessionKeys) lines.push(`- \`${k}\``);
        }
        lines.push('');
        lines.push(`**Permanent allowlist** (${permanentKeys.length}):`);
        if (permanentKeys.length === 0) {
          lines.push('_None_');
        } else {
          for (const k of permanentKeys) lines.push(`- \`${k}\``);
        }
        lines.push('');
        lines.push('_Use `/revoke <pattern>` to remove a permanent entry._');
        await this.sender.sendTextNotice(chatId, '🛡 Approvals', lines.join('\n'), 'blue');
        return true;
      }

      case '/revoke': {
        // Remove a pattern from the permanent allowlist. The session
        // allowlist is per-chat ephemeral state cleared by /reset, so we
        // don't expose a revoke for it — restart the session instead.
        const pattern = text.slice('/revoke'.length).trim();
        if (!pattern) {
          const all = approvalStore.getPermanentApprovals();
          if (all.length === 0) {
            await this.sender.sendTextNotice(
              chatId,
              '🛡 Revoke',
              'Usage: `/revoke <pattern>`\n\n_Permanent allowlist is empty._',
              'blue',
            );
          } else {
            const list = all.map((k) => `- \`${k}\``).join('\n');
            await this.sender.sendTextNotice(
              chatId,
              '🛡 Revoke',
              `Usage: \`/revoke <pattern>\`\n\n**Current permanent allowlist:**\n${list}`,
              'blue',
            );
          }
          return true;
        }
        const removed = approvalStore.revokePermanent(pattern);
        if (removed) {
          this.audit.log({ event: 'approval_revoked', botName: this.config.name, chatId, userId, prompt: pattern });
          await this.sender.sendTextNotice(
            chatId,
            '✅ Revoked',
            `\`${pattern}\` removed from the permanent allowlist.`,
            'green',
          );
        } else {
          await this.sender.sendTextNotice(
            chatId,
            'ℹ️ Not Found',
            `\`${pattern}\` is not in the permanent allowlist. Use \`/approvals\` to see current entries.`,
            'blue',
          );
        }
        return true;
      }

      case '/yolo': {
        // `/yolo on|off` toggles auto-approval for this chat session.
        // Without args, reports the current state. YOLO does NOT persist
        // across sessions — it is cleared on /reset or process restart.
        const arg = text.slice('/yolo'.length).trim().toLowerCase();
        const sessionKey = buildSessionKey(this.config.name, chatId);
        if (!arg) {
          const on = approvalStore.isYolo(sessionKey);
          await this.sender.sendTextNotice(chatId, '🤠 YOLO Mode', `Current: **${on ? 'on' : 'off'}**\n\nUsage: \`/yolo on|off\`\n\nWhen on, all dangerous commands auto-approve for this chat.`, on ? 'orange' : 'blue');
        } else if (arg === 'on') {
          approvalStore.setYolo(sessionKey, true);
          await this.sender.sendTextNotice(chatId, '🤠 YOLO On', 'Dangerous commands will auto-approve for this chat. Use `/yolo off` to disable.', 'orange');
        } else if (arg === 'off') {
          approvalStore.setYolo(sessionKey, false);
          await this.sender.sendTextNotice(chatId, '✅ YOLO Off', 'Dangerous commands will prompt for approval again.', 'green');
        } else {
          await this.sender.sendTextNotice(chatId, '❌ Invalid Argument', `\`${arg}\` is not valid. Use: \`on\` or \`off\``, 'red');
        }
        return true;
      }

      case '/memory': {
        const args = text.slice('/memory'.length).trim();
        // Ensure metamemory skill is available to all Claude sessions
        ensureSkillInstalled('metamemory', this.logger).catch(() => {});
        await this.handleMemoryCommand(chatId, args);
        return true;
      }

      case '/sync': {
        const args = text.slice('/sync'.length).trim();
        await this.handleSyncCommand(chatId, args);
        return true;
      }

      case '/report-bug':
      case '/fix-issue':
      case '/request-feature':
        // Install contribution skills so Claude can use them regardless of working directory
        ensureSkillsInstalled(CONTRIBUTION_SKILLS, this.logger).catch(() => {});
        return false; // pass through to Claude

      case '/model': {
        const args = text.slice('/model'.length).trim();
        await this.handleModelCommand(chatId, args);
        return true;
      }

      default:
        // Unrecognized /xxx commands — not handled here, pass through to Claude
        return false;
    }
  }

  private async handleMemoryCommand(chatId: string, args: string): Promise<void> {
    const [subCmd, ...rest] = args.split(/\s+/);

    if (!subCmd) {
      await this.sender.sendTextNotice(
        chatId,
        '📝 Memory',
        'Usage:\n- `/memory list` — Show folder tree\n- `/memory search <query>` — Search documents\n- `/memory status` — Health check',
      );
      return;
    }

    try {
      switch (subCmd.toLowerCase()) {
        case 'list': {
          const tree = await this.memoryClient.listFolderTree();
          const formatted = this.memoryClient.formatFolderTree(tree);
          await this.sender.sendTextNotice(chatId, '📂 Memory Folders', formatted);
          break;
        }
        case 'search': {
          const query = rest.join(' ').trim();
          if (!query) {
            await this.sender.sendTextNotice(chatId, '📝 Memory', 'Usage: `/memory search <query>`');
            return;
          }
          const results = await this.memoryClient.search(query);
          const formatted = this.memoryClient.formatSearchResults(results);
          await this.sender.sendTextNotice(chatId, `🔍 Search: ${query}`, formatted);
          break;
        }
        case 'status': {
          const health = await this.memoryClient.health();
          await this.sender.sendTextNotice(
            chatId,
            '📝 Memory Status',
            `Status: ${health.status}\nDocuments: ${health.document_count}\nFolders: ${health.folder_count}`,
            'green',
          );
          break;
        }
        default:
          await this.sender.sendTextNotice(chatId, '📝 Memory', `Unknown sub-command: \`${subCmd}\`\nUse \`/memory\` for help.`, 'orange');
      }
    } catch (err: any) {
      this.logger.error({ err, chatId }, 'Memory command error');
      await this.sender.sendTextNotice(chatId, '❌ Memory Error', `Failed to connect to memory server: ${err.message}`, 'red');
    }
  }

  private async handleSyncCommand(chatId: string, args: string): Promise<void> {
    if (!this.docSync) {
      await this.sender.sendTextNotice(chatId, '❌ Sync Unavailable', 'Wiki sync is not configured for this bot.', 'red');
      return;
    }

    const [subCmd] = args.split(/\s+/);

    if (!subCmd) {
      // Default: trigger full sync
      if (this.docSync.isSyncing()) {
        await this.sender.sendTextNotice(chatId, '⏳ Sync In Progress', 'A sync is already running. Please wait.', 'orange');
        return;
      }

      await this.sender.sendTextNotice(chatId, '🔄 Sync Started', 'Syncing MetaMemory documents to Feishu Wiki...', 'blue');

      try {
        const result = await this.docSync.syncAll();
        const lines = [
          `**Created:** ${result.created}`,
          `**Updated:** ${result.updated}`,
          `**Skipped:** ${result.skipped} (unchanged)`,
          `**Deleted:** ${result.deleted}`,
          `**Duration:** ${(result.durationMs / 1000).toFixed(1)}s`,
        ];
        if (result.errors.length > 0) {
          lines.push('', `**Errors (${result.errors.length}):**`);
          for (const err of result.errors.slice(0, 5)) {
            lines.push(`- ${err}`);
          }
          if (result.errors.length > 5) {
            lines.push(`- ... and ${result.errors.length - 5} more`);
          }
        }
        const color = result.errors.length > 0 ? 'orange' : 'green';
        await this.sender.sendTextNotice(chatId, '✅ Sync Complete', lines.join('\n'), color);
      } catch (err: any) {
        this.logger.error({ err, chatId }, 'Sync command error');
        await this.sender.sendTextNotice(chatId, '❌ Sync Failed', err.message, 'red');
      }
      return;
    }

    switch (subCmd.toLowerCase()) {
      case 'status': {
        const stats = this.docSync.getStats();
        const spaceId = stats.wikiSpaceId || 'Not configured';
        await this.sender.sendTextNotice(chatId, '📊 Sync Status', [
          `**Wiki Space:** \`${spaceId}\``,
          `**Synced Documents:** ${stats.documentCount}`,
          `**Synced Folders:** ${stats.folderCount}`,
          `**Currently Syncing:** ${this.docSync.isSyncing() ? 'Yes' : 'No'}`,
        ].join('\n'));
        break;
      }
      default:
        await this.sender.sendTextNotice(chatId, '📝 Sync', 'Usage:\n- `/sync` — Sync all documents to Feishu Wiki\n- `/sync status` — Show sync status', 'blue');
    }
  }

  private async handleModelCommand(chatId: string, args: string): Promise<void> {
    const session = this.sessionManager.getSession(chatId);
    const botEngine = resolveEngineName(this.config);
    const activeEngine = session.engine ?? botEngine;
    const botDefault = this.defaultModelForEngine(activeEngine);

    // No args — show current model
    if (!args) {
      const active = session.model || botDefault || '_default_';
      const exampleModels = this.exampleModelsForEngine(activeEngine);
      const lines = [
        `**Engine:** \`${activeEngine}\`${session.engine ? ' (session override)' : ''}`,
        `**Active:** \`${active}\`${session.model ? ' (session override)' : ''}`,
        `**Bot default:** \`${botDefault || '_unset_'}\``,
        '',
        'Usage:',
        '- `/model list` — Show available engines + models',
        '- `/model claude`, `/model kimi`, or `/model codex` — Switch engine (resets session)',
        `- \`/model <name>\` — Set session model (e.g. ${exampleModels})`,
        '- `/model reset` — Clear overrides, use bot defaults',
      ];
      await this.sender.sendTextNotice(chatId, '🤖 Model', lines.join('\n'));
      return;
    }

    const normalized = args.toLowerCase();

    // Engine switch — /model claude, /model kimi, or /model codex
    if (isEngineName(normalized)) {
      if (activeEngine === normalized) {
        await this.sender.sendTextNotice(
          chatId,
          'ℹ️ Already using ' + normalized,
          `This chat is already on the \`${normalized}\` engine.`,
          'blue',
        );
        return;
      }
      this.sessionManager.setSessionEngine(chatId, normalized);
      await this.sender.sendTextNotice(
        chatId,
        `✅ Engine switched to ${normalized}`,
        [
          `Next message will run on the **${normalized}** engine.`,
          '',
          '_Session ID and model override cleared — a fresh conversation starts on the next turn._',
          this.authTipForEngine(normalized),
        ].join('\n'),
        'green',
      );
      return;
    }

    // List available models
    if (normalized === 'list' || normalized === 'ls') {
      const active = session.model || botDefault;
      const claudeModels = [
        { id: 'claude-opus-4-7', label: 'Opus 4.7', note: 'Most capable · 200k context' },
        { id: 'claude-opus-4-7[1m]', label: 'Opus 4.7 (1M)', note: '1M context window' },
        { id: 'claude-opus-4-6', label: 'Opus 4.6', note: '200k context' },
        { id: 'claude-opus-4-6[1m]', label: 'Opus 4.6 (1M)', note: '1M context window' },
        { id: 'claude-sonnet-4-6', label: 'Sonnet 4.6', note: 'Balanced · 200k context' },
        { id: 'claude-sonnet-4-6[1m]', label: 'Sonnet 4.6 (1M)', note: '1M context window' },
        { id: 'claude-haiku-4-5', label: 'Haiku 4.5', note: 'Fastest · 200k context' },
      ];
      const kimiModels = [
        { id: 'kimi-for-coding', label: 'Kimi for Coding', note: 'Subscription default · 256k context · thinking' },
        { id: 'kimi-k2', label: 'Kimi K2', note: 'Legacy coding model' },
      ];
      const codexModels = [
        { id: 'gpt-5.4-codex', label: 'GPT-5.4 Codex', note: 'Recommended Codex coding model' },
        { id: 'gpt-5.4', label: 'GPT-5.4', note: 'General flagship model' },
        { id: 'gpt-5.2-codex', label: 'GPT-5.2 Codex', note: 'Legacy Codex coding model' },
      ];
      const models = activeEngine === 'kimi' ? kimiModels : activeEngine === 'codex' ? codexModels : claudeModels;
      const header = activeEngine === 'kimi'
        ? '**Available Kimi models:**'
        : activeEngine === 'codex'
          ? '**Common Codex models:**'
          : '**Available Claude models:**';
      const lines = [
        `**Current engine:** \`${activeEngine}\`${session.engine ? ' (session override)' : ''}`,
        '',
        '**Engines:** `/model claude`, `/model kimi`, or `/model codex` to switch.',
        '',
        header,
        '',
      ];
      for (const m of models) {
        const marker = m.id === active ? ' ✅' : '';
        lines.push(`- \`${m.id}\` — ${m.label} · ${m.note}${marker}`);
      }
      lines.push('');
      if (activeEngine === 'claude') {
        lines.push('_Tip: append `[1m]` to a model name to enable the 1M context window. Only Opus 4.7/4.6 and Sonnet 4.6 support it._');
      } else if (activeEngine === 'codex') {
        lines.push('_Tip: leave unset to use the Codex CLI default from `~/.codex/config.toml`._');
      } else {
        lines.push('_Tip: leave unset to use the kimi-cli default (recommended for subscription users — the server picks the best available)._');
      }
      lines.push('Use `/model <name>` to set the model for the current engine.');
      await this.sender.sendTextNotice(chatId, '🤖 Available Models', lines.join('\n'));
      return;
    }

    // Reset — clear overrides (both engine AND model)
    if (normalized === 'reset' || normalized === 'clear' || normalized === 'default') {
      this.sessionManager.setSessionModel(chatId, undefined);
      this.sessionManager.setSessionEngine(chatId, undefined);
      const fallback = botDefault || '_default_';
      await this.sender.sendTextNotice(
        chatId,
        '✅ Overrides Cleared',
        `Session engine and model overrides cleared. Using bot defaults: engine \`${botEngine}\`, model \`${fallback}\`.`,
        'green',
      );
      return;
    }

    // Set the model (use only the first token, ignore trailing junk)
    const newModel = args.split(/\s+/)[0];
    this.sessionManager.setSessionModel(chatId, newModel, activeEngine);
    await this.sender.sendTextNotice(
      chatId,
      '✅ Model Set',
      `Session model set to \`${newModel}\` on engine \`${activeEngine}\`. It will take effect on the next message.`,
      'green',
    );
  }

  private defaultModelForEngine(engine: EngineName): string | undefined {
    switch (engine) {
      case 'claude':
        return this.config.claude.model;
      case 'kimi':
        return this.config.kimi?.model;
      case 'codex':
        return this.config.codex?.model || this.config.codex?.displayModel;
    }
  }

  private exampleModelsForEngine(engine: EngineName): string {
    switch (engine) {
      case 'claude':
        return '`claude-opus-4-7`, `claude-sonnet-4-6`, `claude-haiku-4-5`';
      case 'kimi':
        return '`kimi-for-coding`, `kimi-k2`';
      case 'codex':
        return '`gpt-5.4-codex`, `gpt-5.4`, `gpt-5.2-codex`';
    }
  }

  private authTipForEngine(engine: EngineName): string {
    switch (engine) {
      case 'claude':
        return '_Make sure Claude Code is authenticated (`claude login`)._';
      case 'kimi':
        return '_Make sure `kimi login` has been completed on this host._';
      case 'codex':
        return '_Make sure Codex CLI is authenticated (`codex login`) or configured with an API key._';
    }
  }
}

function isEngineName(value: string): value is EngineName {
  return value === 'claude' || value === 'kimi' || value === 'codex';
}
