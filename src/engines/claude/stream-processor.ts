import type { SDKMessage } from './executor.js';
import type {
  BackgroundEvent,
  BackgroundTaskStatus,
  CardState,
  ToolCall,
  PendingQuestion,
  SubagentTask,
} from '../../feishu/card-builder.js';

const IMAGE_EXTENSIONS = new Set(['.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp', '.svg', '.tiff']);

/**
 * Tools that the Agent SDK auto-responds to in bypassPermissions mode
 * (the SDK already emits a tool_result, so the bridge must NOT send one
 * or Anthropic returns a duplicate tool_result error). We still detect
 * them here so the bridge can run side effects — e.g. surfacing plan
 * content as a separate chat message before the SDK continues.
 */
const SDK_HANDLED_TOOLS = new Set<string>(['ExitPlanMode', 'EnterPlanMode']);

export interface DetectedTool {
  toolUseId: string;
  name: string;
}

export interface StreamProcessorConfig {
  model?: string;
  thinking?: string;
  effort?: string;
  startTime?: number;
}

export class StreamProcessor {
  private responseText = '';
  private thinkingText = '';
  /** Text from the just-completed turn, consumed by the bridge after sending */
  private _completedTurnText: string | undefined;
  /** Last turn text emitted, used to deduplicate against SDK result */
  private _lastSentTurnText: string | undefined;
  /** SDK result text, stored separately so it doesn't overwrite responseText */
  private _resultSummary: string | undefined;
  /**
   * Running transcript of everything that surfaces in the chat: assistant turn
   * text, top-level tool outputs, and the SDK result summary. The bridge uses
   * this for ApiTaskResult.responseText so synchronous bus callers see what the
   * group chat sees — otherwise responseText is empty whenever the session
   * ends on tool calls (no trailing assistant text).
   */
  private _transcript: string[] = [];
  private toolCalls: ToolCall[] = [];
  private toolSummaries: string[] = [];
  private subagentTasks: Map<string, SubagentTask> = new Map();
  private subagentCurrentTools: Map<string, string | null> = new Map();
  private currentToolName: string | null = null;
  private sessionId: string | undefined;
  private costUsd: number | undefined;
  private durationMs: number | undefined;
  private numTurns: number | undefined;
  private _imagePaths: Set<string> = new Set();
  private _pendingQuestions: PendingQuestion[] = [];
  private _sdkHandledTools: DetectedTool[] = [];
  private _planFilePath: string | null = null;
  private _config: StreamProcessorConfig;
  private _model: string | undefined;
  private _totalTokens: number | undefined;
  private _contextWindow: number | undefined;
  // Track per-API-call usage from stream events for accurate context window display
  private _lastInputTokens: number | undefined;
  private _lastOutputTokens: number | undefined;
  // Live background tasks (Monitor, etc.) — task_id → latest rollup.
  private _backgroundEvents: Map<string, BackgroundEvent> = new Map();

  constructor(
    private userPrompt: string,
    config?: StreamProcessorConfig,
    private workingDirectory?: string,
  ) {
    this._config = config || {};
  }

  processMessage(message: SDKMessage): CardState {
    // Capture session_id from any message
    if (message.session_id) {
      this.sessionId = message.session_id;
    }

    switch (message.type) {
      case 'system':
        // SDK emits task_started / task_progress / task_notification / task_updated
        // as type='system' with a specific subtype. Surface them so Feishu can
        // show background task (e.g. Monitor) progress mid-turn.
        this.processSystemMessage(message);
        break;

      case 'assistant':
        this.processAssistantMessage(message);
        break;

      case 'user':
        this.processUserMessage(message);
        break;

      case 'result':
        return this.processResultMessage(message);

      case 'stream_event':
        this.processStreamEvent(message);
        break;

      case 'task_notification':
        // Codex translator synthesizes this shape for top-level error events.
        this.recordCodexTaskNotification(message);
        break;

      case 'tool_use_summary':
        if (message.summary) {
          this.toolSummaries.push(message.summary);
        }
        break;

      case 'tool_progress':
        // Update elapsed time on running tools
        if (message.tool_name) {
          const tool = this.toolCalls.find(
            (t) => t.name === message.tool_name && t.status === 'running',
          );
          if (tool && message.elapsed_time_seconds) {
            tool.detail = `${tool.detail} (${message.elapsed_time_seconds.toFixed(0)}s)`.trim();
          }
        }
        break;
    }

    // Determine running status
    // Determine running status
    const hasActiveTools = this.toolCalls.some((t) => t.status === 'running');
    const status = this._pendingQuestions.length > 0
      ? 'waiting_for_input'
      : hasActiveTools ? 'running' : this.responseText ? 'running' : 'thinking';

    // Capture and clear completedTurnText so it's only emitted once
    const turnText = this._completedTurnText;
    this._completedTurnText = undefined;

    return {
      status,
      userPrompt: this.userPrompt,
      responseText: this.responseText,
      completedTurnText: turnText,
      thinkingText: this.thinkingText || undefined,
      toolCalls: [...this.toolCalls],
      toolSummaries: this.toolSummaries.length > 0 ? [...this.toolSummaries] : undefined,
      subagentTasks: this.subagentTasks.size > 0 ? [...this.subagentTasks.values()] : undefined,
      startTime: this._config.startTime,
      costUsd: this.costUsd,
      durationMs: this.durationMs,
      model: this._model || this._config.model,
      totalTokens: this._totalTokens,
      contextWindow: this._contextWindow,
      pendingQuestion: this._pendingQuestions[0] || undefined,
      thinking: this._config.thinking,
      effort: this._config.effort,
      sessionId: this.sessionId,
      workingDirectory: this.workingDirectory,
      numTurns: this.numTurns,
      backgroundEvents: this._backgroundEvents.size > 0
        ? [...this._backgroundEvents.values()]
        : undefined,
    };
  }

  private recordTaskEvent(message: SDKMessage, subtype: string): void {
    const m = message as Record<string, unknown>;
    const taskId = typeof m.task_id === 'string' ? m.task_id : undefined;
    if (!taskId) return;

    // Ambient/housekeeping tasks (skip_transcript=true) stay hidden from the card.
    if (m.skip_transcript === true) return;

    const prior = this._backgroundEvents.get(taskId);
    const patch = (m.patch as Record<string, unknown> | undefined) ?? undefined;
    const description = typeof m.description === 'string'
      ? m.description
      : (typeof patch?.description === 'string' ? patch.description as string : prior?.description);

    let status: BackgroundTaskStatus = prior?.status ?? 'running';
    if (subtype === 'task_notification') {
      const s = typeof m.status === 'string' ? m.status : undefined;
      if (s === 'completed' || s === 'failed' || s === 'stopped') status = s;
    } else if (subtype === 'task_updated') {
      const s = typeof patch?.status === 'string' ? patch.status as string : undefined;
      if (s === 'completed') status = 'completed';
      else if (s === 'failed' || s === 'killed') status = 'failed';
      else if (s === 'running') status = 'running';
    }

    // SDKTaskNotificationMessage.summary carries the last-line event text for Monitor
    // and the final message for one-shot background tasks. SDKTaskProgressMessage
    // also exposes an optional summary for in-flight updates.
    const summary = typeof m.summary === 'string' ? m.summary : undefined;
    const lastEvent = summary ?? prior?.lastEvent;

    this._backgroundEvents.set(taskId, {
      taskId,
      description: description ?? prior?.description ?? 'background task',
      status,
      lastEvent,
    });
  }

  private recordCodexTaskNotification(message: SDKMessage): void {
    const m = message as Record<string, unknown>;
    const result = typeof m.result === 'string' ? m.result : undefined;
    if (!result) return;
    const taskId = typeof m.session_id === 'string' ? m.session_id : 'codex';
    this._backgroundEvents.set(taskId, {
      taskId,
      description: 'Codex notification',
      status: 'running',
      lastEvent: result,
    });
  }

  private processAssistantMessage(message: SDKMessage): void {
    if (!message.message?.content) return;

    const isSubagent = message.parent_tool_use_id !== null && message.parent_tool_use_id !== undefined;

    if (isSubagent) {
      const task = this.getOrCreateSubagentTask(message.parent_tool_use_id!);
      for (const block of message.message.content) {
        if (block.type === 'thinking' && block.thinking) {
          task.thinkingText = block.thinking;
        } else if (block.type === 'tool_use' && block.name) {
          if (!task.toolCalls) task.toolCalls = [];
          this.completeSubagentTool(message.parent_tool_use_id!);
          const detail = formatToolDetail(block.name, block.input);
          const inputStr = formatToolInput(block.name, block.input);
          task.toolCalls.push({ name: block.name, detail, status: 'running', input: inputStr || undefined });
          this.subagentCurrentTools.set(message.parent_tool_use_id!, block.name);
        } else if (block.type === 'tool_result') {
          const output = extractToolOutput(block.content);
          this.completeSubagentTool(message.parent_tool_use_id!, output);
        }
      }
      return;
    }

    for (const block of message.message.content) {
      if (block.type === 'thinking' && block.thinking) {
        this.thinkingText = block.thinking;
      } else if (block.type === 'text' && block.text) {
        // Emit completed turn text for the bridge to send as a separate message.
        // Then reset responseText so the card is clean for the next turn's streaming.
        this._completedTurnText = block.text;
        this._lastSentTurnText = block.text;
        this.responseText = '';
        this._transcript.push(block.text);
      } else if (block.type === 'tool_use' && block.name) {
        this.addToolCall(block.name, block.input);
        if (block.name === 'AskUserQuestion' && block.id && block.input) {
          this.extractPendingQuestion(block.id, block.input);
        } else if (SDK_HANDLED_TOOLS.has(block.name) && block.id) {
          this._sdkHandledTools.push({ toolUseId: block.id, name: block.name });
        }
      } else if (block.type === 'tool_result') {
        const output = extractToolOutput(block.content);
        this.completeCurrentTool(output);
      }
    }
  }

  private processUserMessage(message: SDKMessage): void {
    if (!message.message?.content) return;

    const isSubagent = message.parent_tool_use_id !== null && message.parent_tool_use_id !== undefined;

    for (const block of message.message.content) {
      if (block.type === 'tool_result') {
        const output = extractToolOutput(block.content);
        if (isSubagent) {
          this.completeSubagentTool(message.parent_tool_use_id!, output);
        } else {
          this.completeCurrentTool(output);
        }
      }
    }
  }

  private getOrCreateSubagentTask(taskId: string): SubagentTask {
    let task = this.subagentTasks.get(taskId);
    if (!task) {
      task = { taskId, description: 'Subagent task', status: 'running', toolCalls: [] };
      this.subagentTasks.set(taskId, task);
    }
    return task;
  }

  private completeSubagentTool(taskId: string, output?: string): void {
    const currentName = this.subagentCurrentTools.get(taskId);
    if (!currentName) return;
    const task = this.subagentTasks.get(taskId);
    if (!task?.toolCalls) return;
    const tool = [...task.toolCalls].reverse().find(t => t.name === currentName && t.status === 'running');
    if (tool) {
      tool.status = 'done';
      if (output) tool.output = output;
    }
    this.subagentCurrentTools.set(taskId, null);
  }

  private processStreamEvent(message: SDKMessage): void {
    const event = message.event;
    if (!event) return;

    // Track message_start/message_delta from ALL levels (not just top-level)
    // because these carry per-API-call token usage needed for context display
    if (event.type === 'message_start') {
      const usage = (event as any).message?.usage;
      if (usage) {
        this._lastInputTokens = (usage.input_tokens ?? 0)
          + (usage.cache_read_input_tokens ?? 0)
          + (usage.cache_creation_input_tokens ?? 0);
      }
    } else if (event.type === 'message_delta') {
      const usage = (event as any).usage;
      if (usage?.output_tokens != null) {
        this._lastOutputTokens = usage.output_tokens;
      }
    }

    // Handle subagent stream events
    if (message.parent_tool_use_id !== null && message.parent_tool_use_id !== undefined) {
      const taskId = message.parent_tool_use_id;
      const task = this.getOrCreateSubagentTask(taskId);
      if (!task.toolCalls) task.toolCalls = [];

      if (event.type === 'content_block_start') {
        const block = event.content_block;
        if (block?.type === 'tool_use' && block.name) {
          this.completeSubagentTool(taskId);
          const detail = formatToolDetail(block.name, undefined);
          task.toolCalls.push({ name: block.name, detail, status: 'running' });
          this.subagentCurrentTools.set(taskId, block.name);
        }
      } else if (event.type === 'content_block_delta') {
        const delta = event.delta;
        if (delta?.type === 'thinking_delta' && delta.thinking) {
          task.thinkingText = (task.thinkingText || '') + delta.thinking;
        }
      }
      return;
    }

    if (event.type === 'content_block_start') {
      const block = event.content_block;
      if (block?.type === 'tool_use' && block.name) {
        this.addToolCall(block.name, undefined);
      }
      if (block?.type === 'text') {
        // Reset for new text block
      }
    } else if (event.type === 'content_block_delta') {
      const delta = event.delta;
      if (delta?.type === 'thinking_delta' && delta.thinking) {
        this.thinkingText += delta.thinking;
      } else if (delta?.type === 'text_delta' && delta.text) {
        this.responseText += delta.text;
      }
    } else if (event.type === 'content_block_stop') {
      // Tool may be complete
      // Actual completion is tracked via assistant messages
    }
  }

  private processSystemMessage(message: SDKMessage): void {
    if (!message.subtype) return;

    // Surface background task events (Monitor, etc.) regardless of whether they
    // also represent a subagent. recordTaskEvent filters skip_transcript=true.
    if (
      message.subtype === 'task_started'
      || message.subtype === 'task_progress'
      || message.subtype === 'task_notification'
      || message.subtype === 'task_updated'
    ) {
      this.recordTaskEvent(message, message.subtype);
    }

    switch (message.subtype) {
      case 'task_started':
        if (message.task_id) {
          const existing = this.subagentTasks.get(message.task_id);
          if (existing) {
            // Merge: update description but preserve any tool calls already captured
            existing.description = message.description || message.prompt || existing.description;
          } else {
            this.subagentTasks.set(message.task_id, {
              taskId: message.task_id,
              description: message.description || message.prompt || 'Subagent task',
              status: 'running',
              toolCalls: [],
            });
          }
        }
        break;

      case 'task_progress':
        if (message.task_id) {
          const task = this.subagentTasks.get(message.task_id);
          if (task) {
            if (message.summary) task.summary = message.summary;
            if (message.usage) task.usage = message.usage;
            // last_tool_name is the SDK's way of reporting subagent tool usage
            if (message.last_tool_name) {
              if (!task.toolCalls) task.toolCalls = [];
              const last = task.toolCalls[task.toolCalls.length - 1];
              // Avoid duplicating consecutive identical tool names
              if (!last || last.name !== message.last_tool_name || last.status === 'done') {
                // Mark previous running tool done before adding new one
                if (last && last.status === 'running') last.status = 'done';
                task.toolCalls.push({ name: message.last_tool_name, detail: '', status: 'running' });
              }
            }
          }
        }
        break;

      case 'task_notification':
        if (message.task_id) {
          const task = this.subagentTasks.get(message.task_id);
          if (task) {
            task.status = (message.status as SubagentTask['status']) || 'completed';
            if (message.summary) task.summary = message.summary;
            if (message.usage) task.usage = message.usage;
            if (message.last_tool_name) {
              if (!task.toolCalls) task.toolCalls = [];
              const last = task.toolCalls[task.toolCalls.length - 1];
              if (!last || last.name !== message.last_tool_name) {
                task.toolCalls.push({ name: message.last_tool_name, detail: '', status: 'done' });
              }
            }
            // Mark all running tools as done when task completes
            if (task.toolCalls) {
              for (const t of task.toolCalls) {
                if (t.status === 'running') t.status = 'done';
              }
            }
          }
        }
        break;
    }
  }

  private processResultMessage(message: SDKMessage): CardState {
    this.costUsd = message.total_cost_usd;
    this.durationMs = message.duration_ms;
    if (message.num_turns !== undefined) {
      this.numTurns = message.num_turns;
    }

    // Extract model usage info (per-model breakdown from SDK)
    if (message.modelUsage) {
      const models = Object.keys(message.modelUsage);
      if (models.length > 0) {
        // Primary model is the one with highest cost
        const primaryModel = models.reduce((a, b) =>
          (message.modelUsage![a].costUSD ?? 0) >= (message.modelUsage![b].costUSD ?? 0) ? a : b
        );
        const mu = message.modelUsage[primaryModel];
        this._model = primaryModel;
        this._contextWindow = mu.contextWindow;
        // Use last API call's tokens from stream events (accurate context window occupation)
        // Falls back to cumulative modelUsage input+output if stream events weren't captured
        if (this._lastInputTokens != null) {
          this._totalTokens = this._lastInputTokens + (this._lastOutputTokens ?? 0);
        } else {
          let totalTokens = 0;
          for (const m of models) {
            totalTokens += (message.modelUsage![m].inputTokens ?? 0);
            totalTokens += (message.modelUsage![m].outputTokens ?? 0);
          }
          this._totalTokens = totalTokens;
        }
      }
    }

    // Mark all tools as done
    for (const tool of this.toolCalls) {
      tool.status = 'done';
    }

    const resultText = message.result || '';
    const isError = message.subtype !== 'success';
    // SDK sometimes wraps API errors as "success" with the error text as result
    const isApiError = !isError && isApiErrorResult(resultText);

    // Store result separately — only if it differs from the last turn text already sent.
    // SDK result often echoes the last assistant message; skip to avoid duplication.
    this._resultSummary = (resultText && resultText !== this._lastSentTurnText) ? resultText : undefined;
    if (this._resultSummary && !isApiError) {
      this._transcript.push(`[Result]\n${this._resultSummary}`);
    }

    return {
      status: (isError || isApiError) ? 'error' : 'complete',
      userPrompt: this.userPrompt,
      responseText: '',
      resultSummary: isApiError ? undefined : this._resultSummary,
      thinkingText: this.thinkingText || undefined,
      toolCalls: [...this.toolCalls],
      toolSummaries: this.toolSummaries.length > 0 ? [...this.toolSummaries] : undefined,
      subagentTasks: this.subagentTasks.size > 0 ? [...this.subagentTasks.values()] : undefined,
      startTime: this._config.startTime,
      costUsd: this.costUsd,
      durationMs: this.durationMs,
      errorMessage: isError
        ? (message.errors?.join('; ') || `Ended with: ${message.subtype}`)
        : isApiError ? resultText : undefined,
      model: this._model || this._config.model,
      thinking: this._config.thinking,
      effort: this._config.effort,
      sessionId: this.sessionId,
      workingDirectory: this.workingDirectory,
      numTurns: this.numTurns,
      totalTokens: this._totalTokens,
      contextWindow: this._contextWindow,
      backgroundEvents: this._backgroundEvents.size > 0
        ? [...this._backgroundEvents.values()]
        : undefined,
    };
  }

  private addToolCall(name: string, input: unknown): void {
    // Complete previous tool
    this.completeCurrentTool();

    this.currentToolName = name;
    const detail = formatToolDetail(name, input);
    const inputStr = formatToolInput(name, input);
    this.toolCalls.push({ name, detail, status: 'running', input: inputStr || undefined });

    // Track image file paths and plan file paths from Write tool
    if (name === 'Write' && input && typeof input === 'object') {
      const filePath = (input as Record<string, unknown>).file_path as string;
      if (filePath && isImagePath(filePath)) {
        this._imagePaths.add(filePath);
      }
      if (filePath && filePath.includes('.claude/plans/') && filePath.endsWith('.md')) {
        this._planFilePath = filePath;
      }
    }
  }

  private completeCurrentTool(output?: string): void {
    if (this.currentToolName) {
      const tool = this.toolCalls.find(
        (t) => t.name === this.currentToolName && t.status === 'running',
      );
      if (tool) {
        tool.status = 'done';
        if (output) {
          tool.output = output;
          const header = tool.detail ? `[Tool: ${tool.name}] ${tool.detail}` : `[Tool: ${tool.name}]`;
          this._transcript.push(`${header}\n${output}`);
        }
      }
      this.currentToolName = null;
    }
  }

  private extractPendingQuestion(toolUseId: string, input: unknown): void {
    if (!input || typeof input !== 'object') return;
    const inp = input as Record<string, unknown>;
    const questions = inp.questions;
    if (!Array.isArray(questions)) return;

    const parsed = questions.map((q: any) => ({
      question: String(q.question || ''),
      header: String(q.header || ''),
      options: Array.isArray(q.options)
        ? q.options.map((o: any) => ({
            label: String(o.label || ''),
            description: String(o.description || ''),
          }))
        : [],
      multiSelect: Boolean(q.multiSelect),
    }));

    // Queue instead of overwrite — supports multiple AskUserQuestion calls
    this._pendingQuestions.push({ toolUseId, questions: parsed });
  }

  /** Remove the first pending question (after it's been fully answered). */
  clearPendingQuestion(): void {
    this._pendingQuestions.shift();
  }

  /** Peek at the first pending question without removing it. */
  getPendingQuestion(): PendingQuestion | null {
    return this._pendingQuestions[0] ?? null;
  }

  /**
   * Get and clear any tools the SDK handles itself (e.g. ExitPlanMode,
   * EnterPlanMode). The bridge uses the returned list to run side effects
   * such as sending the plan content as a separate message — it must NOT
   * push its own tool_result, since the SDK already did.
   */
  drainSdkHandledTools(): DetectedTool[] {
    if (this._sdkHandledTools.length === 0) return [];
    const tools = [...this._sdkHandledTools];
    this._sdkHandledTools = [];
    return tools;
  }

  /** Return the current card state without processing a new message. */
  getCurrentState(): CardState {
    const hasActiveTools = this.toolCalls.some((t) => t.status === 'running');
    const status = this._pendingQuestions.length > 0
      ? 'waiting_for_input'
      : hasActiveTools ? 'running' : this.responseText ? 'running' : 'thinking';
    return {
      status,
      userPrompt: this.userPrompt,
      responseText: this.responseText,
      thinkingText: this.thinkingText || undefined,
      toolCalls: [...this.toolCalls],
      toolSummaries: this.toolSummaries.length > 0 ? [...this.toolSummaries] : undefined,
      subagentTasks: this.subagentTasks.size > 0 ? [...this.subagentTasks.values()] : undefined,
      startTime: this._config.startTime,
      costUsd: this.costUsd,
      durationMs: this.durationMs,
      model: this._model || this._config.model,
      totalTokens: this._totalTokens,
      contextWindow: this._contextWindow,
      pendingQuestion: this._pendingQuestions[0] || undefined,
      thinking: this._config.thinking,
      effort: this._config.effort,
      sessionId: this.sessionId,
      workingDirectory: this.workingDirectory,
      numTurns: this.numTurns,
      backgroundEvents: this._backgroundEvents.size > 0
        ? [...this._backgroundEvents.values()]
        : undefined,
    };
  }


  getSessionId(): string | undefined {
    return this.sessionId;
  }

  /**
   * Full transcript of the session as the chat saw it: each completed turn's
   * text, each top-level tool output (with a `[Tool: Name] detail` header),
   * the SDK result summary, and any in-progress text not yet flushed as a
   * completed turn. Joined with blank lines. Used by the bridge to populate
   * ApiTaskResult.responseText so sync bus callers receive the same content
   * the Feishu cards show.
   */
  getFullTranscript(): string {
    const parts = [...this._transcript];
    if (this.responseText) parts.push(this.responseText);
    return parts.join('\n\n').trim();
  }

  getImagePaths(): string[] {
    return [...this._imagePaths];
  }

  getPlanFilePath(): string | null {
    return this._planFilePath;
  }
}

function isImagePath(filePath: string): boolean {
  const ext = filePath.slice(filePath.lastIndexOf('.')).toLowerCase();
  return IMAGE_EXTENSIONS.has(ext);
}

/** Scan text for absolute image file paths */
export function extractImagePaths(text: string): string[] {
  const pathRegex = /\/[\w./_-]+\.(?:png|jpe?g|gif|webp|bmp|svg|tiff)/gi;
  const matches = text.match(pathRegex) || [];
  return [...new Set(matches)];
}

function formatToolDetail(name: string, input: unknown): string {
  if (!input || typeof input !== 'object') return '';

  const inp = input as Record<string, unknown>;

  switch (name) {
    case 'Read':
      return inp.file_path ? `\`${shortenPath(inp.file_path as string)}\`` : '';
    case 'Write':
      return inp.file_path ? `\`${shortenPath(inp.file_path as string)}\`` : '';
    case 'Edit':
      return inp.file_path ? `\`${shortenPath(inp.file_path as string)}\`` : '';
    case 'Bash':
      return inp.command ? `\`${truncate(inp.command as string, 60)}\`` : '';
    case 'Glob':
      return inp.pattern ? `\`${inp.pattern}\`` : '';
    case 'Grep':
      return inp.pattern ? `\`${inp.pattern}\`` : '';
    case 'WebSearch':
      return inp.query ? `"${truncate(inp.query as string, 50)}"` : '';
    case 'WebFetch':
      return inp.url ? `\`${truncate(inp.url as string, 60)}\`` : '';
    case 'Task':
      return inp.description ? `${inp.description}` : '';
    case 'AskUserQuestion': {
      const qs = inp.questions;
      if (Array.isArray(qs) && qs.length > 0) {
        const first = qs[0] as Record<string, unknown>;
        return first.question ? truncate(String(first.question), 50) : '';
      }
      return '';
    }
    default:
      return '';
  }
}

function shortenPath(filePath: string): string {
  const parts = filePath.split('/');
  if (parts.length <= 3) return filePath;
  return '.../' + parts.slice(-2).join('/');
}

function truncate(text: string, max: number): string {
  if (text.length <= max) return text;
  return text.slice(0, max) + '...';
}

function formatToolInput(name: string, input: unknown): string {
  if (!input || typeof input !== 'object') return '';
  const inp = input as Record<string, unknown>;

  switch (name) {
    case 'Read':
      return inp.file_path ? String(inp.file_path) : '';
    case 'Write':
    case 'Edit':
      return inp.file_path ? String(inp.file_path) : '';
    case 'Bash':
      return inp.command ? String(inp.command) : '';
    case 'Glob':
      return inp.pattern ? String(inp.pattern) : '';
    case 'Grep':
      return inp.pattern ? String(inp.pattern) : '';
    case 'WebSearch':
      return inp.query ? String(inp.query) : '';
    case 'WebFetch':
      return inp.url ? String(inp.url) : '';
    default:
      // For unknown tools, serialize the full input
      try {
        return JSON.stringify(input, null, 2);
      } catch {
        return '';
      }
  }
}

function extractToolOutput(content: unknown): string {
  if (!content) return '';
  if (typeof content === 'string') return content;
  // content can be an array of content blocks
  if (Array.isArray(content)) {
    return content
      .map((c: any) => (typeof c === 'string' ? c : c?.text || ''))
      .filter(Boolean)
      .join('\n');
  }
  try {
    return JSON.stringify(content);
  } catch {
    return '';
  }
}

/** Detect API error responses that the SDK wraps as successful results */
function isApiErrorResult(text: string): boolean {
  if (!text) return false;
  return /^API Error:\s*\d{3}\s/i.test(text);
}
