// Shared types used across IM platforms (Feishu, Telegram, etc.)

export type CardStatus = 'thinking' | 'running' | 'complete' | 'error' | 'waiting_for_input';

export interface ToolCall {
  name: string;
  detail: string;
  status: 'running' | 'done';
  input?: string;
  output?: string;
}

export interface PendingQuestion {
  toolUseId: string;
  questions: Array<{
    question: string;
    header: string;
    options: Array<{ label: string; description: string }>;
    multiSelect: boolean;
  }>;
}

/** A question the user has already answered — kept visible on the live card so the Q&A history isn't lost when Claude's stream resumes. */
export interface AnsweredQuestion {
  header: string;
  question: string;
  answer: string;
  /** Options that were available when the question was asked, so the Q&A history retains the full choice context. */
  options?: Array<{ label: string; description: string }>;
}

export interface SubagentTask {
  taskId: string;
  description: string;
  status: 'running' | 'completed' | 'failed' | 'stopped';
  summary?: string;
  usage?: { total_tokens: number; tool_uses: number; duration_ms: number };
  thinkingText?: string;
  toolCalls?: ToolCall[];
}

export interface CardState {
  status: CardStatus;
  userPrompt: string;
  responseText: string;
  thinkingText?: string;
  toolCalls: ToolCall[];
  toolSummaries?: string[];
  subagentTasks?: SubagentTask[];
  startTime?: number;
  costUsd?: number;
  durationMs?: number;
  errorMessage?: string;
  retryInfo?: string;
  pendingQuestion?: PendingQuestion;
  /** Questions already answered in the current turn — shown on the live card so the user can see what they replied after Claude resumes streaming. Cleared on turn recreate (previous Q&A is frozen into the Turn card). */
  answeredQuestions?: AnsweredQuestion[];
  /** Primary model used (e.g. "claude-opus-4-7") */
  model?: string;
  thinking?: string;
  effort?: string;
  sessionId?: string;
  workingDirectory?: string;
  numTurns?: number;
  /** Total input+output tokens consumed */
  totalTokens?: number;
  /** Context window size of the primary model */
  contextWindow?: number;
  /** Text from a just-completed assistant turn, ready to be sent as a separate message */
  completedTurnText?: string;
  /** SDK result text, sent as a separate message with stats at completion */
  resultSummary?: string;
  /** Custom card header title override (e.g. "Turn 1", "📊 Result") */
  cardTitle?: string;
  /** Cumulative session cost (USD), accumulated across queries until /reset */
  sessionCostUsd?: number;
}

export interface IncomingMessage {
  messageId: string;
  chatId: string;
  chatType: string;
  userId: string;
  text: string;
  imageKey?: string;
  fileKey?: string;
  fileName?: string;
  /** Additional media from batched messages (smart debounce). */
  extraMedia?: Array<{
    messageId: string;
    imageKey?: string;
    fileKey?: string;
    fileName?: string;
  }>;
}
