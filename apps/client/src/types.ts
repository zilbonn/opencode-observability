// New interface for human-in-the-loop requests
export interface HumanInTheLoop {
  question: string;
  responseWebSocketUrl: string;
  type: 'question' | 'permission' | 'choice';
  choices?: string[]; // For multiple choice questions
  timeout?: number; // Optional timeout in seconds
  requiresResponse?: boolean; // Whether response is required or optional
}

// Response interface
export interface HumanInTheLoopResponse {
  response?: string;
  permission?: boolean;
  choice?: string; // Selected choice from options
  hookEvent: HookEvent;
  respondedAt: number;
  respondedBy?: string; // Optional user identifier
}

// Status tracking interface
export interface HumanInTheLoopStatus {
  status: 'pending' | 'responded' | 'timeout' | 'error';
  respondedAt?: number;
  response?: HumanInTheLoopResponse;
}

export interface HookEvent {
  id?: number;
  source_app: string;
  session_id: string;
  hook_event_type: string;
  payload: Record<string, any>;
  chat?: any[];
  summary?: string;
  timestamp?: number;
  model_name?: string;

  // NEW: Optional HITL data
  humanInTheLoop?: HumanInTheLoop;
  humanInTheLoopStatus?: HumanInTheLoopStatus;
}

export interface FilterOptions {
  source_apps: string[];
  session_ids: string[];
  hook_event_types: string[];
}

export interface WebSocketMessage {
  type: 'initial' | 'event' | 'hitl_response';
  data: HookEvent | HookEvent[] | HumanInTheLoopResponse;
}

export type TimeRange = '1m' | '3m' | '5m' | '10m';

export interface ChartDataPoint {
  timestamp: number;
  count: number;
  eventTypes: Record<string, number>; // event type -> count
  sessions: Record<string, number>; // session id -> count
}

export interface ChartConfig {
  maxDataPoints: number;
  animationDuration: number;
  barWidth: number;
  barGap: number;
  colors: {
    primary: string;
    glow: string;
    axis: string;
    text: string;
  };
}

// =====================================================
// METRICS TYPES - For Wardenn Security Assessment Tracking
// =====================================================

// Token usage tracking
export interface TokenMetric {
  id?: number;
  session_id: string;
  source_app: string;
  model_name?: string;
  input_tokens: number;
  output_tokens: number;
  total_tokens: number;
  estimated_cost: number;
  timestamp: number;
}

export interface TokenSummary {
  session_id?: string;
  total_input_tokens: number;
  total_output_tokens: number;
  total_tokens: number;
  total_cost: number;
  by_model: Record<string, { tokens: number; cost: number }>;
  by_agent: Record<string, { tokens: number; cost: number }>;
}

// Tool effectiveness tracking
export interface ToolMetric {
  id?: number;
  session_id: string;
  source_app: string;
  tool_name: string;
  tool_type?: 'mcp' | 'bash' | 'builtin' | 'other';
  status: 'success' | 'failure' | 'timeout';
  duration_ms?: number;
  found_vulnerability?: boolean;
  vulnerability_type?: string;
  error_message?: string;
  timestamp: number;
}

export interface ToolEffectivenessReport {
  tool_name: string;
  total_calls: number;
  success_count: number;
  failure_count: number;
  timeout_count: number;
  success_rate: number;
  avg_duration_ms: number;
  vulnerabilities_found: number;
}

// Security findings tracking
export interface Finding {
  id?: number;
  session_id: string;
  source_app: string;
  finding_id: string;
  vulnerability_type: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence: 'confirmed' | 'likely' | 'possible';
  wstg_id?: string;
  tool_used?: string;
  target_url?: string;
  location?: string;
  title?: string;
  description?: string;
  timestamp: number;
}

export interface FindingSummary {
  total_findings: number;
  by_severity: Record<string, number>;
  by_type: Record<string, number>;
  by_agent: Record<string, number>;
  by_confidence: Record<string, number>;
}

// WSTG coverage tracking
export interface WSTGCoverage {
  id?: number;
  session_id: string;
  source_app: string;
  wstg_id: string;
  wstg_name?: string;
  status: 'executed' | 'skipped' | 'partial' | 'not_applicable';
  skip_reason?: string;
  findings_count: number;
  timestamp: number;
}

export interface WSTGCoverageReport {
  total_tests: number;
  executed: number;
  skipped: number;
  partial: number;
  not_applicable: number;
  coverage_percentage: number;
  by_category: Record<string, { executed: number; total: number; percentage: number }>;
}

// Session summary
export interface SessionSummary {
  id?: number;
  session_id: string;
  client_name?: string;
  target_url?: string;
  status: 'running' | 'completed' | 'failed' | 'timeout';
  started_at: number;
  ended_at?: number;
  duration_ms?: number;
  total_tokens: number;
  total_cost: number;
  total_findings: number;
  total_tool_calls: number;
  agents_used: string[];
  wstg_coverage_pct: number;
}

// Metrics dashboard summary
export interface MetricsDashboard {
  sessions: {
    total: number;
    running: number;
    completed: number;
    failed: number;
  };
  tokens: TokenSummary;
  findings: FindingSummary;
  tools: ToolEffectivenessReport[];
  wstg: WSTGCoverageReport;
}