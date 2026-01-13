/**
 * OpenCode Observability Plugin
 *
 * Sends OpenCode events to the multi-agent observability server.
 * Compatible with the claude-code-hooks-multi-agent-observability system.
 *
 * Events are sent to http://localhost:4000/events in the same format
 * as Claude Code hooks, allowing both tools to use the same dashboard.
 *
 * METRICS TRACKING:
 * - Token usage (estimated from model responses)
 * - Tool effectiveness (duration, success/failure, vulnerabilities found)
 * - Security findings (parsed from tool outputs)
 * - WSTG coverage (tracked when WSTG MCP tools are used)
 * - Session management (lifecycle tracking)
 */

const SERVER_URL = process.env.OBSERVABILITY_SERVER_URL || 'http://localhost:4000/events';
const METRICS_BASE_URL = process.env.OBSERVABILITY_METRICS_URL || 'http://localhost:4000';

// Model cost estimates per 1M tokens (input/output)
const MODEL_COSTS = {
  'claude-opus-4': { input: 15.00, output: 75.00 },
  'claude-opus-4-5': { input: 15.00, output: 75.00 },
  'anthropic/claude-opus-4': { input: 15.00, output: 75.00 },
  'anthropic/claude-opus-4-5': { input: 15.00, output: 75.00 },
  'claude-sonnet-4': { input: 3.00, output: 15.00 },
  'anthropic/claude-sonnet-4': { input: 3.00, output: 15.00 },
  'claude-haiku-3.5': { input: 0.80, output: 4.00 },
  'anthropic/claude-haiku-3.5': { input: 0.80, output: 4.00 },
  'claude-3-opus': { input: 15.00, output: 75.00 },
  'claude-3-sonnet': { input: 3.00, output: 15.00 },
  'claude-3-haiku': { input: 0.25, output: 1.25 },
};

// Severity patterns for finding detection
const SEVERITY_PATTERNS = {
  critical: /critical|crit|severity:\s*critical/i,
  high: /high|severity:\s*high/i,
  medium: /medium|med|severity:\s*medium/i,
  low: /low|severity:\s*low|informational/i,
  info: /info|severity:\s*info/i,
};

// Vulnerability type patterns
const VULN_PATTERNS = {
  'SQL Injection': /sql\s*injection|sqli|' or |" or |union\s+select/i,
  'XSS': /cross.site\s*scripting|xss|<script|javascript:/i,
  'Command Injection': /command\s*injection|os\s*injection|rce|remote\s*code/i,
  'Path Traversal': /path\s*traversal|directory\s*traversal|\.\.\/|\.\.\\|lfi|local\s*file/i,
  'SSRF': /ssrf|server.side\s*request/i,
  'XXE': /xxe|xml\s*external\s*entity/i,
  'IDOR': /idor|insecure\s*direct\s*object/i,
  'Authentication Bypass': /auth.*bypass|authentication\s*bypass/i,
  'Information Disclosure': /information\s*disclosure|sensitive\s*data|exposed/i,
  'CSRF': /csrf|cross.site\s*request\s*forgery/i,
  'Open Redirect': /open\s*redirect|url\s*redirect/i,
  'Security Misconfiguration': /misconfiguration|misconfig|default\s*credential/i,
};

// WSTG ID patterns
const WSTG_PATTERNS = {
  'WSTG-INPV-05': /sql\s*injection|sqli/i,
  'WSTG-INPV-01': /reflected.*xss|xss/i,
  'WSTG-INPV-02': /stored.*xss/i,
  'WSTG-INPV-12': /command\s*injection/i,
  'WSTG-ATHZ-01': /path\s*traversal|directory\s*traversal/i,
  'WSTG-INPV-19': /ssrf/i,
  'WSTG-INPV-07': /xxe/i,
  'WSTG-ATHZ-04': /idor/i,
  'WSTG-ATHN-04': /auth.*bypass/i,
  'WSTG-INFO-02': /information\s*disclosure/i,
  'WSTG-SESS-05': /csrf/i,
  'WSTG-CLNT-04': /open\s*redirect/i,
  'WSTG-CONF-06': /misconfiguration/i,
};

/**
 * Extract agent name from directory path
 */
function extractAgentName(directory) {
  if (!directory) return 'opencode';

  const wardennMatch = directory.match(/\/agents\/([^\/]+)\/?$/);
  if (wardennMatch) {
    return wardennMatch[1];
  }

  const projectMatch = directory.match(/\/([^\/]+)\/?$/);
  if (projectMatch) {
    return projectMatch[1];
  }

  return process.env.OBSERVABILITY_SOURCE_APP || 'opencode';
}

/**
 * Determine tool type from tool name
 */
function getToolType(toolName) {
  if (!toolName) return 'other';
  if (toolName.startsWith('mcp__')) return 'mcp';
  if (toolName === 'Bash' || toolName === 'bash') return 'bash';
  if (['Read', 'Write', 'Edit', 'Glob', 'Grep', 'WebFetch', 'WebSearch', 'Task', 'TodoWrite'].includes(toolName)) {
    return 'builtin';
  }
  return 'other';
}

/**
 * Parse nuclei output for findings
 */
function parseNucleiOutput(output) {
  const findings = [];
  if (!output || typeof output !== 'string') return findings;

  // Nuclei output pattern: [severity] [template-id] [protocol] target
  const nucleiPattern = /\[(\w+)\]\s*\[([^\]]+)\]\s*\[([^\]]+)\]\s*(.+)/g;
  let match;

  while ((match = nucleiPattern.exec(output)) !== null) {
    const [, severity, templateId, protocol, target] = match;
    findings.push({
      severity: severity.toLowerCase(),
      vulnerability_type: templateId,
      target_url: target.trim(),
      tool_used: 'nuclei',
      confidence: 'confirmed',
    });
  }

  return findings;
}

/**
 * Parse Caido findings from output
 */
function parseCaidoOutput(output) {
  const findings = [];
  if (!output || typeof output !== 'string') return findings;

  // Look for vulnerability indicators in Caido output
  for (const [vulnType, pattern] of Object.entries(VULN_PATTERNS)) {
    if (pattern.test(output)) {
      let severity = 'medium';
      for (const [sev, sevPattern] of Object.entries(SEVERITY_PATTERNS)) {
        if (sevPattern.test(output)) {
          severity = sev;
          break;
        }
      }

      // Find matching WSTG ID
      let wstgId = null;
      for (const [id, wstgPattern] of Object.entries(WSTG_PATTERNS)) {
        if (wstgPattern.test(vulnType) || wstgPattern.test(output)) {
          wstgId = id;
          break;
        }
      }

      findings.push({
        severity,
        vulnerability_type: vulnType,
        wstg_id: wstgId,
        tool_used: 'caido',
        confidence: 'possible',
      });
    }
  }

  return findings;
}

/**
 * Detect findings from any tool output
 */
function detectFindings(toolName, output) {
  const findings = [];
  if (!output) return findings;

  const outputStr = typeof output === 'string' ? output : JSON.stringify(output);

  // Tool-specific parsing
  if (toolName === 'Bash' && outputStr.includes('[')) {
    // Could be nuclei output
    findings.push(...parseNucleiOutput(outputStr));
  }

  if (toolName?.includes('caido')) {
    findings.push(...parseCaidoOutput(outputStr));
  }

  // Generic vulnerability detection if no specific findings yet
  if (findings.length === 0) {
    for (const [vulnType, pattern] of Object.entries(VULN_PATTERNS)) {
      if (pattern.test(outputStr)) {
        let severity = 'medium';
        for (const [sev, sevPattern] of Object.entries(SEVERITY_PATTERNS)) {
          if (sevPattern.test(outputStr)) {
            severity = sev;
            break;
          }
        }

        let wstgId = null;
        for (const [id, wstgPattern] of Object.entries(WSTG_PATTERNS)) {
          if (wstgPattern.test(vulnType)) {
            wstgId = id;
            break;
          }
        }

        findings.push({
          severity,
          vulnerability_type: vulnType,
          wstg_id: wstgId,
          tool_used: toolName,
          confidence: 'possible',
        });
        break; // Only report first match per output
      }
    }
  }

  return findings;
}

/**
 * Send event to observability server (existing events endpoint)
 */
async function sendEvent(eventType, payload, sessionId, sourceApp, modelName = '') {
  try {
    const eventData = {
      source_app: sourceApp,
      session_id: sessionId || 'unknown',
      hook_event_type: eventType,
      payload: payload,
      timestamp: Date.now(),
      model_name: modelName
    };

    const response = await fetch(SERVER_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'OpenCode-Observability-Plugin/1.0'
      },
      body: JSON.stringify(eventData)
    });

    if (!response.ok && process.env.OBSERVABILITY_DEBUG) {
      console.error(`[Observability] Failed to send event: ${response.status}`);
    }
  } catch (error) {
    if (process.env.OBSERVABILITY_DEBUG) {
      console.error(`[Observability] Error sending event: ${error.message}`);
    }
  }
}

/**
 * Send metric to observability server (new metrics endpoints)
 */
async function sendMetric(endpoint, data) {
  try {
    const response = await fetch(`${METRICS_BASE_URL}${endpoint}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'OpenCode-Observability-Plugin/1.0'
      },
      body: JSON.stringify(data)
    });

    if (!response.ok && process.env.OBSERVABILITY_DEBUG) {
      console.error(`[Observability] Failed to send metric to ${endpoint}: ${response.status}`);
    }
    return response.ok;
  } catch (error) {
    if (process.env.OBSERVABILITY_DEBUG) {
      console.error(`[Observability] Error sending metric: ${error.message}`);
    }
    return false;
  }
}

/**
 * Main plugin export
 */
export const ObservabilityPlugin = async ({ project, client, $, directory, worktree }) => {
  const agentName = extractAgentName(directory);
  const currentSessionId = `${agentName}-${Date.now()}-${Math.random().toString(36).substr(2, 8)}`;
  const currentModel = process.env.OPENCODE_MODEL || 'anthropic/claude-opus-4-5';

  console.log(`[Observability] Plugin loaded for agent: ${agentName}`);
  console.log(`[Observability] Session ID: ${currentSessionId}`);
  console.log(`[Observability] Metrics tracking enabled`);

  // Cache for tracking tool execution timing
  const toolTimingCache = new Map();
  const argsCache = new Map();

  // Tracking counters for this session
  let totalToolCalls = 0;
  let totalFindings = 0;
  let findingCounter = 0;
  const wstgCoverage = new Set();
  const agentsUsed = new Set([agentName]);

  // Create session on startup
  const createSession = async () => {
    await sendMetric('/api/sessions', {
      session_id: currentSessionId,
      client_name: project?.name || agentName,
      target_url: process.env.TARGET_URL || null,
      status: 'running',
      started_at: Date.now(),
      total_tokens: 0,
      total_cost: 0,
      total_findings: 0,
      total_tool_calls: 0,
      agents_used: [agentName],
      wstg_coverage_pct: 0
    });
  };

  // Update session with current stats
  const updateSession = async (status = 'running') => {
    await sendMetric('/api/sessions', {
      session_id: currentSessionId,
      status,
      total_findings: totalFindings,
      total_tool_calls: totalToolCalls,
      agents_used: Array.from(agentsUsed),
      wstg_coverage_pct: (wstgCoverage.size / 91) * 100, // 91 WSTG tests total
      ...(status !== 'running' ? { ended_at: Date.now() } : {})
    });
  };

  // Record tool metric
  const recordToolMetric = async (toolName, status, durationMs, foundVuln = false, vulnType = null, errorMsg = null) => {
    totalToolCalls++;

    await sendMetric('/api/metrics/tools', {
      session_id: currentSessionId,
      source_app: agentName,
      tool_name: toolName,
      tool_type: getToolType(toolName),
      status,
      duration_ms: durationMs,
      found_vulnerability: foundVuln,
      vulnerability_type: vulnType,
      error_message: errorMsg,
      timestamp: Date.now()
    });
  };

  // Record finding
  const recordFinding = async (finding) => {
    findingCounter++;
    totalFindings++;

    const findingData = {
      session_id: currentSessionId,
      source_app: agentName,
      finding_id: `${agentName}-${currentSessionId.slice(-8)}-${findingCounter}`,
      vulnerability_type: finding.vulnerability_type,
      severity: finding.severity || 'medium',
      confidence: finding.confidence || 'possible',
      wstg_id: finding.wstg_id || null,
      tool_used: finding.tool_used || null,
      target_url: finding.target_url || null,
      location: finding.location || null,
      title: finding.title || finding.vulnerability_type,
      description: finding.description || null,
      timestamp: Date.now()
    };

    await sendMetric('/api/metrics/findings', findingData);

    // Track WSTG coverage if we have a WSTG ID
    if (finding.wstg_id) {
      await recordWSTGCoverage(finding.wstg_id, 'executed', finding.vulnerability_type ? 1 : 0);
    }
  };

  // Record WSTG coverage
  const recordWSTGCoverage = async (wstgId, status = 'executed', findingsCount = 0) => {
    if (wstgCoverage.has(wstgId)) return; // Already recorded
    wstgCoverage.add(wstgId);

    await sendMetric('/api/metrics/wstg', {
      session_id: currentSessionId,
      source_app: agentName,
      wstg_id: wstgId,
      wstg_name: null, // Could be looked up from WSTG database
      status,
      findings_count: findingsCount,
      timestamp: Date.now()
    });
  };

  // Record token usage (estimated)
  const recordTokenUsage = async (inputTokens, outputTokens) => {
    const modelKey = Object.keys(MODEL_COSTS).find(k => currentModel.includes(k)) || 'claude-opus-4';
    const costs = MODEL_COSTS[modelKey] || { input: 15.00, output: 75.00 };

    const estimatedCost = (inputTokens * costs.input / 1000000) + (outputTokens * costs.output / 1000000);

    await sendMetric('/api/metrics/tokens', {
      session_id: currentSessionId,
      source_app: agentName,
      model_name: currentModel,
      input_tokens: inputTokens,
      output_tokens: outputTokens,
      total_tokens: inputTokens + outputTokens,
      estimated_cost: estimatedCost,
      timestamp: Date.now()
    });
  };

  // Initialize session
  await createSession();

  // Send initial SessionStart event (existing behavior)
  sendEvent('SessionStart', {
    session_id: currentSessionId,
    cwd: directory,
    project_name: project?.name || agentName
  }, currentSessionId, agentName, currentModel);

  return {
    /**
     * Tool execution started
     */
    "tool.execute.before": async ({ tool, sessionID, callID }, { args }) => {
      if (process.env.OBSERVABILITY_DEBUG) {
        console.log('[Observability] tool.execute.before:', tool);
      }

      const toolName = tool || 'unknown';
      const toolArgs = args || {};

      // Cache timing and args
      if (callID) {
        toolTimingCache.set(callID, Date.now());
        argsCache.set(callID, toolArgs);
      }

      // Build tool_input
      const toolInput = {};
      if (toolArgs.command) toolInput.command = toolArgs.command;
      if (toolArgs.filePath || toolArgs.file_path || toolArgs.path) {
        toolInput.file_path = toolArgs.filePath || toolArgs.file_path || toolArgs.path;
      }
      if (toolArgs.pattern) toolInput.pattern = toolArgs.pattern;
      if (toolArgs.query) toolInput.query = toolArgs.query;
      if (toolArgs.content) {
        toolInput.content = typeof toolArgs.content === 'string'
          ? toolArgs.content.slice(0, 500) : toolArgs.content;
      }
      if (toolArgs.old_string) toolInput.old_string = toolArgs.old_string;
      if (toolArgs.new_string) toolInput.new_string = toolArgs.new_string;

      if (Object.keys(toolInput).length === 0 && Object.keys(toolArgs).length > 0) {
        Object.assign(toolInput, toolArgs);
      }

      // Track WSTG coverage for WSTG MCP calls
      if (toolName.includes('wstg')) {
        const wstgIdMatch = JSON.stringify(toolArgs).match(/WSTG-[A-Z]+-\d+/i);
        if (wstgIdMatch) {
          await recordWSTGCoverage(wstgIdMatch[0].toUpperCase(), 'executed', 0);
        }
      }

      // Send existing PreToolUse event
      await sendEvent('PreToolUse', {
        tool_name: toolName,
        tool_input: toolInput,
        session_id: currentSessionId
      }, currentSessionId, agentName, currentModel);
    },

    /**
     * Tool execution completed
     */
    "tool.execute.after": async ({ tool, sessionID, callID }, { title, output, metadata }) => {
      const toolName = tool || 'unknown';

      // Calculate duration
      const startTime = callID ? toolTimingCache.get(callID) : null;
      const durationMs = startTime ? Date.now() - startTime : null;
      if (callID) {
        toolTimingCache.delete(callID);
      }

      // Get cached args
      const cachedArgs = callID ? argsCache.get(callID) : null;
      if (callID) {
        argsCache.delete(callID);
      }

      // Determine success/failure
      const hasError = metadata?.error || (typeof output === 'string' && output.includes('Error:'));
      const status = hasError ? 'failure' : 'success';

      // Detect findings in output
      const findings = detectFindings(toolName, output);
      const foundVuln = findings.length > 0;

      // Record tool metric
      await recordToolMetric(
        toolName,
        status,
        durationMs,
        foundVuln,
        foundVuln ? findings[0]?.vulnerability_type : null,
        hasError ? String(metadata?.error || '').slice(0, 500) : null
      );

      // Record any findings detected
      for (const finding of findings) {
        await recordFinding(finding);
      }

      // Update session stats periodically
      if (totalToolCalls % 10 === 0) {
        await updateSession();
      }

      // Build tool_input for existing event
      const toolArgs = cachedArgs || metadata?.input || metadata?.args || {};
      const toolInput = {};
      if (toolArgs.command) toolInput.command = toolArgs.command;
      if (toolArgs.filePath || toolArgs.file_path || toolArgs.path) {
        toolInput.file_path = toolArgs.filePath || toolArgs.file_path || toolArgs.path;
      }
      if (toolArgs.pattern) toolInput.pattern = toolArgs.pattern;
      if (toolArgs.query) toolInput.query = toolArgs.query;

      if (Object.keys(toolInput).length === 0 && Object.keys(toolArgs).length > 0) {
        Object.assign(toolInput, toolArgs);
      }

      // Truncate output
      let toolOutput = '';
      if (typeof output === 'string') {
        toolOutput = output.length > 2000 ? output.slice(0, 2000) + '...' : output;
      } else if (output) {
        try {
          const jsonStr = JSON.stringify(output);
          toolOutput = jsonStr.length > 2000 ? jsonStr.slice(0, 2000) + '...' : jsonStr;
        } catch {
          toolOutput = String(output).slice(0, 2000);
        }
      }

      // Send existing PostToolUse event
      await sendEvent('PostToolUse', {
        tool_name: toolName,
        tool_input: toolInput,
        tool_output: toolOutput,
        tool_error: metadata?.error ? String(metadata.error) : null,
        session_id: currentSessionId
      }, currentSessionId, agentName, currentModel);
    },

    /**
     * Session created
     */
    "session.created": async (event) => {
      await sendEvent('SessionStart', {
        session_id: currentSessionId,
        cwd: directory,
        project_name: project?.name || agentName
      }, currentSessionId, agentName, currentModel);
    },

    /**
     * Session idle/ended
     */
    "session.idle": async (event) => {
      // Update session to completed
      await updateSession('completed');

      await sendEvent('Stop', {
        session_id: currentSessionId,
        stop_reason: 'end_turn',
        cwd: directory
      }, currentSessionId, agentName, currentModel);
    },

    /**
     * Message updated - track user prompts and estimate tokens
     */
    "message.updated": async (event) => {
      if (event?.role === 'user' || event?.type === 'user') {
        const messageContent = event?.content || event?.text || event?.message || '';
        const promptText = typeof messageContent === 'string' ? messageContent : JSON.stringify(messageContent);

        // Estimate tokens (rough: ~4 chars per token)
        const estimatedInputTokens = Math.ceil(promptText.length / 4);

        await sendEvent('UserPromptSubmit', {
          session_id: currentSessionId,
          prompt: promptText
        }, currentSessionId, agentName, currentModel);
      }

      // Track assistant responses for token estimation
      if (event?.role === 'assistant' || event?.type === 'assistant') {
        const responseContent = event?.content || event?.text || event?.message || '';
        const responseText = typeof responseContent === 'string' ? responseContent : JSON.stringify(responseContent);

        // Estimate tokens (rough: ~4 chars per token)
        const estimatedInputTokens = Math.ceil(responseText.length / 8); // Assume input was ~half the response
        const estimatedOutputTokens = Math.ceil(responseText.length / 4);

        await recordTokenUsage(estimatedInputTokens, estimatedOutputTokens);
      }
    },

    /**
     * File edited
     */
    "file.edited": async (event) => {
      await sendEvent('PostToolUse', {
        tool_name: 'Edit',
        tool_input: {
          file_path: event?.path || event?.file || ''
        },
        session_id: currentSessionId
      }, currentSessionId, agentName, currentModel);
    },

    /**
     * Error occurred
     */
    "error": async (event) => {
      // Update session status on error
      await updateSession('failed');

      await sendEvent('Error', {
        session_id: currentSessionId,
        error: event?.message || event?.error || 'Unknown error',
        cwd: directory
      }, currentSessionId, agentName, currentModel);
    }
  };
};

// Default export for OpenCode
export default ObservabilityPlugin;
