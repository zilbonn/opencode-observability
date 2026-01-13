/**
 * OpenCode Observability Plugin
 *
 * Sends OpenCode events to the multi-agent observability server.
 * Captures ALL interesting data from OpenCode hooks.
 *
 * METRICS TRACKING:
 * - Token usage (REAL data: input, output, reasoning, cache)
 * - Cost (actual API cost)
 * - Message latency (created → completed timing)
 * - Tool effectiveness (duration, success/failure, state transitions)
 * - Errors (API errors, auth errors, abort, output length)
 * - Retries (attempts and reasons)
 * - Reasoning (thinking time and tokens)
 * - Agent tracking (which agents are used, subagent spawns)
 * - Security findings (from Bash/nuclei outputs)
 * - WSTG coverage
 * - Session management
 */

const SERVER_URL = process.env.OBSERVABILITY_SERVER_URL || 'http://localhost:4000/events';
const METRICS_BASE_URL = process.env.OBSERVABILITY_METRICS_URL || 'http://localhost:4000';

// Severity patterns for finding detection
const SEVERITY_PATTERNS = {
  critical: /critical|crit|severity:\s*critical/i,
  high: /high|severity:\s*high/i,
  medium: /medium|med|severity:\s*medium/i,
  low: /low|severity:\s*low|informational/i,
  info: /info|severity:\s*info/i,
};

// Vulnerability type patterns - only match clear indicators from security tools
const VULN_PATTERNS = {
  'SQL Injection': /\[sql.?injection\]|\[sqli\]|SQL Injection confirmed|vulnerable to SQL/i,
  'XSS': /\[xss\]|\[cross.site.scripting\]|XSS confirmed|vulnerable to XSS/i,
  'Command Injection': /\[command.?injection\]|\[rce\]|\[os.?injection\]|RCE confirmed/i,
  'Path Traversal': /\[path.?traversal\]|\[lfi\]|\[directory.?traversal\]|LFI confirmed/i,
  'SSRF': /\[ssrf\]|SSRF confirmed|server.side request forgery confirmed/i,
  'XXE': /\[xxe\]|XXE confirmed|XML external entity confirmed/i,
  'IDOR': /\[idor\]|IDOR confirmed|insecure direct object/i,
  'Open Redirect': /\[open.?redirect\]|open redirect confirmed/i,
};

// WSTG ID patterns
const WSTG_PATTERNS = {
  'WSTG-INPV-05': /sql.?injection|sqli/i,
  'WSTG-INPV-01': /xss|cross.site.scripting/i,
  'WSTG-INPV-12': /command.?injection|rce/i,
  'WSTG-ATHZ-01': /path.?traversal|directory.?traversal|lfi/i,
  'WSTG-INPV-19': /ssrf/i,
  'WSTG-INPV-07': /xxe/i,
  'WSTG-ATHZ-04': /idor/i,
  'WSTG-CLNT-04': /open.?redirect/i,
};

// Tools that should be scanned for security findings
const SECURITY_SCAN_TOOLS = ['Bash', 'bash'];

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

  const nucleiPattern = /\[(\w+)\]\s*\[([^\]]+)\]\s*\[([^\]]+)\]\s*(.+)/g;
  let match;

  while ((match = nucleiPattern.exec(output)) !== null) {
    const [, severity, templateId, protocol, target] = match;
    const sevLower = severity.toLowerCase();
    if (['critical', 'high', 'medium', 'low', 'info'].includes(sevLower)) {
      findings.push({
        severity: sevLower,
        vulnerability_type: templateId,
        target_url: target.trim(),
        tool_used: 'nuclei',
        confidence: 'confirmed',
      });
    }
  }

  return findings;
}

/**
 * Detect findings from Bash tool output only
 */
function detectFindings(toolName, output) {
  const findings = [];
  if (!output) return findings;

  if (!SECURITY_SCAN_TOOLS.includes(toolName)) {
    return findings;
  }

  const outputStr = typeof output === 'string' ? output : JSON.stringify(output);

  const nucleiFindings = parseNucleiOutput(outputStr);
  if (nucleiFindings.length > 0) {
    return nucleiFindings;
  }

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
        confidence: 'confirmed',
      });
      break;
    }
  }

  return findings;
}

/**
 * Send event to observability server
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
        'User-Agent': 'OpenCode-Observability-Plugin/2.0'
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
 * Send metric to observability server
 */
async function sendMetric(endpoint, data) {
  try {
    const response = await fetch(`${METRICS_BASE_URL}${endpoint}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'OpenCode-Observability-Plugin/2.0'
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

  console.log(`[Observability] Plugin v2.0 loaded for agent: ${agentName}`);
  console.log(`[Observability] Session ID: ${currentSessionId}`);
  console.log(`[Observability] Full metrics tracking enabled`);

  // Caches
  const toolTimingCache = new Map();
  const argsCache = new Map();
  const recordedIds = new Set();

  // Session metrics
  let totalToolCalls = 0;
  let totalFindings = 0;
  let findingCounter = 0;
  let totalInputTokens = 0;
  let totalOutputTokens = 0;
  let totalReasoningTokens = 0;
  let totalCacheReadTokens = 0;
  let totalCacheWriteTokens = 0;
  let totalCost = 0;
  let totalRetries = 0;
  let totalErrors = 0;
  let totalReasoningTimeMs = 0;
  let messageCount = 0;
  let totalLatencyMs = 0;
  const wstgCoverage = new Set();
  const agentsUsed = new Set([agentName]);
  const errorTypes = {};
  const modelsUsed = new Set();

  // Create session
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

  // Update session
  const updateSession = async (status = 'running') => {
    await sendMetric('/api/sessions', {
      session_id: currentSessionId,
      status,
      total_findings: totalFindings,
      total_tool_calls: totalToolCalls,
      agents_used: Array.from(agentsUsed),
      wstg_coverage_pct: (wstgCoverage.size / 91) * 100,
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

    await sendMetric('/api/metrics/findings', {
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
    });

    if (finding.wstg_id) {
      await recordWSTGCoverage(finding.wstg_id, 'executed', 1);
    }
  };

  // Record WSTG coverage
  const recordWSTGCoverage = async (wstgId, status = 'executed', findingsCount = 0) => {
    if (wstgCoverage.has(wstgId)) return;
    wstgCoverage.add(wstgId);

    await sendMetric('/api/metrics/wstg', {
      session_id: currentSessionId,
      source_app: agentName,
      wstg_id: wstgId,
      wstg_name: null,
      status,
      findings_count: findingsCount,
      timestamp: Date.now()
    });
  };

  // Token estimation constants (approximate)
  const CHARS_PER_TOKEN = 4;
  const MODEL_PRICING = {
    // Anthropic pricing per 1M tokens
    'anthropic/claude-opus-4-5': { input: 15, output: 75 },
    'anthropic/claude-sonnet-4': { input: 3, output: 15 },
    'anthropic/claude-3-5-sonnet': { input: 3, output: 15 },
    'anthropic/claude-3-opus': { input: 15, output: 75 },
    'default': { input: 3, output: 15 }
  };

  // Estimate tokens from text
  const estimateTokens = (text) => {
    if (!text) return 0;
    const str = typeof text === 'string' ? text : JSON.stringify(text);
    return Math.ceil(str.length / CHARS_PER_TOKEN);
  };

  // Estimate cost from tokens
  const estimateCost = (inputTokens, outputTokens, modelName) => {
    const pricing = MODEL_PRICING[modelName] || MODEL_PRICING['default'];
    const inputCost = (inputTokens / 1000000) * pricing.input;
    const outputCost = (outputTokens / 1000000) * pricing.output;
    return inputCost + outputCost;
  };

  // Record REAL token usage (when available from message hooks)
  const recordRealTokenUsage = async (tokens, cost, modelName) => {
    if (!tokens) return;

    const inputTokens = tokens.input || 0;
    const outputTokens = tokens.output || 0;
    const reasoningTokens = tokens.reasoning || 0;
    const cacheReadTokens = tokens.cache?.read || 0;
    const cacheWriteTokens = tokens.cache?.write || 0;
    const actualCost = cost || 0;

    totalInputTokens += inputTokens;
    totalOutputTokens += outputTokens;
    totalReasoningTokens += reasoningTokens;
    totalCacheReadTokens += cacheReadTokens;
    totalCacheWriteTokens += cacheWriteTokens;
    totalCost += actualCost;

    if (modelName) modelsUsed.add(modelName);

    const totalTokensThisMessage = inputTokens + outputTokens + reasoningTokens;

    if (totalTokensThisMessage > 0 || actualCost > 0) {
      await sendMetric('/api/metrics/tokens', {
        session_id: currentSessionId,
        source_app: agentName,
        model_name: modelName || currentModel,
        input_tokens: inputTokens,
        output_tokens: outputTokens,
        total_tokens: totalTokensThisMessage,
        estimated_cost: actualCost,
        reasoning_tokens: reasoningTokens,
        cache_read_tokens: cacheReadTokens,
        cache_write_tokens: cacheWriteTokens,
        timestamp: Date.now()
      });
    }
  };

  // Record ESTIMATED token usage (fallback when message hooks don't fire)
  const recordEstimatedTokenUsage = async (inputText, outputText) => {
    const inputTokens = estimateTokens(inputText);
    const outputTokens = estimateTokens(outputText);
    const estimatedCost = estimateCost(inputTokens, outputTokens, currentModel);

    totalInputTokens += inputTokens;
    totalOutputTokens += outputTokens;
    totalCost += estimatedCost;

    if (inputTokens > 0 || outputTokens > 0) {
      await sendMetric('/api/metrics/tokens', {
        session_id: currentSessionId,
        source_app: agentName,
        model_name: currentModel,
        input_tokens: inputTokens,
        output_tokens: outputTokens,
        total_tokens: inputTokens + outputTokens,
        estimated_cost: estimatedCost,
        is_estimate: true,
        timestamp: Date.now()
      });
    }
  };

  // Initialize
  await createSession();
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
      const toolName = tool || 'unknown';
      const toolArgs = args || {};

      if (callID) {
        toolTimingCache.set(callID, Date.now());
        argsCache.set(callID, toolArgs);
      }

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

      if (Object.keys(toolInput).length === 0 && Object.keys(toolArgs).length > 0) {
        Object.assign(toolInput, toolArgs);
      }

      if (toolName.includes('wstg')) {
        const wstgIdMatch = JSON.stringify(toolArgs).match(/WSTG-[A-Z]+-\d+/i);
        if (wstgIdMatch) {
          await recordWSTGCoverage(wstgIdMatch[0].toUpperCase(), 'executed', 0);
        }
      }

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

      const startTime = callID ? toolTimingCache.get(callID) : null;
      const durationMs = startTime ? Date.now() - startTime : null;
      if (callID) toolTimingCache.delete(callID);

      const cachedArgs = callID ? argsCache.get(callID) : null;
      if (callID) argsCache.delete(callID);

      const hasError = metadata?.error || (typeof output === 'string' && output.startsWith('Error:'));
      const status = hasError ? 'failure' : 'success';

      const findings = detectFindings(toolName, output);
      const foundVuln = findings.length > 0;

      await recordToolMetric(
        toolName,
        status,
        durationMs,
        foundVuln,
        foundVuln ? findings[0]?.vulnerability_type : null,
        hasError ? String(metadata?.error || '').slice(0, 500) : null
      );

      for (const finding of findings) {
        await recordFinding(finding);
      }

      // Estimate tokens from tool I/O (fallback since message hooks don't fire in OpenCode 1.1.x)
      const inputStr = cachedArgs ? JSON.stringify(cachedArgs) : '';
      const outputStr = typeof output === 'string' ? output : (output ? JSON.stringify(output) : '');
      await recordEstimatedTokenUsage(inputStr, outputStr);

      if (totalToolCalls % 10 === 0) {
        await updateSession();
      }

      const toolArgs = cachedArgs || metadata?.input || {};
      const toolInput = {};
      if (toolArgs.command) toolInput.command = toolArgs.command;
      if (toolArgs.filePath || toolArgs.file_path || toolArgs.path) {
        toolInput.file_path = toolArgs.filePath || toolArgs.file_path || toolArgs.path;
      }

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

      await sendEvent('PostToolUse', {
        tool_name: toolName,
        tool_input: toolInput,
        tool_output: toolOutput,
        tool_error: metadata?.error ? String(metadata.error) : null,
        duration_ms: durationMs,
        session_id: currentSessionId
      }, currentSessionId, agentName, currentModel);
    },

    /**
     * Universal event handler - receives ALL OpenCode events
     * Event structure: { type: string, properties: object }
     *
     * According to OpenCode SDK types:
     * - message.updated: properties.info contains Message (with tokens, cost)
     * - message.part.updated: properties.part contains Part (StepFinishPart has tokens)
     * - session.idle, session.error, etc.
     */
    event: async ({ event }) => {
      if (process.env.OBSERVABILITY_DEBUG) {
        console.log('[Observability] Event received:', event?.type);
      }

      const eventType = event?.type;
      const props = event?.properties || {};

      // ===== SESSION EVENTS =====
      if (eventType === 'session.created') {
        await sendEvent('SessionStart', {
          session_id: currentSessionId,
          cwd: directory,
          project_name: project?.name || agentName
        }, currentSessionId, agentName, currentModel);
      }

      if (eventType === 'session.idle') {
        await updateSession('completed');
        await sendEvent('Stop', {
          session_id: currentSessionId,
          stop_reason: 'idle',
          total_cost: totalCost,
          total_tokens: totalInputTokens + totalOutputTokens + totalReasoningTokens,
          total_tool_calls: totalToolCalls,
          total_errors: totalErrors,
          total_retries: totalRetries,
          agents_used: Array.from(agentsUsed),
          models_used: Array.from(modelsUsed),
          cwd: directory
        }, currentSessionId, agentName, currentModel);
      }

      if (eventType === 'session.updated') {
        const session = props.session || props;
        if (session?.title) {
          await sendEvent('SessionUpdate', {
            session_id: currentSessionId,
            title: session.title,
            time_updated: session?.time?.updated
          }, currentSessionId, agentName, currentModel);
        }
      }

      if (eventType === 'session.error') {
        const error = props.error || props;
        totalErrors++;
        const errType = error?.type || error?.name || 'unknown';
        errorTypes[errType] = (errorTypes[errType] || 0) + 1;

        await sendEvent('SessionError', {
          session_id: currentSessionId,
          error_type: errType,
          error_message: error?.message || String(error),
          total_errors: totalErrors
        }, currentSessionId, agentName, currentModel);
      }

      // ===== MESSAGE EVENTS - REAL TOKEN DATA =====
      if (eventType === 'message.updated') {
        // According to SDK types: EventMessageUpdated.properties.info contains Message
        const message = props.info || props;

        if (process.env.OBSERVABILITY_DEBUG) {
          console.log('[Observability] message.updated - role:', message?.role, 'tokens:', message?.tokens);
        }

        // User messages
        if (message?.role === 'user') {
          const messageContent = message?.content || message?.text || '';
          const promptText = typeof messageContent === 'string' ? messageContent : JSON.stringify(messageContent);

          await sendEvent('UserPromptSubmit', {
            session_id: currentSessionId,
            prompt: promptText
          }, currentSessionId, agentName, currentModel);
        }

        // Assistant messages - REAL tokens, cost, latency, errors
        if (message?.role === 'assistant') {
          const messageId = message?.id || `msg-${Date.now()}`;

          if (!recordedIds.has(messageId)) {
            recordedIds.add(messageId);
            messageCount++;

            // Record REAL tokens and cost from AssistantMessage
            if (message?.tokens) {
              if (process.env.OBSERVABILITY_DEBUG) {
                console.log('[Observability] Recording REAL tokens:', message.tokens, 'cost:', message.cost);
              }
              await recordRealTokenUsage(message.tokens, message.cost, message.modelID);
            }

            // Calculate latency
            let latencyMs = null;
            if (message?.time?.created && message?.time?.completed) {
              latencyMs = message.time.completed - message.time.created;
              totalLatencyMs += latencyMs;
            }

            // Track model used
            if (message?.modelID) modelsUsed.add(message.modelID);
            if (message?.providerID) modelsUsed.add(`${message.providerID}/${message.modelID}`);

            // Handle errors
            if (message?.error) {
              totalErrors++;
              const errType = message.error.type || message.error.name || 'unknown';
              errorTypes[errType] = (errorTypes[errType] || 0) + 1;

              await sendEvent('MessageError', {
                session_id: currentSessionId,
                message_id: messageId,
                error_type: errType,
                error_message: message.error.message || String(message.error),
                is_auth_error: errType === 'ProviderAuthError',
                is_api_error: errType === 'ApiError',
                is_abort_error: errType === 'MessageAbortedError',
                is_length_error: errType === 'MessageOutputLengthError'
              }, currentSessionId, agentName, currentModel);
            }

            // Send message completion event
            await sendEvent('MessageComplete', {
              session_id: currentSessionId,
              message_id: messageId,
              model: message?.modelID,
              provider: message?.providerID,
              latency_ms: latencyMs,
              finish_reason: message?.finish,
              cost: message?.cost,
              tokens: message?.tokens,
              has_error: !!message?.error
            }, currentSessionId, agentName, currentModel);
          }
        }
      }

      // ===== MESSAGE PART EVENTS - StepFinish has tokens =====
      if (eventType === 'message.part.updated') {
        // According to SDK types: EventMessagePartUpdated.properties.part contains Part
        const part = props.part || props;

        if (process.env.OBSERVABILITY_DEBUG) {
          console.log('[Observability] message.part.updated - type:', part?.type);
        }

        const partId = part?.id || `part-${Date.now()}-${Math.random()}`;
        if (recordedIds.has(partId)) return;

        // StepFinishPart - contains REAL tokens and cost
        if (part?.type === 'step-finish' && part?.tokens) {
          recordedIds.add(partId);
          if (process.env.OBSERVABILITY_DEBUG) {
            console.log('[Observability] StepFinish tokens:', part.tokens, 'cost:', part.cost);
          }
          await recordRealTokenUsage(part.tokens, part.cost, null);

          await sendEvent('StepFinish', {
            session_id: currentSessionId,
            part_id: partId,
            reason: part.reason,
            cost: part.cost,
            tokens: part.tokens
          }, currentSessionId, agentName, currentModel);
        }

        // ReasoningPart - thinking time
        if (part?.type === 'reasoning') {
          recordedIds.add(partId);
          let reasoningTimeMs = null;
          if (part?.time?.start && part?.time?.end) {
            reasoningTimeMs = part.time.end - part.time.start;
            totalReasoningTimeMs += reasoningTimeMs;
          }

          await sendEvent('Reasoning', {
            session_id: currentSessionId,
            part_id: partId,
            reasoning_time_ms: reasoningTimeMs,
            text_length: part?.text?.length || 0
          }, currentSessionId, agentName, currentModel);
        }

        // ToolPart - tool state transitions
        if (part?.type === 'tool' && part?.state) {
          const state = part.state;

          await sendEvent('ToolState', {
            session_id: currentSessionId,
            part_id: partId,
            tool: part.tool,
            call_id: part.callID,
            status: state.status,
            title: state.title,
            has_error: state.status === 'error',
            error_message: state.error,
            duration_ms: state.time?.start && state.time?.end ? state.time.end - state.time.start : null
          }, currentSessionId, agentName, currentModel);
        }

        // RetryPart - track retries
        if (part?.type === 'retry') {
          recordedIds.add(partId);
          totalRetries++;

          await sendEvent('Retry', {
            session_id: currentSessionId,
            part_id: partId,
            attempt: part.attempt,
            error_type: part.error?.type || 'unknown',
            error_message: part.error?.message,
            total_retries: totalRetries
          }, currentSessionId, agentName, currentModel);
        }

        // AgentPart - track agent spawns
        if (part?.type === 'agent') {
          recordedIds.add(partId);
          const spawnedAgent = part.name || 'unknown';
          agentsUsed.add(spawnedAgent);

          await sendEvent('AgentSpawn', {
            session_id: currentSessionId,
            part_id: partId,
            agent_name: spawnedAgent,
            source: part.source,
            agents_used: Array.from(agentsUsed)
          }, currentSessionId, agentName, currentModel);
        }
      }

      // ===== PERMISSION EVENTS =====
      if (eventType === 'permission.updated') {
        const permission = props;
        await sendEvent('PermissionRequest', {
          session_id: currentSessionId,
          permission_type: permission?.type,
          tool: permission?.tool,
          action: permission?.action
        }, currentSessionId, agentName, currentModel);
      }

      if (eventType === 'permission.replied') {
        const permission = props;
        await sendEvent('PermissionResponse', {
          session_id: currentSessionId,
          permission_type: permission?.type,
          tool: permission?.tool,
          allowed: permission?.allowed,
          response: permission?.response
        }, currentSessionId, agentName, currentModel);
      }

      // ===== FILE EVENTS =====
      if (eventType === 'file.edited') {
        await sendEvent('FileEdit', {
          session_id: currentSessionId,
          file_path: props?.path || props?.file || ''
        }, currentSessionId, agentName, currentModel);
      }

      // ===== TODO EVENTS =====
      if (eventType === 'todo.updated') {
        const todos = props?.todos || props;
        await sendEvent('TodoUpdate', {
          session_id: currentSessionId,
          todo_count: Array.isArray(todos) ? todos.length : 0,
          todos: Array.isArray(todos) ? todos.slice(0, 10) : []
        }, currentSessionId, agentName, currentModel);
      }
    }
  };
};

export default ObservabilityPlugin;
