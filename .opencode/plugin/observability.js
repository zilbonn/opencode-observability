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
     * Session events
     */
    "session.created": async (event) => {
      await sendEvent('SessionStart', {
        session_id: currentSessionId,
        cwd: directory,
        project_name: project?.name || agentName
      }, currentSessionId, agentName, currentModel);
    },

    "session.idle": async (event) => {
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
    },

    "session.updated": async (session) => {
      if (process.env.OBSERVABILITY_DEBUG) {
        console.log('[Observability] session.updated:', session?.id);
      }
      // Track session title/metadata updates
      if (session?.title) {
        await sendEvent('SessionUpdate', {
          session_id: currentSessionId,
          title: session.title,
          time_updated: session?.time?.updated
        }, currentSessionId, agentName, currentModel);
      }
    },

    "session.error": async (error) => {
      totalErrors++;
      const errorType = error?.type || error?.name || 'unknown';
      errorTypes[errorType] = (errorTypes[errorType] || 0) + 1;

      await sendEvent('SessionError', {
        session_id: currentSessionId,
        error_type: errorType,
        error_message: error?.message || String(error),
        total_errors: totalErrors
      }, currentSessionId, agentName, currentModel);
    },

    /**
     * Message updated - REAL token data + latency + errors
     */
    "message.updated": async (message) => {
      if (process.env.OBSERVABILITY_DEBUG) {
        console.log('[Observability] message.updated type:', message?.role || message?.type);
      }

      // User messages
      if (message?.role === 'user' || message?.type === 'user') {
        const messageContent = message?.content || message?.text || message?.message || '';
        const promptText = typeof messageContent === 'string' ? messageContent : JSON.stringify(messageContent);

        await sendEvent('UserPromptSubmit', {
          session_id: currentSessionId,
          prompt: promptText
        }, currentSessionId, agentName, currentModel);
      }

      // Assistant messages - tokens, cost, latency, errors
      if (message?.role === 'assistant' || message?.type === 'assistant') {
        const messageId = message?.id || `msg-${Date.now()}`;

        if (!recordedIds.has(messageId)) {
          recordedIds.add(messageId);
          messageCount++;

          // Record tokens and cost
          if (message?.tokens) {
            await recordRealTokenUsage(message.tokens, message.cost, message.modelID || message.model);
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
            const errorType = message.error.type || message.error.name || 'unknown';
            errorTypes[errorType] = (errorTypes[errorType] || 0) + 1;

            await sendEvent('MessageError', {
              session_id: currentSessionId,
              message_id: messageId,
              error_type: errorType,
              error_message: message.error.message || String(message.error),
              // Specific error types from OpenCode
              is_auth_error: errorType === 'ProviderAuthError',
              is_api_error: errorType === 'ApiError',
              is_abort_error: errorType === 'MessageAbortedError',
              is_length_error: errorType === 'MessageOutputLengthError'
            }, currentSessionId, agentName, currentModel);
          }

          // Send message completion event with all data
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
    },

    /**
     * Message part updated - reasoning, tool states, retries, agents
     */
    "message.part.updated": async (part) => {
      if (process.env.OBSERVABILITY_DEBUG) {
        console.log('[Observability] message.part.updated type:', part?.type);
      }

      const partId = part?.id || `part-${Date.now()}-${Math.random()}`;
      if (recordedIds.has(partId)) return;

      // StepFinishPart - tokens and cost
      if (part?.type === 'step-finish' && part?.tokens) {
        recordedIds.add(partId);
        await recordRealTokenUsage(part.tokens, part.cost, part.model);

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
          start_time: state.time?.start,
          end_time: state.time?.end,
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
          retry_time: part.time,
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
    },

    /**
     * Permission events
     */
    "permission.updated": async (permission) => {
      await sendEvent('PermissionRequest', {
        session_id: currentSessionId,
        permission_type: permission?.type,
        tool: permission?.tool,
        action: permission?.action
      }, currentSessionId, agentName, currentModel);
    },

    "permission.replied": async (permission) => {
      await sendEvent('PermissionResponse', {
        session_id: currentSessionId,
        permission_type: permission?.type,
        tool: permission?.tool,
        allowed: permission?.allowed,
        response: permission?.response
      }, currentSessionId, agentName, currentModel);
    },

    /**
     * File edited
     */
    "file.edited": async (event) => {
      await sendEvent('FileEdit', {
        session_id: currentSessionId,
        file_path: event?.path || event?.file || ''
      }, currentSessionId, agentName, currentModel);
    },

    /**
     * Todo updated
     */
    "todo.updated": async (todos) => {
      await sendEvent('TodoUpdate', {
        session_id: currentSessionId,
        todo_count: Array.isArray(todos) ? todos.length : 0,
        todos: Array.isArray(todos) ? todos.slice(0, 10) : []
      }, currentSessionId, agentName, currentModel);
    },

    /**
     * Error occurred
     */
    "error": async (event) => {
      totalErrors++;
      const errorType = event?.type || event?.name || 'unknown';
      errorTypes[errorType] = (errorTypes[errorType] || 0) + 1;

      await updateSession('failed');

      await sendEvent('Error', {
        session_id: currentSessionId,
        error_type: errorType,
        error_message: event?.message || event?.error || 'Unknown error',
        total_errors: totalErrors,
        error_types: errorTypes,
        cwd: directory
      }, currentSessionId, agentName, currentModel);
    }
  };
};

export default ObservabilityPlugin;
