/**
 * OpenCode Observability Plugin
 *
 * Sends OpenCode events to the multi-agent observability server.
 * Compatible with the claude-code-hooks-multi-agent-observability system.
 *
 * Events are sent to http://localhost:4000/events in the same format
 * as Claude Code hooks, allowing both tools to use the same dashboard.
 */

const SERVER_URL = process.env.OBSERVABILITY_SERVER_URL || 'http://localhost:4000/events';

/**
 * Extract agent name from directory path
 * e.g., /opt/wardenn/agents/state1.6-login -> state1.6-login
 */
function extractAgentName(directory) {
  if (!directory) return 'opencode';

  // Try to extract from Wardenn agent path pattern
  const wardennMatch = directory.match(/\/agents\/([^\/]+)\/?$/);
  if (wardennMatch) {
    return wardennMatch[1];
  }

  // Try to extract from project path
  const projectMatch = directory.match(/\/([^\/]+)\/?$/);
  if (projectMatch) {
    return projectMatch[1];
  }

  // Fallback to environment variable or default
  return process.env.OBSERVABILITY_SOURCE_APP || 'opencode';
}

/**
 * Send event to observability server
 * Matches the format expected by claude-code-hooks-multi-agent-observability
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
    // Silently fail to not block OpenCode operations
    if (process.env.OBSERVABILITY_DEBUG) {
      console.error(`[Observability] Error sending event: ${error.message}`);
    }
  }
}

/**
 * Main plugin export
 *
 * OpenCode hook structure:
 * - tool.execute.before: (input, output) => { input.tool, output.args }
 * - tool.execute.after: (input, output) => { input.tool, output.args, output.result }
 */
export const ObservabilityPlugin = async ({ project, client, $, directory, worktree }) => {
  // Extract agent name from directory path
  const agentName = extractAgentName(directory);

  // Generate unique session ID for this run
  const currentSessionId = `${agentName}-${Date.now()}-${Math.random().toString(36).substr(2, 8)}`;
  const currentModel = process.env.OPENCODE_MODEL || 'anthropic/claude-opus-4-5';

  console.log(`[Observability] Plugin loaded for agent: ${agentName}`);
  console.log(`[Observability] Session ID: ${currentSessionId}`);

  // Cache to store args from before hook for use in after hook
  const argsCache = new Map();

  // Send initial SessionStart event
  sendEvent('SessionStart', {
    session_id: currentSessionId,
    cwd: directory,
    project_name: project?.name || agentName
  }, currentSessionId, agentName, currentModel);

  return {
    /**
     * Tool execution started (maps to PreToolUse)
     * OpenCode structure:
     * - First param: { tool, sessionID, callID }
     * - Second param: { args } where args is the tool arguments object
     */
    "tool.execute.before": async ({ tool, sessionID, callID }, { args }) => {
      // Debug: Log the raw data OpenCode sends
      if (process.env.OBSERVABILITY_DEBUG) {
        console.log('[Observability] tool.execute.before:');
        console.log('  tool:', tool);
        console.log('  sessionID:', sessionID);
        console.log('  callID:', callID);
        console.log('  args:', JSON.stringify(args, null, 2));
      }

      const toolName = tool || 'unknown';
      const toolArgs = args || {};

      // Cache args for use in after hook
      if (callID) {
        argsCache.set(callID, toolArgs);
      }

      // Build tool_input matching Claude Code format
      const toolInput = {};

      // Handle different tool types
      if (toolArgs.command) {
        toolInput.command = toolArgs.command;
      }
      if (toolArgs.filePath || toolArgs.file_path || toolArgs.path) {
        toolInput.file_path = toolArgs.filePath || toolArgs.file_path || toolArgs.path;
      }
      if (toolArgs.pattern) {
        toolInput.pattern = toolArgs.pattern;
      }
      if (toolArgs.query) {
        toolInput.query = toolArgs.query;
      }
      if (toolArgs.content) {
        toolInput.content = typeof toolArgs.content === 'string'
          ? toolArgs.content.slice(0, 500)
          : toolArgs.content;
      }
      if (toolArgs.old_string) {
        toolInput.old_string = toolArgs.old_string;
      }
      if (toolArgs.new_string) {
        toolInput.new_string = toolArgs.new_string;
      }

      // If no specific args found, include all args
      if (Object.keys(toolInput).length === 0 && Object.keys(toolArgs).length > 0) {
        Object.assign(toolInput, toolArgs);
      }

      const payload = {
        tool_name: toolName,
        tool_input: toolInput,
        session_id: currentSessionId
      };

      await sendEvent('PreToolUse', payload, currentSessionId, agentName, currentModel);
    },

    /**
     * Tool execution completed (maps to PostToolUse)
     * OpenCode structure:
     * - First param: { tool, sessionID, callID }
     * - Second param: { title, output, metadata }
     */
    "tool.execute.after": async ({ tool, sessionID, callID }, { title, output, metadata }) => {
      // Debug: Log the raw data OpenCode sends
      if (process.env.OBSERVABILITY_DEBUG) {
        console.log('[Observability] tool.execute.after:');
        console.log('  tool:', tool);
        console.log('  sessionID:', sessionID);
        console.log('  callID:', callID);
        console.log('  title:', title);
        console.log('  output:', typeof output === 'string' ? output.slice(0, 200) : JSON.stringify(output)?.slice(0, 200));
        console.log('  metadata:', JSON.stringify(metadata, null, 2));
      }

      const toolName = tool || 'unknown';

      // Retrieve cached args from before hook using callID
      const cachedArgs = callID ? argsCache.get(callID) : null;
      if (callID) {
        argsCache.delete(callID); // Clean up cache
      }

      // Build tool_input from cached args or metadata
      const toolArgs = cachedArgs || metadata?.input || metadata?.args || {};
      const toolInput = {};

      // Handle different tool types
      if (toolArgs.command) {
        toolInput.command = toolArgs.command;
      }
      if (toolArgs.filePath || toolArgs.file_path || toolArgs.path) {
        toolInput.file_path = toolArgs.filePath || toolArgs.file_path || toolArgs.path;
      }
      if (toolArgs.pattern) {
        toolInput.pattern = toolArgs.pattern;
      }
      if (toolArgs.query) {
        toolInput.query = toolArgs.query;
      }

      // If no specific args found, include all args
      if (Object.keys(toolInput).length === 0 && Object.keys(toolArgs).length > 0) {
        Object.assign(toolInput, toolArgs);
      }

      // Truncate large outputs
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

      const payload = {
        tool_name: toolName,
        tool_input: toolInput,
        tool_output: toolOutput,
        tool_error: metadata?.error ? String(metadata.error) : null,
        session_id: currentSessionId
      };

      await sendEvent('PostToolUse', payload, currentSessionId, agentName, currentModel);
    },

    /**
     * Session created (maps to SessionStart)
     */
    "session.created": async (event) => {
      const payload = {
        session_id: currentSessionId,
        cwd: directory,
        project_name: project?.name || agentName
      };

      await sendEvent('SessionStart', payload, currentSessionId, agentName, currentModel);
    },

    /**
     * Session idle/ended (maps to Stop)
     */
    "session.idle": async (event) => {
      const payload = {
        session_id: currentSessionId,
        stop_reason: 'end_turn',
        cwd: directory
      };

      await sendEvent('Stop', payload, currentSessionId, agentName, currentModel);
    },

    /**
     * Message updated (maps to UserPromptSubmit for user messages)
     */
    "message.updated": async (event) => {
      if (event?.role === 'user' || event?.type === 'user') {
        const messageContent = event?.content || event?.text || event?.message || '';

        const payload = {
          session_id: currentSessionId,
          prompt: typeof messageContent === 'string' ? messageContent : JSON.stringify(messageContent)
        };

        await sendEvent('UserPromptSubmit', payload, currentSessionId, agentName, currentModel);
      }
    },

    /**
     * File edited
     */
    "file.edited": async (event) => {
      const payload = {
        tool_name: 'Edit',
        tool_input: {
          file_path: event?.path || event?.file || ''
        },
        session_id: currentSessionId
      };

      await sendEvent('PostToolUse', payload, currentSessionId, agentName, currentModel);
    }
  };
};

// Default export for OpenCode
export default ObservabilityPlugin;
