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
      payload: payload,  // Full payload matching Claude Code format
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

    if (!response.ok) {
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
 */
export const ObservabilityPlugin = async ({ project, client, $, directory, worktree }) => {
  // Extract agent name from directory path
  const agentName = extractAgentName(directory);

  // Generate unique session ID for this run
  const currentSessionId = `${agentName}-${Date.now()}-${Math.random().toString(36).substr(2, 8)}`;
  let currentModel = process.env.OPENCODE_MODEL || 'anthropic/claude-opus-4-5';

  console.log(`[Observability] Plugin loaded for agent: ${agentName}`);
  console.log(`[Observability] Session ID: ${currentSessionId}`);
  console.log(`[Observability] Server: ${SERVER_URL}`);

  // Send initial SessionStart event
  const initialPayload = {
    session_id: currentSessionId,
    cwd: directory,
    project_name: project?.name || agentName,
    agent_name: agentName
  };
  sendEvent('SessionStart', initialPayload, currentSessionId, agentName, currentModel);

  return {
    /**
     * Tool execution started (maps to PreToolUse)
     * Payload format matches Claude Code's PreToolUse hook
     */
    "tool.execute.before": async (event) => {
      // Structure payload to match Claude Code format
      // Claude Code sends: { tool_name, tool_input, session_id, ... }
      const toolName = event.tool || event.name || 'unknown';
      const toolInput = event.input || event.args || event.parameters || {};

      const payload = {
        tool_name: toolName,
        tool_input: toolInput,
        session_id: currentSessionId,
        cwd: directory
      };

      // Log for debugging
      if (process.env.OBSERVABILITY_DEBUG) {
        console.log(`[Observability] PreToolUse: ${toolName}`, JSON.stringify(toolInput).slice(0, 200));
      }

      await sendEvent('PreToolUse', payload, currentSessionId, agentName, currentModel);
    },

    /**
     * Tool execution completed (maps to PostToolUse)
     * Payload format matches Claude Code's PostToolUse hook
     */
    "tool.execute.after": async (event) => {
      const toolName = event.tool || event.name || 'unknown';
      const toolInput = event.input || event.args || event.parameters || {};
      const toolOutput = event.output || event.result || event.response || '';
      const toolError = event.error || null;

      // Truncate large outputs for display
      let outputStr = '';
      if (typeof toolOutput === 'string') {
        outputStr = toolOutput.length > 2000 ? toolOutput.slice(0, 2000) + '...' : toolOutput;
      } else if (toolOutput) {
        try {
          const jsonStr = JSON.stringify(toolOutput);
          outputStr = jsonStr.length > 2000 ? jsonStr.slice(0, 2000) + '...' : jsonStr;
        } catch {
          outputStr = String(toolOutput).slice(0, 2000);
        }
      }

      const payload = {
        tool_name: toolName,
        tool_input: toolInput,
        tool_output: outputStr,
        tool_error: toolError ? String(toolError) : null,
        session_id: currentSessionId,
        duration_ms: event.duration || event.elapsed || 0
      };

      await sendEvent('PostToolUse', payload, currentSessionId, agentName, currentModel);
    },

    /**
     * Session created (maps to SessionStart)
     */
    "session.created": async (event) => {
      if (event.model) {
        currentModel = event.model;
      }

      const payload = {
        session_id: currentSessionId,
        model: currentModel,
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
        stop_reason: event.reason || 'end_turn',
        cwd: directory
      };

      await sendEvent('Stop', payload, currentSessionId, agentName, currentModel);
    },

    /**
     * Session compaction (maps to PreCompact)
     */
    "session.compacted": async (event) => {
      const payload = {
        session_id: currentSessionId,
        summary: event.summary || 'Context compacted',
        tokens_before: event.tokensBefore || 0,
        tokens_after: event.tokensAfter || 0
      };

      await sendEvent('PreCompact', payload, currentSessionId, agentName, currentModel);
    },

    /**
     * Message updated (maps to UserPromptSubmit for user messages)
     */
    "message.updated": async (event) => {
      if (event.role === 'user' || event.type === 'user') {
        const messageContent = event.content || event.text || event.message || '';

        const payload = {
          session_id: currentSessionId,
          prompt: typeof messageContent === 'string' ? messageContent : JSON.stringify(messageContent),
          cwd: directory
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
          file_path: event.path || event.file || '',
          changes: event.changes || event.diff || ''
        },
        session_id: currentSessionId
      };

      await sendEvent('PostToolUse', payload, currentSessionId, agentName, currentModel);
    },

    /**
     * Permission request (maps to Notification)
     */
    "command.permission": async (event) => {
      const payload = {
        session_id: currentSessionId,
        type: 'permission',
        message: event.message || `Permission requested for: ${event.command || 'unknown'}`,
        command: event.command || ''
      };

      await sendEvent('Notification', payload, currentSessionId, agentName, currentModel);
    }
  };
};

// Default export for OpenCode
export default ObservabilityPlugin;
