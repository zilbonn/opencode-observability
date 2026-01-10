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

  // Try to extract from .opencode project path
  const projectMatch = directory.match(/\/([^\/]+)\/?$/);
  if (projectMatch) {
    return projectMatch[1];
  }

  // Fallback to environment variable or default
  return process.env.OBSERVABILITY_SOURCE_APP || 'opencode';
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
        'User-Agent': 'OpenCode-Observability-Plugin/1.0'
      },
      body: JSON.stringify(eventData)
    });

    if (!response.ok) {
      console.error(`[Observability] Failed to send event: ${response.status}`);
    }
  } catch (error) {
    // Silently fail to not block OpenCode operations
    // Only log in debug mode
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
    agent_name: agentName,
    model: currentModel,
    cwd: directory,
    project: project?.name || agentName,
    created_at: Date.now()
  };

  // Fire SessionStart immediately when plugin loads
  sendEvent('SessionStart', initialPayload, currentSessionId, agentName, currentModel);

  return {
    /**
     * Tool execution started (maps to PreToolUse)
     */
    "tool.execute.before": async (event) => {
      const payload = {
        tool_name: event.tool || event.name || 'unknown',
        tool_input: event.input || event.args || {},
        session_id: currentSessionId,
        agent_name: agentName,
        cwd: directory
      };

      await sendEvent('PreToolUse', payload, currentSessionId, agentName, currentModel);
    },

    /**
     * Tool execution completed (maps to PostToolUse)
     */
    "tool.execute.after": async (event) => {
      const payload = {
        tool_name: event.tool || event.name || 'unknown',
        tool_input: event.input || event.args || {},
        tool_output: event.output || event.result || '',
        tool_error: event.error || null,
        session_id: currentSessionId,
        agent_name: agentName,
        duration_ms: event.duration || 0
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
        agent_name: agentName,
        model: currentModel,
        cwd: directory,
        project: project?.name || agentName,
        created_at: Date.now()
      };

      await sendEvent('SessionStart', payload, currentSessionId, agentName, currentModel);
    },

    /**
     * Session idle/ended (maps to Stop)
     */
    "session.idle": async (event) => {
      const payload = {
        session_id: currentSessionId,
        agent_name: agentName,
        reason: 'idle',
        cwd: directory,
        stopped_at: Date.now()
      };

      await sendEvent('Stop', payload, currentSessionId, agentName, currentModel);
    },

    /**
     * Session compaction (maps to PreCompact)
     */
    "session.compacted": async (event) => {
      const payload = {
        session_id: currentSessionId,
        agent_name: agentName,
        reason: event.reason || 'context_limit',
        tokens_before: event.tokensBefore || 0,
        tokens_after: event.tokensAfter || 0
      };

      await sendEvent('PreCompact', payload, currentSessionId, agentName, currentModel);
    },

    /**
     * Message updated (maps to UserPromptSubmit for user messages)
     */
    "message.updated": async (event) => {
      // Only send for user messages
      if (event.role === 'user' || event.type === 'user') {
        const payload = {
          session_id: currentSessionId,
          agent_name: agentName,
          message: event.content || event.text || '',
          role: event.role || 'user'
        };

        await sendEvent('UserPromptSubmit', payload, currentSessionId, agentName, currentModel);
      }
    },

    /**
     * File edited (custom event for file operations)
     */
    "file.edited": async (event) => {
      const payload = {
        session_id: currentSessionId,
        agent_name: agentName,
        file_path: event.path || event.file || '',
        changes: event.changes || [],
        tool_name: 'Edit'
      };

      await sendEvent('PostToolUse', payload, currentSessionId, agentName, currentModel);
    },

    /**
     * Command events (permission requests)
     */
    "command.permission": async (event) => {
      const payload = {
        session_id: currentSessionId,
        agent_name: agentName,
        command: event.command || '',
        allowed: event.allowed || false,
        tool_name: 'Bash'
      };

      await sendEvent('Notification', payload, currentSessionId, agentName, currentModel);
    }
  };
};

// Default export for OpenCode
export default ObservabilityPlugin;
