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
const SOURCE_APP = process.env.OBSERVABILITY_SOURCE_APP || 'opencode-wardenn';

/**
 * Send event to observability server
 */
async function sendEvent(eventType, payload, sessionId, modelName = '') {
  try {
    const eventData = {
      source_app: SOURCE_APP,
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
    console.error(`[Observability] Error sending event: ${error.message}`);
  }
}

/**
 * Extract session ID from context
 */
function getSessionId(context) {
  // Try different ways to get session ID
  if (context?.sessionId) return context.sessionId;
  if (context?.session?.id) return context.session.id;
  if (context?.id) return context.id;
  // Generate a unique ID if none available
  return `opencode-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

/**
 * Main plugin export
 */
export const ObservabilityPlugin = async ({ project, client, $, directory, worktree }) => {
  // Store session ID for this instance
  let currentSessionId = `opencode-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  let currentModel = '';

  console.log(`[Observability] Plugin loaded for project: ${project?.name || directory}`);

  return {
    /**
     * Tool execution started (maps to PreToolUse)
     */
    "tool.execute.before": async (event) => {
      const payload = {
        tool_name: event.tool || event.name || 'unknown',
        tool_input: event.input || event.args || {},
        session_id: currentSessionId,
        cwd: directory
      };

      await sendEvent('PreToolUse', payload, currentSessionId, currentModel);
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
        duration_ms: event.duration || 0
      };

      await sendEvent('PostToolUse', payload, currentSessionId, currentModel);
    },

    /**
     * Session created (maps to SessionStart)
     */
    "session.created": async (event) => {
      currentSessionId = event.sessionId || event.id || currentSessionId;
      currentModel = event.model || '';

      const payload = {
        session_id: currentSessionId,
        model: currentModel,
        cwd: directory,
        project: project?.name || '',
        created_at: Date.now()
      };

      await sendEvent('SessionStart', payload, currentSessionId, currentModel);
    },

    /**
     * Session idle/ended (maps to Stop)
     */
    "session.idle": async (event) => {
      const payload = {
        session_id: currentSessionId,
        reason: 'idle',
        cwd: directory,
        stopped_at: Date.now()
      };

      await sendEvent('Stop', payload, currentSessionId, currentModel);
    },

    /**
     * Session compaction (maps to PreCompact)
     */
    "session.compacted": async (event) => {
      const payload = {
        session_id: currentSessionId,
        reason: event.reason || 'context_limit',
        tokens_before: event.tokensBefore || 0,
        tokens_after: event.tokensAfter || 0
      };

      await sendEvent('PreCompact', payload, currentSessionId, currentModel);
    },

    /**
     * Message updated (maps to UserPromptSubmit for user messages)
     */
    "message.updated": async (event) => {
      // Only send for user messages
      if (event.role === 'user' || event.type === 'user') {
        const payload = {
          session_id: currentSessionId,
          message: event.content || event.text || '',
          role: event.role || 'user'
        };

        await sendEvent('UserPromptSubmit', payload, currentSessionId, currentModel);
      }
    },

    /**
     * File edited (custom event for file operations)
     */
    "file.edited": async (event) => {
      const payload = {
        session_id: currentSessionId,
        file_path: event.path || event.file || '',
        changes: event.changes || [],
        tool_name: 'Edit'
      };

      await sendEvent('PostToolUse', payload, currentSessionId, currentModel);
    },

    /**
     * Command events (permission requests)
     */
    "command.permission": async (event) => {
      const payload = {
        session_id: currentSessionId,
        command: event.command || '',
        allowed: event.allowed || false,
        tool_name: 'Bash'
      };

      await sendEvent('Notification', payload, currentSessionId, currentModel);
    }
  };
};

// Default export for OpenCode
export default ObservabilityPlugin;
