import {
  initDatabase,
  insertEvent,
  getFilterOptions,
  getRecentEvents,
  updateEventHITLResponse,
  // Metrics imports
  insertTokenMetric,
  getTokenSummary,
  insertToolMetric,
  getToolEffectivenessReport,
  insertFinding,
  getFindingSummary,
  getFindings,
  insertWSTGCoverage,
  getWSTGCoverageReport,
  upsertSession,
  getSession,
  getSessions,
  addAgentToSession,
  getMetricsDashboard
} from './db';
import type {
  HookEvent,
  HumanInTheLoopResponse,
  TokenMetric,
  ToolMetric,
  Finding,
  WSTGCoverage,
  SessionSummary
} from './types';
import { 
  createTheme, 
  updateThemeById, 
  getThemeById, 
  searchThemes, 
  deleteThemeById, 
  exportThemeById, 
  importTheme,
  getThemeStats 
} from './theme';

// Initialize database
initDatabase();

// Store WebSocket clients
const wsClients = new Set<any>();

// Helper function to send response to agent via WebSocket
async function sendResponseToAgent(
  wsUrl: string,
  response: HumanInTheLoopResponse
): Promise<void> {
  console.log(`[HITL] Connecting to agent WebSocket: ${wsUrl}`);

  return new Promise((resolve, reject) => {
    let ws: WebSocket | null = null;
    let isResolved = false;

    const cleanup = () => {
      if (ws) {
        try {
          ws.close();
        } catch (e) {
          // Ignore close errors
        }
      }
    };

    try {
      ws = new WebSocket(wsUrl);

      ws.onopen = () => {
        if (isResolved) return;
        console.log('[HITL] WebSocket connection opened, sending response...');

        try {
          ws!.send(JSON.stringify(response));
          console.log('[HITL] Response sent successfully');

          // Wait longer to ensure message fully transmits before closing
          setTimeout(() => {
            cleanup();
            if (!isResolved) {
              isResolved = true;
              resolve();
            }
          }, 500);
        } catch (error) {
          console.error('[HITL] Error sending message:', error);
          cleanup();
          if (!isResolved) {
            isResolved = true;
            reject(error);
          }
        }
      };

      ws.onerror = (error) => {
        console.error('[HITL] WebSocket error:', error);
        cleanup();
        if (!isResolved) {
          isResolved = true;
          reject(error);
        }
      };

      ws.onclose = () => {
        console.log('[HITL] WebSocket connection closed');
      };

      // Timeout after 5 seconds
      setTimeout(() => {
        if (!isResolved) {
          console.error('[HITL] Timeout sending response to agent');
          cleanup();
          isResolved = true;
          reject(new Error('Timeout sending response to agent'));
        }
      }, 5000);

    } catch (error) {
      console.error('[HITL] Error creating WebSocket:', error);
      cleanup();
      if (!isResolved) {
        isResolved = true;
        reject(error);
      }
    }
  });
}

// Create Bun server with HTTP and WebSocket support
const server = Bun.serve({
  port: parseInt(process.env.SERVER_PORT || '4000'),
  
  async fetch(req: Request) {
    const url = new URL(req.url);
    
    // Handle CORS
    const headers = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };
    
    // Handle preflight
    if (req.method === 'OPTIONS') {
      return new Response(null, { headers });
    }
    
    // POST /events - Receive new events
    if (url.pathname === '/events' && req.method === 'POST') {
      try {
        const event: HookEvent = await req.json();
        
        // Validate required fields
        if (!event.source_app || !event.session_id || !event.hook_event_type || !event.payload) {
          return new Response(JSON.stringify({ error: 'Missing required fields' }), {
            status: 400,
            headers: { ...headers, 'Content-Type': 'application/json' }
          });
        }
        
        // Insert event into database
        const savedEvent = insertEvent(event);
        
        // Broadcast to all WebSocket clients
        const message = JSON.stringify({ type: 'event', data: savedEvent });
        wsClients.forEach(client => {
          try {
            client.send(message);
          } catch (err) {
            // Client disconnected, remove from set
            wsClients.delete(client);
          }
        });
        
        return new Response(JSON.stringify(savedEvent), {
          headers: { ...headers, 'Content-Type': 'application/json' }
        });
      } catch (error) {
        console.error('Error processing event:', error);
        return new Response(JSON.stringify({ error: 'Invalid request' }), {
          status: 400,
          headers: { ...headers, 'Content-Type': 'application/json' }
        });
      }
    }
    
    // GET /events/filter-options - Get available filter options
    if (url.pathname === '/events/filter-options' && req.method === 'GET') {
      const options = getFilterOptions();
      return new Response(JSON.stringify(options), {
        headers: { ...headers, 'Content-Type': 'application/json' }
      });
    }
    
    // GET /events/recent - Get recent events
    if (url.pathname === '/events/recent' && req.method === 'GET') {
      const limit = parseInt(url.searchParams.get('limit') || '300');
      const events = getRecentEvents(limit);
      return new Response(JSON.stringify(events), {
        headers: { ...headers, 'Content-Type': 'application/json' }
      });
    }

    // POST /events/:id/respond - Respond to HITL request
    if (url.pathname.match(/^\/events\/\d+\/respond$/) && req.method === 'POST') {
      const id = parseInt(url.pathname.split('/')[2]);

      try {
        const response: HumanInTheLoopResponse = await req.json();
        response.respondedAt = Date.now();

        // Update event in database
        const updatedEvent = updateEventHITLResponse(id, response);

        if (!updatedEvent) {
          return new Response(JSON.stringify({ error: 'Event not found' }), {
            status: 404,
            headers: { ...headers, 'Content-Type': 'application/json' }
          });
        }

        // Send response to agent via WebSocket
        if (updatedEvent.humanInTheLoop?.responseWebSocketUrl) {
          try {
            await sendResponseToAgent(
              updatedEvent.humanInTheLoop.responseWebSocketUrl,
              response
            );
          } catch (error) {
            console.error('Failed to send response to agent:', error);
            // Don't fail the request if we can't reach the agent
          }
        }

        // Broadcast updated event to all connected clients
        const message = JSON.stringify({ type: 'event', data: updatedEvent });
        wsClients.forEach(client => {
          try {
            client.send(message);
          } catch (err) {
            wsClients.delete(client);
          }
        });

        return new Response(JSON.stringify(updatedEvent), {
          headers: { ...headers, 'Content-Type': 'application/json' }
        });
      } catch (error) {
        console.error('Error processing HITL response:', error);
        return new Response(JSON.stringify({ error: 'Invalid request' }), {
          status: 400,
          headers: { ...headers, 'Content-Type': 'application/json' }
        });
      }
    }

    // Theme API endpoints
    
    // POST /api/themes - Create a new theme
    if (url.pathname === '/api/themes' && req.method === 'POST') {
      try {
        const themeData = await req.json();
        const result = await createTheme(themeData);
        
        const status = result.success ? 201 : 400;
        return new Response(JSON.stringify(result), {
          status,
          headers: { ...headers, 'Content-Type': 'application/json' }
        });
      } catch (error) {
        console.error('Error creating theme:', error);
        return new Response(JSON.stringify({ 
          success: false, 
          error: 'Invalid request body' 
        }), {
          status: 400,
          headers: { ...headers, 'Content-Type': 'application/json' }
        });
      }
    }
    
    // GET /api/themes - Search themes
    if (url.pathname === '/api/themes' && req.method === 'GET') {
      const query = {
        query: url.searchParams.get('query') || undefined,
        isPublic: url.searchParams.get('isPublic') ? url.searchParams.get('isPublic') === 'true' : undefined,
        authorId: url.searchParams.get('authorId') || undefined,
        sortBy: url.searchParams.get('sortBy') as any || undefined,
        sortOrder: url.searchParams.get('sortOrder') as any || undefined,
        limit: url.searchParams.get('limit') ? parseInt(url.searchParams.get('limit')!) : undefined,
        offset: url.searchParams.get('offset') ? parseInt(url.searchParams.get('offset')!) : undefined,
      };
      
      const result = await searchThemes(query);
      return new Response(JSON.stringify(result), {
        headers: { ...headers, 'Content-Type': 'application/json' }
      });
    }
    
    // GET /api/themes/:id - Get a specific theme
    if (url.pathname.startsWith('/api/themes/') && req.method === 'GET') {
      const id = url.pathname.split('/')[3];
      if (!id) {
        return new Response(JSON.stringify({ 
          success: false, 
          error: 'Theme ID is required' 
        }), {
          status: 400,
          headers: { ...headers, 'Content-Type': 'application/json' }
        });
      }
      
      const result = await getThemeById(id);
      const status = result.success ? 200 : 404;
      return new Response(JSON.stringify(result), {
        status,
        headers: { ...headers, 'Content-Type': 'application/json' }
      });
    }
    
    // PUT /api/themes/:id - Update a theme
    if (url.pathname.startsWith('/api/themes/') && req.method === 'PUT') {
      const id = url.pathname.split('/')[3];
      if (!id) {
        return new Response(JSON.stringify({ 
          success: false, 
          error: 'Theme ID is required' 
        }), {
          status: 400,
          headers: { ...headers, 'Content-Type': 'application/json' }
        });
      }
      
      try {
        const updates = await req.json();
        const result = await updateThemeById(id, updates);
        
        const status = result.success ? 200 : 400;
        return new Response(JSON.stringify(result), {
          status,
          headers: { ...headers, 'Content-Type': 'application/json' }
        });
      } catch (error) {
        console.error('Error updating theme:', error);
        return new Response(JSON.stringify({ 
          success: false, 
          error: 'Invalid request body' 
        }), {
          status: 400,
          headers: { ...headers, 'Content-Type': 'application/json' }
        });
      }
    }
    
    // DELETE /api/themes/:id - Delete a theme
    if (url.pathname.startsWith('/api/themes/') && req.method === 'DELETE') {
      const id = url.pathname.split('/')[3];
      if (!id) {
        return new Response(JSON.stringify({ 
          success: false, 
          error: 'Theme ID is required' 
        }), {
          status: 400,
          headers: { ...headers, 'Content-Type': 'application/json' }
        });
      }
      
      const authorId = url.searchParams.get('authorId');
      const result = await deleteThemeById(id, authorId || undefined);
      
      const status = result.success ? 200 : (result.error?.includes('not found') ? 404 : 403);
      return new Response(JSON.stringify(result), {
        status,
        headers: { ...headers, 'Content-Type': 'application/json' }
      });
    }
    
    // GET /api/themes/:id/export - Export a theme
    if (url.pathname.match(/^\/api\/themes\/[^\/]+\/export$/) && req.method === 'GET') {
      const id = url.pathname.split('/')[3];
      
      const result = await exportThemeById(id);
      if (!result.success) {
        const status = result.error?.includes('not found') ? 404 : 400;
        return new Response(JSON.stringify(result), {
          status,
          headers: { ...headers, 'Content-Type': 'application/json' }
        });
      }
      
      return new Response(JSON.stringify(result.data), {
        headers: { 
          ...headers, 
          'Content-Type': 'application/json',
          'Content-Disposition': `attachment; filename="${result.data.theme.name}.json"`
        }
      });
    }
    
    // POST /api/themes/import - Import a theme
    if (url.pathname === '/api/themes/import' && req.method === 'POST') {
      try {
        const importData = await req.json();
        const authorId = url.searchParams.get('authorId');
        
        const result = await importTheme(importData, authorId || undefined);
        
        const status = result.success ? 201 : 400;
        return new Response(JSON.stringify(result), {
          status,
          headers: { ...headers, 'Content-Type': 'application/json' }
        });
      } catch (error) {
        console.error('Error importing theme:', error);
        return new Response(JSON.stringify({ 
          success: false, 
          error: 'Invalid import data' 
        }), {
          status: 400,
          headers: { ...headers, 'Content-Type': 'application/json' }
        });
      }
    }
    
    // GET /api/themes/stats - Get theme statistics
    if (url.pathname === '/api/themes/stats' && req.method === 'GET') {
      const result = await getThemeStats();
      return new Response(JSON.stringify(result), {
        headers: { ...headers, 'Content-Type': 'application/json' }
      });
    }

    // =====================================================
    // METRICS API ENDPOINTS
    // =====================================================

    // POST /api/metrics/tokens - Record token usage
    if (url.pathname === '/api/metrics/tokens' && req.method === 'POST') {
      try {
        const metric: TokenMetric = await req.json();

        if (!metric.session_id || !metric.source_app) {
          return new Response(JSON.stringify({ error: 'Missing session_id or source_app' }), {
            status: 400,
            headers: { ...headers, 'Content-Type': 'application/json' }
          });
        }

        const saved = insertTokenMetric(metric);

        // Broadcast to dashboard
        const message = JSON.stringify({ type: 'token_update', data: saved });
        wsClients.forEach(client => {
          try { client.send(message); } catch (err) { wsClients.delete(client); }
        });

        return new Response(JSON.stringify(saved), {
          headers: { ...headers, 'Content-Type': 'application/json' }
        });
      } catch (error) {
        console.error('Error recording token metric:', error);
        return new Response(JSON.stringify({ error: 'Invalid request' }), {
          status: 400,
          headers: { ...headers, 'Content-Type': 'application/json' }
        });
      }
    }

    // GET /api/metrics/tokens - Get token summary
    if (url.pathname === '/api/metrics/tokens' && req.method === 'GET') {
      const sessionId = url.searchParams.get('session_id') || undefined;
      const summary = getTokenSummary(sessionId);
      return new Response(JSON.stringify(summary), {
        headers: { ...headers, 'Content-Type': 'application/json' }
      });
    }

    // POST /api/metrics/tools - Record tool usage
    if (url.pathname === '/api/metrics/tools' && req.method === 'POST') {
      try {
        const metric: ToolMetric = await req.json();

        if (!metric.session_id || !metric.source_app || !metric.tool_name || !metric.status) {
          return new Response(JSON.stringify({ error: 'Missing required fields' }), {
            status: 400,
            headers: { ...headers, 'Content-Type': 'application/json' }
          });
        }

        const saved = insertToolMetric(metric);

        // Broadcast to dashboard
        const message = JSON.stringify({ type: 'tool_update', data: saved });
        wsClients.forEach(client => {
          try { client.send(message); } catch (err) { wsClients.delete(client); }
        });

        return new Response(JSON.stringify(saved), {
          headers: { ...headers, 'Content-Type': 'application/json' }
        });
      } catch (error) {
        console.error('Error recording tool metric:', error);
        return new Response(JSON.stringify({ error: 'Invalid request' }), {
          status: 400,
          headers: { ...headers, 'Content-Type': 'application/json' }
        });
      }
    }

    // GET /api/metrics/tools - Get tool effectiveness report
    if (url.pathname === '/api/metrics/tools' && req.method === 'GET') {
      const sessionId = url.searchParams.get('session_id') || undefined;
      const report = getToolEffectivenessReport(sessionId);
      return new Response(JSON.stringify(report), {
        headers: { ...headers, 'Content-Type': 'application/json' }
      });
    }

    // POST /api/metrics/findings - Record a finding
    if (url.pathname === '/api/metrics/findings' && req.method === 'POST') {
      try {
        const finding: Finding = await req.json();

        if (!finding.session_id || !finding.source_app || !finding.finding_id || !finding.vulnerability_type) {
          return new Response(JSON.stringify({ error: 'Missing required fields' }), {
            status: 400,
            headers: { ...headers, 'Content-Type': 'application/json' }
          });
        }

        const saved = insertFinding(finding);

        // Broadcast to dashboard
        const message = JSON.stringify({ type: 'finding_update', data: saved });
        wsClients.forEach(client => {
          try { client.send(message); } catch (err) { wsClients.delete(client); }
        });

        return new Response(JSON.stringify(saved), {
          headers: { ...headers, 'Content-Type': 'application/json' }
        });
      } catch (error) {
        console.error('Error recording finding:', error);
        return new Response(JSON.stringify({ error: 'Invalid request' }), {
          status: 400,
          headers: { ...headers, 'Content-Type': 'application/json' }
        });
      }
    }

    // GET /api/metrics/findings - Get findings summary or list
    if (url.pathname === '/api/metrics/findings' && req.method === 'GET') {
      const sessionId = url.searchParams.get('session_id') || undefined;
      const listMode = url.searchParams.get('list') === 'true';

      if (listMode) {
        const limit = parseInt(url.searchParams.get('limit') || '100');
        const findings = getFindings(sessionId, limit);
        return new Response(JSON.stringify(findings), {
          headers: { ...headers, 'Content-Type': 'application/json' }
        });
      }

      const summary = getFindingSummary(sessionId);
      return new Response(JSON.stringify(summary), {
        headers: { ...headers, 'Content-Type': 'application/json' }
      });
    }

    // POST /api/metrics/wstg - Record WSTG coverage
    if (url.pathname === '/api/metrics/wstg' && req.method === 'POST') {
      try {
        const coverage: WSTGCoverage = await req.json();

        if (!coverage.session_id || !coverage.source_app || !coverage.wstg_id || !coverage.status) {
          return new Response(JSON.stringify({ error: 'Missing required fields' }), {
            status: 400,
            headers: { ...headers, 'Content-Type': 'application/json' }
          });
        }

        const saved = insertWSTGCoverage(coverage);

        // Broadcast to dashboard
        const message = JSON.stringify({ type: 'wstg_update', data: saved });
        wsClients.forEach(client => {
          try { client.send(message); } catch (err) { wsClients.delete(client); }
        });

        return new Response(JSON.stringify(saved), {
          headers: { ...headers, 'Content-Type': 'application/json' }
        });
      } catch (error) {
        console.error('Error recording WSTG coverage:', error);
        return new Response(JSON.stringify({ error: 'Invalid request' }), {
          status: 400,
          headers: { ...headers, 'Content-Type': 'application/json' }
        });
      }
    }

    // GET /api/metrics/wstg - Get WSTG coverage report
    if (url.pathname === '/api/metrics/wstg' && req.method === 'GET') {
      const sessionId = url.searchParams.get('session_id') || undefined;
      const report = getWSTGCoverageReport(sessionId);
      return new Response(JSON.stringify(report), {
        headers: { ...headers, 'Content-Type': 'application/json' }
      });
    }

    // POST /api/sessions - Create or update a session
    if (url.pathname === '/api/sessions' && req.method === 'POST') {
      try {
        const session: Partial<SessionSummary> & { session_id: string } = await req.json();

        if (!session.session_id) {
          return new Response(JSON.stringify({ error: 'Missing session_id' }), {
            status: 400,
            headers: { ...headers, 'Content-Type': 'application/json' }
          });
        }

        const saved = upsertSession(session);

        // Broadcast to dashboard
        const message = JSON.stringify({ type: 'session_update', data: saved });
        wsClients.forEach(client => {
          try { client.send(message); } catch (err) { wsClients.delete(client); }
        });

        return new Response(JSON.stringify(saved), {
          headers: { ...headers, 'Content-Type': 'application/json' }
        });
      } catch (error) {
        console.error('Error updating session:', error);
        return new Response(JSON.stringify({ error: 'Invalid request' }), {
          status: 400,
          headers: { ...headers, 'Content-Type': 'application/json' }
        });
      }
    }

    // GET /api/sessions - Get sessions list
    if (url.pathname === '/api/sessions' && req.method === 'GET') {
      const status = url.searchParams.get('status') || undefined;
      const limit = parseInt(url.searchParams.get('limit') || '50');
      const sessions = getSessions(status, limit);
      return new Response(JSON.stringify(sessions), {
        headers: { ...headers, 'Content-Type': 'application/json' }
      });
    }

    // GET /api/sessions/:id - Get a specific session
    if (url.pathname.match(/^\/api\/sessions\/[^\/]+$/) && req.method === 'GET') {
      const sessionId = url.pathname.split('/')[3];
      const session = getSession(sessionId);

      if (!session) {
        return new Response(JSON.stringify({ error: 'Session not found' }), {
          status: 404,
          headers: { ...headers, 'Content-Type': 'application/json' }
        });
      }

      return new Response(JSON.stringify(session), {
        headers: { ...headers, 'Content-Type': 'application/json' }
      });
    }

    // POST /api/sessions/:id/agents - Add agent to session
    if (url.pathname.match(/^\/api\/sessions\/[^\/]+\/agents$/) && req.method === 'POST') {
      try {
        const sessionId = url.pathname.split('/')[3];
        const { agent_name } = await req.json();

        if (!agent_name) {
          return new Response(JSON.stringify({ error: 'Missing agent_name' }), {
            status: 400,
            headers: { ...headers, 'Content-Type': 'application/json' }
          });
        }

        addAgentToSession(sessionId, agent_name);
        const session = getSession(sessionId);

        return new Response(JSON.stringify(session), {
          headers: { ...headers, 'Content-Type': 'application/json' }
        });
      } catch (error) {
        return new Response(JSON.stringify({ error: 'Invalid request' }), {
          status: 400,
          headers: { ...headers, 'Content-Type': 'application/json' }
        });
      }
    }

    // GET /api/metrics/dashboard - Get full metrics dashboard
    if (url.pathname === '/api/metrics/dashboard' && req.method === 'GET') {
      const sessionId = url.searchParams.get('session_id') || undefined;
      const dashboard = getMetricsDashboard(sessionId);
      return new Response(JSON.stringify(dashboard), {
        headers: { ...headers, 'Content-Type': 'application/json' }
      });
    }

    // WebSocket upgrade
    if (url.pathname === '/stream') {
      const success = server.upgrade(req);
      if (success) {
        return undefined;
      }
    }
    
    // Default response
    return new Response('Multi-Agent Observability Server', {
      headers: { ...headers, 'Content-Type': 'text/plain' }
    });
  },
  
  websocket: {
    open(ws) {
      console.log('WebSocket client connected');
      wsClients.add(ws);
      
      // Send recent events on connection
      const events = getRecentEvents(300);
      ws.send(JSON.stringify({ type: 'initial', data: events }));
    },
    
    message(ws, message) {
      // Handle any client messages if needed
      console.log('Received message:', message);
    },
    
    close(ws) {
      console.log('WebSocket client disconnected');
      wsClients.delete(ws);
    },
    
    error(ws, error) {
      console.error('WebSocket error:', error);
      wsClients.delete(ws);
    }
  }
});

console.log(`🚀 Server running on http://localhost:${server.port}`);
console.log(`📊 WebSocket endpoint: ws://localhost:${server.port}/stream`);
console.log(`📮 POST events to: http://localhost:${server.port}/events`);