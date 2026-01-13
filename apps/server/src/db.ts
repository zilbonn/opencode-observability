import { Database } from 'bun:sqlite';
import type {
  HookEvent,
  FilterOptions,
  Theme,
  ThemeSearchQuery,
  TokenMetric,
  TokenSummary,
  ToolMetric,
  ToolEffectivenessReport,
  Finding,
  FindingSummary,
  WSTGCoverage,
  WSTGCoverageReport,
  SessionSummary,
  MetricsDashboard
} from './types';

let db: Database;

export function initDatabase(): void {
  db = new Database('events.db');
  
  // Enable WAL mode for better concurrent performance
  db.exec('PRAGMA journal_mode = WAL');
  db.exec('PRAGMA synchronous = NORMAL');
  
  // Create events table
  db.exec(`
    CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      source_app TEXT NOT NULL,
      session_id TEXT NOT NULL,
      hook_event_type TEXT NOT NULL,
      payload TEXT NOT NULL,
      chat TEXT,
      summary TEXT,
      timestamp INTEGER NOT NULL
    )
  `);
  
  // Check if chat column exists, add it if not (for migration)
  try {
    const columns = db.prepare("PRAGMA table_info(events)").all() as any[];
    const hasChatColumn = columns.some((col: any) => col.name === 'chat');
    if (!hasChatColumn) {
      db.exec('ALTER TABLE events ADD COLUMN chat TEXT');
    }

    // Check if summary column exists, add it if not (for migration)
    const hasSummaryColumn = columns.some((col: any) => col.name === 'summary');
    if (!hasSummaryColumn) {
      db.exec('ALTER TABLE events ADD COLUMN summary TEXT');
    }

    // Check if humanInTheLoop column exists, add it if not (for migration)
    const hasHumanInTheLoopColumn = columns.some((col: any) => col.name === 'humanInTheLoop');
    if (!hasHumanInTheLoopColumn) {
      db.exec('ALTER TABLE events ADD COLUMN humanInTheLoop TEXT');
    }

    // Check if humanInTheLoopStatus column exists, add it if not (for migration)
    const hasHumanInTheLoopStatusColumn = columns.some((col: any) => col.name === 'humanInTheLoopStatus');
    if (!hasHumanInTheLoopStatusColumn) {
      db.exec('ALTER TABLE events ADD COLUMN humanInTheLoopStatus TEXT');
    }

    // Check if model_name column exists, add it if not (for migration)
    const hasModelNameColumn = columns.some((col: any) => col.name === 'model_name');
    if (!hasModelNameColumn) {
      db.exec('ALTER TABLE events ADD COLUMN model_name TEXT');
    }
  } catch (error) {
    // If the table doesn't exist yet, the CREATE TABLE above will handle it
  }
  
  // Create indexes for common queries
  db.exec('CREATE INDEX IF NOT EXISTS idx_source_app ON events(source_app)');
  db.exec('CREATE INDEX IF NOT EXISTS idx_session_id ON events(session_id)');
  db.exec('CREATE INDEX IF NOT EXISTS idx_hook_event_type ON events(hook_event_type)');
  db.exec('CREATE INDEX IF NOT EXISTS idx_timestamp ON events(timestamp)');
  
  // Create themes table
  db.exec(`
    CREATE TABLE IF NOT EXISTS themes (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL UNIQUE,
      displayName TEXT NOT NULL,
      description TEXT,
      colors TEXT NOT NULL,
      isPublic INTEGER NOT NULL DEFAULT 0,
      authorId TEXT,
      authorName TEXT,
      createdAt INTEGER NOT NULL,
      updatedAt INTEGER NOT NULL,
      tags TEXT,
      downloadCount INTEGER DEFAULT 0,
      rating REAL DEFAULT 0,
      ratingCount INTEGER DEFAULT 0
    )
  `);
  
  // Create theme shares table
  db.exec(`
    CREATE TABLE IF NOT EXISTS theme_shares (
      id TEXT PRIMARY KEY,
      themeId TEXT NOT NULL,
      shareToken TEXT NOT NULL UNIQUE,
      expiresAt INTEGER,
      isPublic INTEGER NOT NULL DEFAULT 0,
      allowedUsers TEXT,
      createdAt INTEGER NOT NULL,
      accessCount INTEGER DEFAULT 0,
      FOREIGN KEY (themeId) REFERENCES themes (id) ON DELETE CASCADE
    )
  `);
  
  // Create theme ratings table
  db.exec(`
    CREATE TABLE IF NOT EXISTS theme_ratings (
      id TEXT PRIMARY KEY,
      themeId TEXT NOT NULL,
      userId TEXT NOT NULL,
      rating INTEGER NOT NULL,
      comment TEXT,
      createdAt INTEGER NOT NULL,
      UNIQUE(themeId, userId),
      FOREIGN KEY (themeId) REFERENCES themes (id) ON DELETE CASCADE
    )
  `);
  
  // Create indexes for theme tables
  db.exec('CREATE INDEX IF NOT EXISTS idx_themes_name ON themes(name)');
  db.exec('CREATE INDEX IF NOT EXISTS idx_themes_isPublic ON themes(isPublic)');
  db.exec('CREATE INDEX IF NOT EXISTS idx_themes_createdAt ON themes(createdAt)');
  db.exec('CREATE INDEX IF NOT EXISTS idx_theme_shares_token ON theme_shares(shareToken)');
  db.exec('CREATE INDEX IF NOT EXISTS idx_theme_ratings_theme ON theme_ratings(themeId)');

  // =====================================================
  // METRICS TABLES - For Wardenn Security Assessment Tracking
  // =====================================================

  // Token metrics table
  db.exec(`
    CREATE TABLE IF NOT EXISTS token_metrics (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id TEXT NOT NULL,
      source_app TEXT NOT NULL,
      model_name TEXT,
      input_tokens INTEGER DEFAULT 0,
      output_tokens INTEGER DEFAULT 0,
      total_tokens INTEGER DEFAULT 0,
      estimated_cost REAL DEFAULT 0,
      timestamp INTEGER NOT NULL
    )
  `);
  db.exec('CREATE INDEX IF NOT EXISTS idx_token_metrics_session ON token_metrics(session_id)');
  db.exec('CREATE INDEX IF NOT EXISTS idx_token_metrics_source_app ON token_metrics(source_app)');
  db.exec('CREATE INDEX IF NOT EXISTS idx_token_metrics_timestamp ON token_metrics(timestamp)');

  // Tool metrics table
  db.exec(`
    CREATE TABLE IF NOT EXISTS tool_metrics (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id TEXT NOT NULL,
      source_app TEXT NOT NULL,
      tool_name TEXT NOT NULL,
      tool_type TEXT,
      status TEXT NOT NULL,
      duration_ms INTEGER,
      found_vulnerability INTEGER DEFAULT 0,
      vulnerability_type TEXT,
      error_message TEXT,
      timestamp INTEGER NOT NULL
    )
  `);
  db.exec('CREATE INDEX IF NOT EXISTS idx_tool_metrics_session ON tool_metrics(session_id)');
  db.exec('CREATE INDEX IF NOT EXISTS idx_tool_metrics_tool ON tool_metrics(tool_name)');
  db.exec('CREATE INDEX IF NOT EXISTS idx_tool_metrics_status ON tool_metrics(status)');

  // Findings table
  db.exec(`
    CREATE TABLE IF NOT EXISTS findings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id TEXT NOT NULL,
      source_app TEXT NOT NULL,
      finding_id TEXT UNIQUE,
      vulnerability_type TEXT NOT NULL,
      severity TEXT,
      confidence TEXT,
      wstg_id TEXT,
      tool_used TEXT,
      target_url TEXT,
      location TEXT,
      title TEXT,
      description TEXT,
      timestamp INTEGER NOT NULL
    )
  `);
  db.exec('CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id)');
  db.exec('CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(vulnerability_type)');
  db.exec('CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)');

  // WSTG coverage table
  db.exec(`
    CREATE TABLE IF NOT EXISTS wstg_coverage (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id TEXT NOT NULL,
      source_app TEXT NOT NULL,
      wstg_id TEXT NOT NULL,
      wstg_name TEXT,
      status TEXT NOT NULL,
      skip_reason TEXT,
      findings_count INTEGER DEFAULT 0,
      timestamp INTEGER NOT NULL,
      UNIQUE(session_id, wstg_id)
    )
  `);
  db.exec('CREATE INDEX IF NOT EXISTS idx_wstg_session ON wstg_coverage(session_id)');
  db.exec('CREATE INDEX IF NOT EXISTS idx_wstg_status ON wstg_coverage(status)');

  // Sessions summary table
  db.exec(`
    CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id TEXT UNIQUE NOT NULL,
      client_name TEXT,
      target_url TEXT,
      status TEXT DEFAULT 'running',
      started_at INTEGER NOT NULL,
      ended_at INTEGER,
      duration_ms INTEGER,
      total_tokens INTEGER DEFAULT 0,
      total_cost REAL DEFAULT 0,
      total_findings INTEGER DEFAULT 0,
      total_tool_calls INTEGER DEFAULT 0,
      agents_used TEXT,
      wstg_coverage_pct REAL DEFAULT 0
    )
  `);
  db.exec('CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status)');
  db.exec('CREATE INDEX IF NOT EXISTS idx_sessions_client ON sessions(client_name)');
}

export function insertEvent(event: HookEvent): HookEvent {
  const stmt = db.prepare(`
    INSERT INTO events (source_app, session_id, hook_event_type, payload, chat, summary, timestamp, humanInTheLoop, humanInTheLoopStatus, model_name)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const timestamp = event.timestamp || Date.now();

  // Initialize humanInTheLoopStatus to pending if humanInTheLoop exists
  let humanInTheLoopStatus = event.humanInTheLoopStatus;
  if (event.humanInTheLoop && !humanInTheLoopStatus) {
    humanInTheLoopStatus = { status: 'pending' };
  }

  const result = stmt.run(
    event.source_app,
    event.session_id,
    event.hook_event_type,
    JSON.stringify(event.payload),
    event.chat ? JSON.stringify(event.chat) : null,
    event.summary || null,
    timestamp,
    event.humanInTheLoop ? JSON.stringify(event.humanInTheLoop) : null,
    humanInTheLoopStatus ? JSON.stringify(humanInTheLoopStatus) : null,
    event.model_name || null
  );

  return {
    ...event,
    id: result.lastInsertRowid as number,
    timestamp,
    humanInTheLoopStatus
  };
}

export function getFilterOptions(): FilterOptions {
  const sourceApps = db.prepare('SELECT DISTINCT source_app FROM events ORDER BY source_app').all() as { source_app: string }[];
  const sessionIds = db.prepare('SELECT DISTINCT session_id FROM events ORDER BY session_id DESC LIMIT 300').all() as { session_id: string }[];
  const hookEventTypes = db.prepare('SELECT DISTINCT hook_event_type FROM events ORDER BY hook_event_type').all() as { hook_event_type: string }[];
  
  return {
    source_apps: sourceApps.map(row => row.source_app),
    session_ids: sessionIds.map(row => row.session_id),
    hook_event_types: hookEventTypes.map(row => row.hook_event_type)
  };
}

export function getRecentEvents(limit: number = 300): HookEvent[] {
  const stmt = db.prepare(`
    SELECT id, source_app, session_id, hook_event_type, payload, chat, summary, timestamp, humanInTheLoop, humanInTheLoopStatus, model_name
    FROM events
    ORDER BY timestamp DESC
    LIMIT ?
  `);

  const rows = stmt.all(limit) as any[];

  return rows.map(row => ({
    id: row.id,
    source_app: row.source_app,
    session_id: row.session_id,
    hook_event_type: row.hook_event_type,
    payload: JSON.parse(row.payload),
    chat: row.chat ? JSON.parse(row.chat) : undefined,
    summary: row.summary || undefined,
    timestamp: row.timestamp,
    humanInTheLoop: row.humanInTheLoop ? JSON.parse(row.humanInTheLoop) : undefined,
    humanInTheLoopStatus: row.humanInTheLoopStatus ? JSON.parse(row.humanInTheLoopStatus) : undefined,
    model_name: row.model_name || undefined
  })).reverse();
}

// Theme database functions
export function insertTheme(theme: Theme): Theme {
  const stmt = db.prepare(`
    INSERT INTO themes (id, name, displayName, description, colors, isPublic, authorId, authorName, createdAt, updatedAt, tags, downloadCount, rating, ratingCount)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  
  stmt.run(
    theme.id,
    theme.name,
    theme.displayName,
    theme.description || null,
    JSON.stringify(theme.colors),
    theme.isPublic ? 1 : 0,
    theme.authorId || null,
    theme.authorName || null,
    theme.createdAt,
    theme.updatedAt,
    JSON.stringify(theme.tags),
    theme.downloadCount || 0,
    theme.rating || 0,
    theme.ratingCount || 0
  );
  
  return theme;
}

export function updateTheme(id: string, updates: Partial<Theme>): boolean {
  const allowedFields = ['displayName', 'description', 'colors', 'isPublic', 'updatedAt', 'tags'];
  const setClause = Object.keys(updates)
    .filter(key => allowedFields.includes(key))
    .map(key => `${key} = ?`)
    .join(', ');
  
  if (!setClause) return false;
  
  const values = Object.keys(updates)
    .filter(key => allowedFields.includes(key))
    .map(key => {
      if (key === 'colors' || key === 'tags') {
        return JSON.stringify(updates[key as keyof Theme]);
      }
      if (key === 'isPublic') {
        return updates[key as keyof Theme] ? 1 : 0;
      }
      return updates[key as keyof Theme];
    });
  
  const stmt = db.prepare(`UPDATE themes SET ${setClause} WHERE id = ?`);
  const result = stmt.run(...values, id);
  
  return result.changes > 0;
}

export function getTheme(id: string): Theme | null {
  const stmt = db.prepare('SELECT * FROM themes WHERE id = ?');
  const row = stmt.get(id) as any;
  
  if (!row) return null;
  
  return {
    id: row.id,
    name: row.name,
    displayName: row.displayName,
    description: row.description,
    colors: JSON.parse(row.colors),
    isPublic: Boolean(row.isPublic),
    authorId: row.authorId,
    authorName: row.authorName,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    tags: JSON.parse(row.tags || '[]'),
    downloadCount: row.downloadCount,
    rating: row.rating,
    ratingCount: row.ratingCount
  };
}

export function getThemes(query: ThemeSearchQuery = {}): Theme[] {
  let sql = 'SELECT * FROM themes WHERE 1=1';
  const params: any[] = [];
  
  if (query.isPublic !== undefined) {
    sql += ' AND isPublic = ?';
    params.push(query.isPublic ? 1 : 0);
  }
  
  if (query.authorId) {
    sql += ' AND authorId = ?';
    params.push(query.authorId);
  }
  
  if (query.query) {
    sql += ' AND (name LIKE ? OR displayName LIKE ? OR description LIKE ?)';
    const searchTerm = `%${query.query}%`;
    params.push(searchTerm, searchTerm, searchTerm);
  }
  
  // Add sorting
  const sortBy = query.sortBy || 'created';
  const sortOrder = query.sortOrder || 'desc';
  const sortColumn = {
    name: 'name',
    created: 'createdAt',
    updated: 'updatedAt',
    downloads: 'downloadCount',
    rating: 'rating'
  }[sortBy] || 'createdAt';
  
  sql += ` ORDER BY ${sortColumn} ${sortOrder.toUpperCase()}`;
  
  // Add pagination
  if (query.limit) {
    sql += ' LIMIT ?';
    params.push(query.limit);
    
    if (query.offset) {
      sql += ' OFFSET ?';
      params.push(query.offset);
    }
  }
  
  const stmt = db.prepare(sql);
  const rows = stmt.all(...params) as any[];
  
  return rows.map(row => ({
    id: row.id,
    name: row.name,
    displayName: row.displayName,
    description: row.description,
    colors: JSON.parse(row.colors),
    isPublic: Boolean(row.isPublic),
    authorId: row.authorId,
    authorName: row.authorName,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    tags: JSON.parse(row.tags || '[]'),
    downloadCount: row.downloadCount,
    rating: row.rating,
    ratingCount: row.ratingCount
  }));
}

export function deleteTheme(id: string): boolean {
  const stmt = db.prepare('DELETE FROM themes WHERE id = ?');
  const result = stmt.run(id);
  return result.changes > 0;
}

export function incrementThemeDownloadCount(id: string): boolean {
  const stmt = db.prepare('UPDATE themes SET downloadCount = downloadCount + 1 WHERE id = ?');
  const result = stmt.run(id);
  return result.changes > 0;
}

// HITL helper functions
export function updateEventHITLResponse(id: number, response: any): HookEvent | null {
  const status = {
    status: 'responded',
    respondedAt: response.respondedAt,
    response
  };

  const stmt = db.prepare('UPDATE events SET humanInTheLoopStatus = ? WHERE id = ?');
  stmt.run(JSON.stringify(status), id);

  const selectStmt = db.prepare(`
    SELECT id, source_app, session_id, hook_event_type, payload, chat, summary, timestamp, humanInTheLoop, humanInTheLoopStatus, model_name
    FROM events
    WHERE id = ?
  `);
  const row = selectStmt.get(id) as any;

  if (!row) return null;

  return {
    id: row.id,
    source_app: row.source_app,
    session_id: row.session_id,
    hook_event_type: row.hook_event_type,
    payload: JSON.parse(row.payload),
    chat: row.chat ? JSON.parse(row.chat) : undefined,
    summary: row.summary || undefined,
    timestamp: row.timestamp,
    humanInTheLoop: row.humanInTheLoop ? JSON.parse(row.humanInTheLoop) : undefined,
    humanInTheLoopStatus: row.humanInTheLoopStatus ? JSON.parse(row.humanInTheLoopStatus) : undefined,
    model_name: row.model_name || undefined
  };
}

// =====================================================
// METRICS FUNCTIONS
// =====================================================

// Token Metrics
export function insertTokenMetric(metric: TokenMetric): TokenMetric {
  const stmt = db.prepare(`
    INSERT INTO token_metrics (session_id, source_app, model_name, input_tokens, output_tokens, total_tokens, estimated_cost, timestamp)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const timestamp = metric.timestamp || Date.now();
  const result = stmt.run(
    metric.session_id,
    metric.source_app,
    metric.model_name || null,
    metric.input_tokens,
    metric.output_tokens,
    metric.total_tokens,
    metric.estimated_cost,
    timestamp
  );

  // Update session totals
  updateSessionTokens(metric.session_id, metric.total_tokens, metric.estimated_cost);

  return {
    ...metric,
    id: result.lastInsertRowid as number,
    timestamp
  };
}

export function getTokenSummary(sessionId?: string): TokenSummary {
  let whereClause = '';
  const params: any[] = [];

  if (sessionId) {
    whereClause = 'WHERE session_id = ?';
    params.push(sessionId);
  }

  // Get totals
  const totalsStmt = db.prepare(`
    SELECT
      COALESCE(SUM(input_tokens), 0) as total_input,
      COALESCE(SUM(output_tokens), 0) as total_output,
      COALESCE(SUM(total_tokens), 0) as total,
      COALESCE(SUM(estimated_cost), 0) as cost
    FROM token_metrics ${whereClause}
  `);
  const totals = totalsStmt.get(...params) as any;

  // Get by model
  const byModelStmt = db.prepare(`
    SELECT
      model_name,
      SUM(total_tokens) as tokens,
      SUM(estimated_cost) as cost
    FROM token_metrics ${whereClause}
    GROUP BY model_name
  `);
  const byModelRows = byModelStmt.all(...params) as any[];
  const by_model: Record<string, { tokens: number; cost: number }> = {};
  byModelRows.forEach(row => {
    if (row.model_name) {
      by_model[row.model_name] = { tokens: row.tokens, cost: row.cost };
    }
  });

  // Get by agent
  const byAgentStmt = db.prepare(`
    SELECT
      source_app,
      SUM(total_tokens) as tokens,
      SUM(estimated_cost) as cost
    FROM token_metrics ${whereClause}
    GROUP BY source_app
  `);
  const byAgentRows = byAgentStmt.all(...params) as any[];
  const by_agent: Record<string, { tokens: number; cost: number }> = {};
  byAgentRows.forEach(row => {
    by_agent[row.source_app] = { tokens: row.tokens, cost: row.cost };
  });

  return {
    session_id: sessionId,
    total_input_tokens: totals.total_input,
    total_output_tokens: totals.total_output,
    total_tokens: totals.total,
    total_cost: totals.cost,
    by_model,
    by_agent
  };
}

// Tool Metrics
export function insertToolMetric(metric: ToolMetric): ToolMetric {
  const stmt = db.prepare(`
    INSERT INTO tool_metrics (session_id, source_app, tool_name, tool_type, status, duration_ms, found_vulnerability, vulnerability_type, error_message, timestamp)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const timestamp = metric.timestamp || Date.now();
  const result = stmt.run(
    metric.session_id,
    metric.source_app,
    metric.tool_name,
    metric.tool_type || null,
    metric.status,
    metric.duration_ms || null,
    metric.found_vulnerability ? 1 : 0,
    metric.vulnerability_type || null,
    metric.error_message || null,
    timestamp
  );

  // Update session tool count
  updateSessionToolCount(metric.session_id);

  return {
    ...metric,
    id: result.lastInsertRowid as number,
    timestamp
  };
}

export function getToolEffectivenessReport(sessionId?: string): ToolEffectivenessReport[] {
  let whereClause = '';
  const params: any[] = [];

  if (sessionId) {
    whereClause = 'WHERE session_id = ?';
    params.push(sessionId);
  }

  const stmt = db.prepare(`
    SELECT
      tool_name,
      COUNT(*) as total_calls,
      SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) as success_count,
      SUM(CASE WHEN status = 'failure' THEN 1 ELSE 0 END) as failure_count,
      SUM(CASE WHEN status = 'timeout' THEN 1 ELSE 0 END) as timeout_count,
      AVG(CASE WHEN duration_ms IS NOT NULL THEN duration_ms ELSE 0 END) as avg_duration,
      SUM(found_vulnerability) as vulns_found
    FROM tool_metrics ${whereClause}
    GROUP BY tool_name
    ORDER BY total_calls DESC
  `);

  const rows = stmt.all(...params) as any[];
  return rows.map(row => ({
    tool_name: row.tool_name,
    total_calls: row.total_calls,
    success_count: row.success_count,
    failure_count: row.failure_count,
    timeout_count: row.timeout_count,
    success_rate: row.total_calls > 0 ? (row.success_count / row.total_calls) * 100 : 0,
    avg_duration_ms: row.avg_duration || 0,
    vulnerabilities_found: row.vulns_found
  }));
}

// Findings
export function insertFinding(finding: Finding): Finding {
  const stmt = db.prepare(`
    INSERT OR REPLACE INTO findings (session_id, source_app, finding_id, vulnerability_type, severity, confidence, wstg_id, tool_used, target_url, location, title, description, timestamp)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const timestamp = finding.timestamp || Date.now();
  const result = stmt.run(
    finding.session_id,
    finding.source_app,
    finding.finding_id,
    finding.vulnerability_type,
    finding.severity || 'medium',
    finding.confidence || 'possible',
    finding.wstg_id || null,
    finding.tool_used || null,
    finding.target_url || null,
    finding.location || null,
    finding.title || null,
    finding.description || null,
    timestamp
  );

  // Update session finding count
  updateSessionFindingCount(finding.session_id);

  return {
    ...finding,
    id: result.lastInsertRowid as number,
    timestamp
  };
}

export function getFindingSummary(sessionId?: string): FindingSummary {
  let whereClause = '';
  const params: any[] = [];

  if (sessionId) {
    whereClause = 'WHERE session_id = ?';
    params.push(sessionId);
  }

  // Total count
  const totalStmt = db.prepare(`SELECT COUNT(*) as count FROM findings ${whereClause}`);
  const total = (totalStmt.get(...params) as any).count;

  // By severity
  const bySeverityStmt = db.prepare(`
    SELECT severity, COUNT(*) as count FROM findings ${whereClause} GROUP BY severity
  `);
  const bySeverityRows = bySeverityStmt.all(...params) as any[];
  const by_severity: Record<string, number> = {};
  bySeverityRows.forEach(row => {
    by_severity[row.severity || 'unknown'] = row.count;
  });

  // By type
  const byTypeStmt = db.prepare(`
    SELECT vulnerability_type, COUNT(*) as count FROM findings ${whereClause} GROUP BY vulnerability_type
  `);
  const byTypeRows = byTypeStmt.all(...params) as any[];
  const by_type: Record<string, number> = {};
  byTypeRows.forEach(row => {
    by_type[row.vulnerability_type] = row.count;
  });

  // By agent
  const byAgentStmt = db.prepare(`
    SELECT source_app, COUNT(*) as count FROM findings ${whereClause} GROUP BY source_app
  `);
  const byAgentRows = byAgentStmt.all(...params) as any[];
  const by_agent: Record<string, number> = {};
  byAgentRows.forEach(row => {
    by_agent[row.source_app] = row.count;
  });

  // By confidence
  const byConfidenceStmt = db.prepare(`
    SELECT confidence, COUNT(*) as count FROM findings ${whereClause} GROUP BY confidence
  `);
  const byConfidenceRows = byConfidenceStmt.all(...params) as any[];
  const by_confidence: Record<string, number> = {};
  byConfidenceRows.forEach(row => {
    by_confidence[row.confidence || 'unknown'] = row.count;
  });

  return {
    total_findings: total,
    by_severity,
    by_type,
    by_agent,
    by_confidence
  };
}

export function getFindings(sessionId?: string, limit: number = 100): Finding[] {
  let whereClause = '';
  const params: any[] = [];

  if (sessionId) {
    whereClause = 'WHERE session_id = ?';
    params.push(sessionId);
  }

  const stmt = db.prepare(`
    SELECT * FROM findings ${whereClause}
    ORDER BY timestamp DESC
    LIMIT ?
  `);
  params.push(limit);

  return stmt.all(...params) as Finding[];
}

// WSTG Coverage
export function insertWSTGCoverage(coverage: WSTGCoverage): WSTGCoverage {
  const stmt = db.prepare(`
    INSERT OR REPLACE INTO wstg_coverage (session_id, source_app, wstg_id, wstg_name, status, skip_reason, findings_count, timestamp)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const timestamp = coverage.timestamp || Date.now();
  const result = stmt.run(
    coverage.session_id,
    coverage.source_app,
    coverage.wstg_id,
    coverage.wstg_name || null,
    coverage.status,
    coverage.skip_reason || null,
    coverage.findings_count,
    timestamp
  );

  // Update session WSTG coverage percentage
  updateSessionWSTGCoverage(coverage.session_id);

  return {
    ...coverage,
    id: result.lastInsertRowid as number,
    timestamp
  };
}

export function getWSTGCoverageReport(sessionId?: string): WSTGCoverageReport {
  let whereClause = '';
  const params: any[] = [];

  if (sessionId) {
    whereClause = 'WHERE session_id = ?';
    params.push(sessionId);
  }

  // Get counts by status
  const statusStmt = db.prepare(`
    SELECT
      COUNT(*) as total,
      SUM(CASE WHEN status = 'executed' THEN 1 ELSE 0 END) as executed,
      SUM(CASE WHEN status = 'skipped' THEN 1 ELSE 0 END) as skipped,
      SUM(CASE WHEN status = 'partial' THEN 1 ELSE 0 END) as partial,
      SUM(CASE WHEN status = 'not_applicable' THEN 1 ELSE 0 END) as not_applicable
    FROM wstg_coverage ${whereClause}
  `);
  const status = statusStmt.get(...params) as any;

  // Get by category (extract category from WSTG ID like "WSTG-INPV-05" -> "INPV")
  const byCategoryStmt = db.prepare(`
    SELECT
      SUBSTR(wstg_id, 6, 4) as category,
      COUNT(*) as total,
      SUM(CASE WHEN status = 'executed' THEN 1 ELSE 0 END) as executed
    FROM wstg_coverage ${whereClause}
    GROUP BY category
  `);
  const byCategoryRows = byCategoryStmt.all(...params) as any[];
  const by_category: Record<string, { executed: number; total: number; percentage: number }> = {};
  byCategoryRows.forEach(row => {
    by_category[row.category] = {
      executed: row.executed,
      total: row.total,
      percentage: row.total > 0 ? (row.executed / row.total) * 100 : 0
    };
  });

  const applicableTests = status.total - status.not_applicable;
  const coveragePercentage = applicableTests > 0 ? (status.executed / applicableTests) * 100 : 0;

  return {
    total_tests: status.total,
    executed: status.executed,
    skipped: status.skipped,
    partial: status.partial,
    not_applicable: status.not_applicable,
    coverage_percentage: coveragePercentage,
    by_category
  };
}

// Session Management
export function upsertSession(session: Partial<SessionSummary> & { session_id: string }): SessionSummary {
  // Check if session exists
  const existingStmt = db.prepare('SELECT * FROM sessions WHERE session_id = ?');
  const existing = existingStmt.get(session.session_id) as any;

  if (existing) {
    // Update existing session
    const updateStmt = db.prepare(`
      UPDATE sessions SET
        client_name = COALESCE(?, client_name),
        target_url = COALESCE(?, target_url),
        status = COALESCE(?, status),
        ended_at = COALESCE(?, ended_at),
        duration_ms = COALESCE(?, duration_ms)
      WHERE session_id = ?
    `);
    updateStmt.run(
      session.client_name || null,
      session.target_url || null,
      session.status || null,
      session.ended_at || null,
      session.duration_ms || null,
      session.session_id
    );
  } else {
    // Insert new session
    const insertStmt = db.prepare(`
      INSERT INTO sessions (session_id, client_name, target_url, status, started_at, agents_used)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    insertStmt.run(
      session.session_id,
      session.client_name || null,
      session.target_url || null,
      session.status || 'running',
      session.started_at || Date.now(),
      JSON.stringify(session.agents_used || [])
    );
  }

  return getSession(session.session_id)!;
}

export function getSession(sessionId: string): SessionSummary | null {
  const stmt = db.prepare('SELECT * FROM sessions WHERE session_id = ?');
  const row = stmt.get(sessionId) as any;

  if (!row) return null;

  return {
    id: row.id,
    session_id: row.session_id,
    client_name: row.client_name,
    target_url: row.target_url,
    status: row.status,
    started_at: row.started_at,
    ended_at: row.ended_at,
    duration_ms: row.duration_ms,
    total_tokens: row.total_tokens,
    total_cost: row.total_cost,
    total_findings: row.total_findings,
    total_tool_calls: row.total_tool_calls,
    agents_used: row.agents_used ? JSON.parse(row.agents_used) : [],
    wstg_coverage_pct: row.wstg_coverage_pct
  };
}

export function getSessions(status?: string, limit: number = 50): SessionSummary[] {
  let whereClause = '';
  const params: any[] = [];

  if (status) {
    whereClause = 'WHERE status = ?';
    params.push(status);
  }

  const stmt = db.prepare(`
    SELECT * FROM sessions ${whereClause}
    ORDER BY started_at DESC
    LIMIT ?
  `);
  params.push(limit);

  const rows = stmt.all(...params) as any[];
  return rows.map(row => ({
    id: row.id,
    session_id: row.session_id,
    client_name: row.client_name,
    target_url: row.target_url,
    status: row.status,
    started_at: row.started_at,
    ended_at: row.ended_at,
    duration_ms: row.duration_ms,
    total_tokens: row.total_tokens,
    total_cost: row.total_cost,
    total_findings: row.total_findings,
    total_tool_calls: row.total_tool_calls,
    agents_used: row.agents_used ? JSON.parse(row.agents_used) : [],
    wstg_coverage_pct: row.wstg_coverage_pct
  }));
}

// Helper functions to update session aggregates
function updateSessionTokens(sessionId: string, tokens: number, cost: number): void {
  const stmt = db.prepare(`
    UPDATE sessions
    SET total_tokens = total_tokens + ?, total_cost = total_cost + ?
    WHERE session_id = ?
  `);
  stmt.run(tokens, cost, sessionId);
}

function updateSessionToolCount(sessionId: string): void {
  const stmt = db.prepare(`
    UPDATE sessions
    SET total_tool_calls = (SELECT COUNT(*) FROM tool_metrics WHERE session_id = ?)
    WHERE session_id = ?
  `);
  stmt.run(sessionId, sessionId);
}

function updateSessionFindingCount(sessionId: string): void {
  const stmt = db.prepare(`
    UPDATE sessions
    SET total_findings = (SELECT COUNT(*) FROM findings WHERE session_id = ?)
    WHERE session_id = ?
  `);
  stmt.run(sessionId, sessionId);
}

function updateSessionWSTGCoverage(sessionId: string): void {
  const stmt = db.prepare(`
    UPDATE sessions
    SET wstg_coverage_pct = (
      SELECT CASE
        WHEN COUNT(*) - SUM(CASE WHEN status = 'not_applicable' THEN 1 ELSE 0 END) > 0
        THEN (SUM(CASE WHEN status = 'executed' THEN 1 ELSE 0 END) * 100.0) /
             (COUNT(*) - SUM(CASE WHEN status = 'not_applicable' THEN 1 ELSE 0 END))
        ELSE 0
      END
      FROM wstg_coverage WHERE session_id = ?
    )
    WHERE session_id = ?
  `);
  stmt.run(sessionId, sessionId);
}

// Add agent to session
export function addAgentToSession(sessionId: string, agentName: string): void {
  const session = getSession(sessionId);
  if (!session) return;

  const agents = session.agents_used || [];
  if (!agents.includes(agentName)) {
    agents.push(agentName);
    const stmt = db.prepare('UPDATE sessions SET agents_used = ? WHERE session_id = ?');
    stmt.run(JSON.stringify(agents), sessionId);
  }
}

// Get full metrics dashboard
export function getMetricsDashboard(sessionId?: string): MetricsDashboard {
  // Session stats
  const sessionsStmt = db.prepare(`
    SELECT
      COUNT(*) as total,
      SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) as running,
      SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed,
      SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed
    FROM sessions
  `);
  const sessionStats = sessionsStmt.get() as any;

  return {
    sessions: {
      total: sessionStats.total,
      running: sessionStats.running,
      completed: sessionStats.completed,
      failed: sessionStats.failed
    },
    tokens: getTokenSummary(sessionId),
    findings: getFindingSummary(sessionId),
    tools: getToolEffectivenessReport(sessionId),
    wstg: getWSTGCoverageReport(sessionId)
  };
}

export { db };