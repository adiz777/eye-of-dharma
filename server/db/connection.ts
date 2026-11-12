// server/db/connection.ts
// Database connection singleton with pragmas for better-sqlite3

import Database from 'better-sqlite3';
import path from 'node:path';
import fs from 'node:fs';

export interface DatabaseConfig {
  dbPath?: string;
  readonly?: boolean;
  verbose?: (message?: unknown, ...additionalArgs: unknown[]) => void;
}

let dbInstance: Database.Database | null = null;

export function getDatabase(config: DatabaseConfig = {}): Database.Database {
  if (dbInstance) {
    return dbInstance;
  }

  const dbPath = config.dbPath || process.env.EOD_DB_PATH || path.join(process.cwd(), 'data', 'eod.db');

  if (dbPath !== ':memory:') {
    const dir = path.dirname(dbPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  }

  const db = new Database(dbPath, {
    readonly: config.readonly ?? false,
    verbose: config.verbose
  });

  // Apply performance and integrity PRAGMAs
  db.pragma('foreign_keys = ON');
  db.pragma('recursive_triggers = ON');
  db.pragma('busy_timeout = 5000');
  db.pragma('temp_store = MEMORY');

  if (dbPath !== ':memory:') {
    try {
      db.pragma('journal_mode = WAL');
      db.pragma('synchronous = NORMAL');
    } catch {
      // Memory DB or unsupported filesystem
    }
  }

  dbInstance = db;
  return dbInstance;
}

export function closeDatabase(): void {
  if (dbInstance) {
    dbInstance.close();
    dbInstance = null;
  }
}

export function createInMemoryDatabase(): Database.Database {
  const db = new Database(':memory:');
  db.pragma('foreign_keys = ON');
  db.pragma('recursive_triggers = ON');
  db.pragma('busy_timeout = 5000');
  db.pragma('temp_store = MEMORY');
  return db;
}
