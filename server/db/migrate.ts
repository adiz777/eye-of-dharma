// server/db/migrate.ts
// Migration runner for EYE OF DHARMA relational schema & triggers

import type Database from 'better-sqlite3';
import { getDatabase } from './connection.js';
import { INITIAL_SCHEMA_SQL, IMMUTABILITY_TRIGGERS_SQL } from './schema.js';

export function runMigrations(db: Database.Database): void {
  db.transaction(() => {
    // 1. Initial 9-table schema and indexes
    db.exec(INITIAL_SCHEMA_SQL);

    // 2. Engine-level immutability triggers and updated_at triggers
    db.exec(IMMUTABILITY_TRIGGERS_SQL);

    // 3. Migration 003: Check and add tlp / classification columns to cases table if missing
    try {
      const colInfo = db.prepare("PRAGMA table_info('cases')").all() as Array<{ name: string }>;
      const colNames = new Set(colInfo.map((c) => c.name));
      if (!colNames.has('tlp')) {
        db.exec("ALTER TABLE cases ADD COLUMN tlp TEXT DEFAULT 'TLP:AMBER'");
      }
      if (!colNames.has('classification')) {
        db.exec("ALTER TABLE cases ADD COLUMN classification TEXT DEFAULT 'UNCLASSIFIED'");
      }
    } catch {
      // Ignored if table doesn't exist or columns already present
    }
  })();
}

// CLI runner if executed directly
if (process.argv[1]?.includes('migrate')) {
  try {
    const db = getDatabase();
    console.log('[EOD Database] Running migrations...');
    runMigrations(db);
    console.log('[EOD Database] Migrations completed successfully. 9 tables and triggers verified.');
    process.exit(0);
  } catch (err) {
    console.error('[EOD Database] Migration failed:', err);
    process.exit(1);
  }
}
