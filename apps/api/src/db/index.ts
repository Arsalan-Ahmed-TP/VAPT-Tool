// ---------------------------------------------------------------------------
// Database connection — Drizzle ORM with PostgreSQL
// ---------------------------------------------------------------------------

import { drizzle } from 'drizzle-orm/node-postgres';
import pg from 'pg';
import { config } from '../config.js';
import { logger } from '../logger.js';
import * as schema from './schema.js';

const pool = new pg.Pool({
  connectionString: config.db.connectionString,
  ssl: config.db.ssl ? { rejectUnauthorized: false } : undefined,
  max: 20,
  idleTimeoutMillis: 30000,
});

pool.on('error', (err) => {
  logger.error('Unexpected database pool error', { error: err.message });
});

export const db = drizzle(pool, { schema });
export { schema };

export async function checkDatabaseConnection(): Promise<boolean> {
  try {
    const client = await pool.connect();
    await client.query('SELECT 1');
    client.release();
    return true;
  } catch (err) {
    logger.error('Database connection failed', { error: (err as Error).message });
    return false;
  }
}
