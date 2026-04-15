// ---------------------------------------------------------------------------
// Findings query service
// ---------------------------------------------------------------------------

import { eq, desc, asc, and, inArray, sql, ilike } from 'drizzle-orm';
import { db, schema } from '../db/index.js';
import type { FindingsQuery } from '@securescope/shared-types';

export async function getFindings(query: FindingsQuery) {
  const page = query.page || 1;
  const pageSize = query.page_size || 50;
  const offset = (page - 1) * pageSize;

  // Build conditions dynamically
  const conditions = [eq(schema.normalizedFindings.scan_id, query.scan_id)];

  if (query.severity?.length) {
    conditions.push(inArray(schema.normalizedFindings.severity, query.severity));
  }
  if (query.category?.length) {
    conditions.push(inArray(schema.normalizedFindings.category, query.category));
  }
  if (query.autofixable !== undefined) {
    conditions.push(eq(schema.normalizedFindings.autofixable, query.autofixable));
  }
  if (query.search) {
    conditions.push(ilike(schema.normalizedFindings.title, `%${query.search}%`));
  }

  const where = and(...conditions);

  // Sort
  let orderBy;
  const direction = query.sort_order === 'asc' ? asc : desc;
  switch (query.sort_by) {
    case 'severity':
      orderBy = direction(schema.normalizedFindings.severity);
      break;
    case 'discovered_at':
      orderBy = direction(schema.normalizedFindings.discovered_at);
      break;
    default:
      orderBy = desc(schema.normalizedFindings.priority_score);
  }

  const [findings, countResult] = await Promise.all([
    db.select()
      .from(schema.normalizedFindings)
      .where(where)
      .orderBy(orderBy)
      .limit(pageSize)
      .offset(offset),
    db.select({ count: sql<number>`count(*)` })
      .from(schema.normalizedFindings)
      .where(where),
  ]);

  const total = Number(countResult[0]?.count ?? 0);

  return {
    data: findings,
    total,
    page,
    page_size: pageSize,
    total_pages: Math.ceil(total / pageSize),
  };
}

export async function getFinding(findingId: string) {
  const [finding] = await db.select()
    .from(schema.normalizedFindings)
    .where(eq(schema.normalizedFindings.finding_id, findingId));
  return finding || null;
}

export async function getCorrelatedGroups(scanId: string) {
  return db.select()
    .from(schema.correlatedGroups)
    .where(eq(schema.correlatedGroups.scan_id, scanId));
}
