// ---------------------------------------------------------------------------
// Health check and system status routes
// ---------------------------------------------------------------------------

import { Router, type Request, type Response } from 'express';
import { checkDatabaseConnection } from '../db/index.js';
import { checkRedisConnection } from '../queue/index.js';

const router = Router();

router.get('/health', async (_req: Request, res: Response) => {
  const [dbOk, redisOk] = await Promise.all([
    checkDatabaseConnection(),
    checkRedisConnection(),
  ]);

  const healthy = dbOk && redisOk;

  res.status(healthy ? 200 : 503).json({
    status: healthy ? 'healthy' : 'degraded',
    timestamp: new Date().toISOString(),
    services: {
      database: dbOk ? 'connected' : 'disconnected',
      redis: redisOk ? 'connected' : 'disconnected',
    },
  });
});

router.get('/ready', async (_req: Request, res: Response) => {
  const dbOk = await checkDatabaseConnection();
  res.status(dbOk ? 200 : 503).json({ ready: dbOk });
});

export default router;
