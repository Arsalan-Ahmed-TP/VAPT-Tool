// ---------------------------------------------------------------------------
// Scan management routes
// ---------------------------------------------------------------------------

import { Router, type Request, type Response, type NextFunction } from 'express';
import { z } from 'zod';
import * as scanService from '../services/scan-service.js';
import { AppError } from '../middleware/error-handler.js';

const router = Router();

const createScanSchema = z.object({
  target_id: z.string().uuid(),
  profile: z.enum(['safe', 'balanced', 'aggressive']).optional(),
  autofix_mode: z.enum(['off', 'recommend_only', 'approval_required']).optional(),
  allow_secret_verification: z.boolean().optional(),
  report_formats: z.array(z.enum(['html', 'json', 'markdown', 'csv', 'sarif'])).optional(),
  enabled_scanners: z.array(z.enum([
    'dast', 'sast', 'api_security', 'secret_scanning',
    'dependency_scanning', 'infra_scanning', 'container_scanning',
  ])).optional(),
});

router.post('/', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const data = createScanSchema.parse(req.body);
    const scan = await scanService.createScan(data as any, 'system');
    res.status(201).json(scan);
  } catch (err) {
    if (err instanceof z.ZodError) {
      next(new AppError(400, 'Validation failed', { errors: err.errors }));
    } else {
      next(err);
    }
  }
});

router.get('/', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const page = parseInt(req.query.page as string) || 1;
    const pageSize = parseInt(req.query.page_size as string) || 20;
    const scans = await scanService.listScans(page, pageSize);
    res.json({ data: scans, page, page_size: pageSize });
  } catch (err) {
    next(err);
  }
});

router.get('/:id', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const scan = await scanService.getScan(String(req.params.id));
    if (!scan) throw new AppError(404, 'Scan not found');
    res.json(scan);
  } catch (err) {
    next(err);
  }
});

router.get('/:id/status', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const status = await scanService.getScanStatus(String(req.params.id));
    if (!status) throw new AppError(404, 'Scan not found');
    res.json(status);
  } catch (err) {
    next(err);
  }
});

router.post('/:id/cancel', async (req: Request, res: Response, next: NextFunction) => {
  try {
    await scanService.cancelScan(String(req.params.id), 'system');
    res.json({ message: 'Scan cancelled' });
  } catch (err) {
    next(err);
  }
});

export default router;
