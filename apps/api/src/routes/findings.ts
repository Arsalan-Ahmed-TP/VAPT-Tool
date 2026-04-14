// ---------------------------------------------------------------------------
// Findings query routes
// ---------------------------------------------------------------------------

import { Router, type Request, type Response, type NextFunction } from 'express';
import * as findingsService from '../services/findings-service.js';
import { AppError } from '../middleware/error-handler.js';

const router = Router();

router.get('/', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const query = {
      scan_id: req.query.scan_id as string,
      severity: req.query.severity ? (req.query.severity as string).split(',') as any[] : undefined,
      category: req.query.category ? (req.query.category as string).split(',') as any[] : undefined,
      autofixable: req.query.autofixable !== undefined ? req.query.autofixable === 'true' : undefined,
      search: req.query.search as string,
      sort_by: (req.query.sort_by as any) || 'priority_score',
      sort_order: (req.query.sort_order as any) || 'desc',
      page: parseInt(req.query.page as string) || 1,
      page_size: parseInt(req.query.page_size as string) || 50,
    };

    if (!query.scan_id) throw new AppError(400, 'scan_id query parameter is required');

    const result = await findingsService.getFindings(query);
    res.json(result);
  } catch (err) {
    next(err);
  }
});

router.get('/:id', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const finding = await findingsService.getFinding(String(req.params.id));
    if (!finding) throw new AppError(404, 'Finding not found');
    res.json(finding);
  } catch (err) {
    next(err);
  }
});

router.get('/correlated/:scanId', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const groups = await findingsService.getCorrelatedGroups(String(req.params.scanId));
    res.json({ data: groups });
  } catch (err) {
    next(err);
  }
});

export default router;
