// ---------------------------------------------------------------------------
// Target management routes
// ---------------------------------------------------------------------------

import { Router, type Request, type Response, type NextFunction } from 'express';
import { z } from 'zod';
import * as targetService from '../services/target-service.js';
import { AppError } from '../middleware/error-handler.js';

const router = Router();

const createTargetSchema = z.object({
  name: z.string().min(1).max(255),
  source_type: z.enum(['git_repository', 'uploaded_archive', 'live_url', 'docker_image', 'kubernetes_manifest', 'terraform_directory']),
  location: z.string().min(1),
  ref: z.string().optional(),
  environment: z.enum(['development', 'qa', 'staging', 'production']).default('development'),
  credential_id: z.string().uuid().optional(),
  exclusions: z.array(z.string()).optional(),
  authorization_confirmed: z.boolean(),
  metadata: z.record(z.unknown()).optional(),
});

router.post('/', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const data = createTargetSchema.parse(req.body);
    const target = await targetService.createTarget(data as any, 'system');
    res.status(201).json(target);
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
    const targets = await targetService.listTargets(page, pageSize);
    res.json({ data: targets, page, page_size: pageSize });
  } catch (err) {
    next(err);
  }
});

router.get('/:id', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const target = await targetService.getTarget(String(req.params.id));
    if (!target) throw new AppError(404, 'Target not found');
    res.json(target);
  } catch (err) {
    next(err);
  }
});

export default router;
