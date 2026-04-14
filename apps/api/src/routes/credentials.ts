// ---------------------------------------------------------------------------
// Credential management routes
// ---------------------------------------------------------------------------

import { Router, type Request, type Response, type NextFunction } from 'express';
import { z } from 'zod';
import * as credentialService from '../services/credential-service.js';
import { AppError } from '../middleware/error-handler.js';

const router = Router();

const createCredentialSchema = z.object({
  name: z.string().min(1).max(255),
  type: z.enum(['git_pat', 'git_ssh', 'bearer_token', 'cookie_session', 'api_key', 'basic_auth', 'custom_header', 'oauth2']),
  value: z.string().min(1),
  config: z.record(z.string()).optional(),
});

router.post('/', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const data = createCredentialSchema.parse(req.body);
    const cred = await credentialService.createCredential(data as any, 'system');
    res.status(201).json(cred);
  } catch (err) {
    if (err instanceof z.ZodError) {
      next(new AppError(400, 'Validation failed', { errors: err.errors }));
    } else {
      next(err);
    }
  }
});

router.get('/', async (_req: Request, res: Response, next: NextFunction) => {
  try {
    const creds = await credentialService.listCredentials();
    res.json({ data: creds });
  } catch (err) {
    next(err);
  }
});

router.get('/:id', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const cred = await credentialService.getCredential(String(req.params.id));
    if (!cred) throw new AppError(404, 'Credential not found');
    res.json(cred);
  } catch (err) {
    next(err);
  }
});

router.delete('/:id', async (req: Request, res: Response, next: NextFunction) => {
  try {
    await credentialService.deleteCredential(String(req.params.id));
    res.status(204).end();
  } catch (err) {
    next(err);
  }
});

export default router;
