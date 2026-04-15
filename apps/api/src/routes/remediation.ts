// ---------------------------------------------------------------------------
// Remediation approval and application routes
// ---------------------------------------------------------------------------

import { Router, type Request, type Response, type NextFunction } from 'express';
import { z } from 'zod';
import * as remediationService from '../services/remediation-service.js';
import { AppError } from '../middleware/error-handler.js';

const router = Router();

const approveSchema = z.object({
  scan_id: z.string().uuid(),
  scope: z.enum(['all_safe', 'by_severity', 'by_category', 'by_finding', 'recommend_only', 'export_patch_only', 'create_branch_only']),
  proposal_ids: z.array(z.string().uuid()).optional(),
  approved_severities: z.array(z.enum(['critical', 'high', 'medium', 'low', 'informational'])).optional(),
  approved_categories: z.array(z.string()).optional(),
  notes: z.string().optional(),
});

const applySchema = z.object({
  approval_id: z.string().uuid(),
  create_branch: z.boolean().optional(),
  branch_name: z.string().optional(),
  dry_run: z.boolean().optional(),
});

// List proposals for a scan
router.get('/proposals/:scanId', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const proposals = await remediationService.getProposals(String(req.params.scanId));
    res.json({ data: proposals });
  } catch (err) {
    next(err);
  }
});

// Get single proposal
router.get('/proposals/detail/:id', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const proposal = await remediationService.getProposal(String(req.params.id));
    if (!proposal) throw new AppError(404, 'Proposal not found');
    res.json(proposal);
  } catch (err) {
    next(err);
  }
});

// Approve remediation
router.post('/approve', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const data = approveSchema.parse(req.body);
    const result = await remediationService.approveRemediation(data as any, 'system');
    res.status(201).json(result);
  } catch (err) {
    if (err instanceof z.ZodError) {
      next(new AppError(400, 'Validation failed', { errors: err.errors }));
    } else {
      next(err);
    }
  }
});

// Apply approved remediation
router.post('/apply', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const data = applySchema.parse(req.body);
    const result = await remediationService.applyRemediation(data as any, 'system');
    res.status(202).json(result);
  } catch (err) {
    if (err instanceof z.ZodError) {
      next(new AppError(400, 'Validation failed', { errors: err.errors }));
    } else {
      next(err);
    }
  }
});

// Export patch
router.get('/patch/:scanId', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const patch = await remediationService.exportPatch(String(req.params.scanId));
    res.json(patch);
  } catch (err) {
    next(err);
  }
});

export default router;
