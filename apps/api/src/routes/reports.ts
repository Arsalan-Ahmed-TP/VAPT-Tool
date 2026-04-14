// ---------------------------------------------------------------------------
// Report generation and download routes
// ---------------------------------------------------------------------------

import { Router, type Request, type Response, type NextFunction } from 'express';
import { z } from 'zod';
import { eq } from 'drizzle-orm';
import { db, schema } from '../db/index.js';
import { reportQueue } from '../queue/index.js';
import { AppError } from '../middleware/error-handler.js';

const router = Router();

const generateReportSchema = z.object({
  scan_id: z.string().uuid(),
  formats: z.array(z.enum(['html', 'json', 'markdown', 'csv', 'sarif'])),
  report_types: z.array(z.enum(['executive', 'technical', 'remediation_plan', 'findings', 'validation', 'compliance'])),
});

// Generate reports
router.post('/generate', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const data = generateReportSchema.parse(req.body);

    await reportQueue.add('generate-reports', {
      scan_id: data.scan_id,
      formats: data.formats,
      report_types: data.report_types,
    }, {
      jobId: `report-${data.scan_id}-${Date.now()}`,
    });

    res.status(202).json({ message: 'Report generation queued', scan_id: data.scan_id });
  } catch (err) {
    if (err instanceof z.ZodError) {
      next(new AppError(400, 'Validation failed', { errors: err.errors }));
    } else {
      next(err);
    }
  }
});

// List reports for a scan
router.get('/:scanId', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const reports = await db.select()
      .from(schema.reportArtifacts)
      .where(eq(schema.reportArtifacts.scan_id, req.params.scanId));
    res.json({ data: reports });
  } catch (err) {
    next(err);
  }
});

// Download a specific report
router.get('/download/:id', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const [report] = await db.select()
      .from(schema.reportArtifacts)
      .where(eq(schema.reportArtifacts.id, req.params.id));

    if (!report) throw new AppError(404, 'Report not found');

    // In production, this would stream from S3 or local storage
    res.json({
      message: 'Download URL would be provided here',
      report_id: report.id,
      storage_path: report.storage_path,
      format: report.format,
    });
  } catch (err) {
    next(err);
  }
});

export default router;
