// ---------------------------------------------------------------------------
// Global error handler middleware
// ---------------------------------------------------------------------------

import type { Request, Response, NextFunction } from 'express';
import { logger } from '../logger.js';

export class AppError extends Error {
  constructor(
    public statusCode: number,
    message: string,
    public details?: Record<string, unknown>,
  ) {
    super(message);
    this.name = 'AppError';
  }
}

export function errorHandler(err: Error, req: Request, res: Response, _next: NextFunction): void {
  const requestId = req.headers['x-request-id'] || 'unknown';

  if (err instanceof AppError) {
    logger.warn('Application error', {
      statusCode: err.statusCode,
      message: err.message,
      path: req.path,
      requestId,
    });
    res.status(err.statusCode).json({
      error: err.name,
      message: err.message,
      details: err.details,
      request_id: requestId,
    });
    return;
  }

  // Unexpected error — log full stack but return generic message
  logger.error('Unhandled error', {
    error: err.message,
    stack: err.stack,
    path: req.path,
    requestId,
  });

  res.status(500).json({
    error: 'InternalServerError',
    message: 'An unexpected error occurred',
    request_id: requestId,
  });
}
