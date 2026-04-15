// ---------------------------------------------------------------------------
// SecureScope API — Express server entry point
// ---------------------------------------------------------------------------

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import rateLimit from 'express-rate-limit';
import { config } from './config.js';
import { logger } from './logger.js';
import { errorHandler } from './middleware/error-handler.js';

// Routes
import healthRoutes from './routes/health.js';
import targetRoutes from './routes/targets.js';
import credentialRoutes from './routes/credentials.js';
import scanRoutes from './routes/scans.js';
import findingRoutes from './routes/findings.js';
import remediationRoutes from './routes/remediation.js';
import reportRoutes from './routes/reports.js';

const app = express();

// ---------------------------------------------------------------------------
// Security middleware
// ---------------------------------------------------------------------------
app.use(helmet());
app.use(cors({
  origin: config.security.corsOrigins,
  credentials: true,
}));
app.use(compression());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting
app.use(rateLimit({
  windowMs: config.security.rateLimitWindowMs,
  max: config.security.rateLimitMax,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'TooManyRequests', message: 'Rate limit exceeded' },
}));

// Request logging
app.use((req, _res, next) => {
  logger.info(`${req.method} ${req.path}`, {
    query: req.query,
    ip: req.ip,
  });
  next();
});

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------
app.use('/', healthRoutes);
app.use('/api/v1/targets', targetRoutes);
app.use('/api/v1/credentials', credentialRoutes);
app.use('/api/v1/scans', scanRoutes);
app.use('/api/v1/findings', findingRoutes);
app.use('/api/v1/remediation', remediationRoutes);
app.use('/api/v1/reports', reportRoutes);

// 404 handler
app.use((_req, res) => {
  res.status(404).json({ error: 'NotFound', message: 'Route not found' });
});

// Global error handler
app.use(errorHandler);

// ---------------------------------------------------------------------------
// Start server
// ---------------------------------------------------------------------------
app.listen(config.port, () => {
  logger.info(`SecureScope API running on port ${config.port}`, {
    env: config.env,
    cors_origins: config.security.corsOrigins,
  });
});

export default app;
