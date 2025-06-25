import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import { config } from '@/utils/config';
import { logger } from '@/utils/logger';
import { dbConnection } from '@/database/connection';
import { StorageFactory } from '@/storage/factory';
import { extractUserId } from '@/middleware/auth';
import filesRouter from '@/routes/files-refactored';
import authRouter from '@/routes/auth';

// Create Express app
const app = express();

function setupMiddleware(): void {
  // Security middleware
  app.use(helmet({
    crossOriginResourcePolicy: { policy: 'cross-origin' }
  }));

  // CORS configuration
  app.use(cors({
    origin: config.security.corsOrigin,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
  }));

  // Compression
  app.use(compression());

  // Body parsing
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true, limit: '10mb' }));

  // Request logging
  app.use((req: Request, _res: Response, next: NextFunction) => {
    logger.info(`${req.method} ${req.path}`, {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      contentLength: req.get('Content-Length')
    });
    next();
  });
}

function setupRoutes(): void {
  // API info endpoint
  app.get('/api/info', (_req: Request, res: Response) => {
    res.json({
      name: 'File Storage Service',
      version: '1.0.0',
      description: 'Secure, extensible file storage and serving backend',
      endpoints: {
        health: '/health',
        upload: 'POST /api/files/upload',
        'upload-multiple': 'POST /api/files/upload-miltiple',
        download: 'GET /api/files/:id/download',
        stream: 'GET /api/files/:id/stream',
        thumbnail: 'GET /api/files/:id/thumbnail/:size',
        list: 'GET /api/files',
        permissions: 'PATCH /api/files/:id/permissions'
      }
    });
  });

  // Auth routes
  app.use('/api/auth', authRouter);

  // File routes
  app.use('/api/files', extractUserId, filesRouter);

  // Health check endpoint
  app.get('/health', async (_req: Request, res: Response) => {
    try {
      const dbHealth = await dbConnection.healthCheck();
      const storageHealth = await StorageFactory.healthCheck();
      
      const isHealthy = dbHealth.connected && storageHealth.healthy;
      
      res.status(isHealthy ? 200 : 503).json({
        status: isHealthy ? 'healthy' : 'unhealthy',
        timestamp: new Date().toISOString(),
        services: {
          database: {
            status: dbHealth.connected ? 'healthy' : 'unhealthy',
            details: dbHealth
          },
          storage: {
            status: storageHealth.healthy ? 'healthy' : 'unhealthy',
            details: storageHealth
          }
        }
      });
    } catch (error) {
      logger.error('Health check failed', {
        error: error instanceof Error ? error.message : error
      });
      
      res.status(503).json({
        status: 'unhealthy',
        timestamp: new Date().toISOString(),
        error: 'Health check failed'
      });
    }
  });

  // 404 handler
  app.use('*', (req: Request, res: Response) => {
    res.status(404).json({
      error: 'Not Found',
      message: `Route ${req.method} ${req.originalUrl} not found`,
      timestamp: new Date().toISOString()
    });
  });
}

function setupErrorHandling(): void {
  // Global error handler
  app.use((error: any, req: Request, res: Response, _next: NextFunction) => {
    logger.error('Unhandled error', {
      error: error.message,
      stack: error.stack,
      url: req.url,
      method: req.method,
      ip: req.ip
    });

    // Don't leak error details in production
    const isDevelopment = config.nodeEnv === 'development';
    
    res.status(error.statusCode || 500).json({
      error: error.name || 'Internal Server Error',
      message: error.message || 'An unexpected error occurred',
      ...(isDevelopment && { stack: error.stack }),
      timestamp: new Date().toISOString()
    });
  });

  // Handle unhandled promise rejections
  process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled Promise Rejection', { reason, promise });
  });

  // Handle uncaught exceptions
  process.on('uncaughtException', (error) => {
    logger.error('Uncaught Exception', { error: error.message, stack: error.stack });
    process.exit(1);
  });
}

async function startServer(): Promise<void> {
  try {
    // Setup middleware, routes, and error handling
    setupMiddleware();
    setupRoutes();
    setupErrorHandling();

    // Connect to database
    await dbConnection.connect();

    // Start server
    app.listen(config.port, () => {
      logger.info(`🚀 File Storage Service started`, {
        port: config.port,
        environment: config.nodeEnv,
        storageProvider: config.storage.provider,
        mongoUri: config.mongodb.uri.replace(/\/\/[^@]+@/, '//***:***@')
      });
    });

  } catch (error) {
    logger.error('Failed to start server', { error: error instanceof Error ? error.message : error });
    process.exit(1);
  }
}

// Start the server
startServer().catch((error) => {
  logger.error('Server startup failed', { error });
  process.exit(1);
});

export { app };
export default app;
