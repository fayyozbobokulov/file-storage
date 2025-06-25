import dotenv from 'dotenv';
import { AppConfig } from '@/types';

// Load environment variables
dotenv.config();

function parseFileSize(size: string): number {
  // If it's already a number, return it directly
  if (/^\d+$/.test(size)) {
    return parseInt(size, 10);
  }
  
  const units = { B: 1, KB: 1024, MB: 1024 * 1024, GB: 1024 * 1024 * 1024 };
  const match = size.match(/^(\d+(?:\.\d+)?)\s*(B|KB|MB|GB)$/i);
  
  if (!match) {
    throw new Error(`Invalid file size format: ${size}. Use either a number (bytes) or format like "100MB"`);
  }
  
  const value = parseFloat(match[1]!);
  const unit = match[2]!.toUpperCase() as keyof typeof units;
  
  return Math.floor(value * units[unit]);
}

function parseMimeTypes(types: string): string[] {
  if (types === '*') return ['*'];
  return types.split(',').map(type => type.trim()).filter(Boolean);
}

function parseThumbnailSizes(sizes: string): number[] {
  return sizes.split(',').map(size => parseInt(size.trim(), 10)).filter(size => !isNaN(size));
}

export const config: AppConfig = {
  port: parseInt(process.env['PORT'] || '3000', 10),
  nodeEnv: process.env['NODE_ENV'] || 'development',
  
  mongodb: {
    uri: process.env['MONGODB_URI'] || 'mongodb://admin:password@localhost:27017/file-storage-service?authSource=admin',
    dbName: process.env['MONGODB_DB_NAME'] || 'file-storage-service'
  },
  
  jwt: {
    secret: process.env['JWT_SECRET'] || 'your-super-secret-jwt-key-change-this-in-production',
    expiresIn: process.env['JWT_EXPIRES_IN'] || '24h'
  },
  
  storage: {
    provider: (process.env['STORAGE_PROVIDER'] as 'local' | 's3') || 'local',
    local: {
      storagePath: process.env['LOCAL_STORAGE_PATH'] || './uploads',
      thumbnailsPath: process.env['LOCAL_THUMBNAILS_PATH'] || './uploads/thumbnails'
    },
    s3: {
      accessKeyId: process.env['AWS_ACCESS_KEY_ID'] || '',
      secretAccessKey: process.env['AWS_SECRET_ACCESS_KEY'] || '',
      region: process.env['AWS_REGION'] || 'us-east-1',
      bucketName: process.env['S3_BUCKET_NAME'] || '',
      thumbnailsBucket: process.env['S3_THUMBNAILS_BUCKET'] || ''
    }
  },
  
  upload: {
    maxFileSize: parseFileSize(process.env['MAX_FILE_SIZE'] || '100MB'),
    allowedMimeTypes: parseMimeTypes(process.env['ALLOWED_MIME_TYPES'] || '*')
  },
  
  thumbnails: {
    sizes: parseThumbnailSizes(process.env['THUMBNAIL_SIZES'] || '128,512'),
    quality: parseInt(process.env['THUMBNAIL_QUALITY'] || '80', 10),
    format: (process.env['THUMBNAIL_FORMAT'] as 'jpeg' | 'png' | 'webp') || 'jpeg'
  },
  
  security: {
    corsOrigin: process.env['CORS_ORIGIN'] || 'http://localhost:3000',
    rateLimitWindowMs: parseInt(process.env['RATE_LIMIT_WINDOW_MS'] || '900000', 10),
    rateLimitMaxRequests: parseInt(process.env['RATE_LIMIT_MAX_REQUESTS'] || '100', 10)
  },
  
  logging: {
    level: process.env['LOG_LEVEL'] || 'info',
    ...(process.env['LOG_FILE'] && { file: process.env['LOG_FILE'] })
  }
};

// Validation
if (config.storage.provider === 's3') {
  if (!config.storage.s3?.accessKeyId || !config.storage.s3?.secretAccessKey || !config.storage.s3?.bucketName) {
    throw new Error('S3 configuration is incomplete. Please provide AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and S3_BUCKET_NAME');
  }
}

if (!config.jwt.secret || config.jwt.secret === 'your-super-secret-jwt-key-change-this-in-production') {
  if (config.nodeEnv === 'production') {
    throw new Error('JWT_SECRET must be set in production environment');
  }
  console.warn('⚠️  Using default JWT secret. Please set JWT_SECRET environment variable for production.');
}
