import multer from 'multer';
import { config } from '@/utils/config';
import { logger } from '@/utils/logger';

/**
 * Multer configuration for file uploads
 * Handles file filtering, size limits, and storage configuration
 */
export const createUploadMiddleware = () => {
  return multer({
    storage: multer.memoryStorage(),
    limits: {
      fileSize: config.upload.maxFileSize,
      files: 1
    },
    fileFilter: (_req, file, cb) => {
      logger.debug('Processing file filter', {
        filename: file.originalname,
        mimetype: file.mimetype,
        allowedTypes: config.upload.allowedMimeTypes
      });

      // Accept all MIME types by default
      // Only check restrictions if allowedMimeTypes is configured with specific types
      // and doesn't include the wildcard '*'
      if (config.upload.allowedMimeTypes.length > 0 && 
          !config.upload.allowedMimeTypes.includes('*') &&
          !config.upload.allowedMimeTypes.some(type => {
            // Allow wildcard subtypes like 'image/*'
            if (type.endsWith('/*')) {
              const mainType = type.split('/')[0];
              const fileMainType = file.mimetype.split('/')[0];
              return mainType === fileMainType;
            }
            return type === file.mimetype;
          })) {
        
        logger.warn('File type rejected by filter', {
          filename: file.originalname,
          mimetype: file.mimetype,
          allowedTypes: config.upload.allowedMimeTypes
        });
        
        cb(new Error(`File type ${file.mimetype} is not allowed`));
        return;
      }

      logger.debug('File type accepted by filter', {
        filename: file.originalname,
        mimetype: file.mimetype
      });
      
      cb(null, true);
    }
  });
};

/**
 * Single file upload middleware
 */
export const uploadSingle = createUploadMiddleware().single('file');

/**
 * Multiple files upload middleware (for future use)
 */
export const uploadMultiple = (maxCount: number = 10) => 
  createUploadMiddleware().array('files', maxCount);

/**
 * Extract and validate file metadata from request body
 */
export const extractFileMetadata = (body: any) => {
  const metadata = {
    isPublic: false,
    permissions: [],
    tags: []
  };

  try {
    if (body.isPublic) {
      metadata.isPublic = JSON.parse(body.isPublic);
    }
    if (body.permissions) {
      metadata.permissions = JSON.parse(body.permissions);
    }
    if (body.tags) {
      metadata.tags = JSON.parse(body.tags);
    }
  } catch (error) {
    logger.error('Failed to parse file metadata', {
      error: error instanceof Error ? error.message : error,
      body
    });
    throw new Error('Invalid JSON in request body metadata');
  }

  return metadata;
};
