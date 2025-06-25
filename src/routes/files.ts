import { Router, Request, Response } from 'express';
import multer from 'multer';
import { requireAuth, optionalAuth, PERMISSIONS } from '@/middleware/auth';
import { FileService } from '@/services/file-service';
import { FileListQuerySchema, PermissionUpdateRequestSchema, UserPermission } from '@/types';
import { config } from '@/utils/config';
import { logger } from '@/utils/logger';

const router = Router();
const fileService = new FileService();

// Configure multer for file uploads
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: config.upload.maxFileSize,
    files: 1
  },
  fileFilter: (_req, file, cb) => {
    if (config.upload.allowedMimeTypes.length > 0 && 
        !config.upload.allowedMimeTypes.includes(file.mimetype)) {
      cb(new Error(`File type ${file.mimetype} is not allowed`));
      return;
    }
    cb(null, true);
  }
});

// Upload file
router.post('/upload', requireAuth, upload.single('file'), async (req: Request, res: Response): Promise<void> => {
  try {
    if (!req.file) {
      res.status(400).json({
        error: 'No file provided',
        message: 'Please select a file to upload'
      });
      return;
    }

    if (!req.user) {
      res.status(401).json({
        error: 'Authentication required',
        message: 'User authentication is required'
      });
      return;
    }

    // Parse additional metadata from request body
    let isPublic = false;
    let permissions: UserPermission[] = [];
    let tags: string[] = [];

    try {
      if (req.body.isPublic) {
        isPublic = JSON.parse(req.body.isPublic);
      }
      if (req.body.permissions) {
        permissions = JSON.parse(req.body.permissions);
      }
      if (req.body.tags) {
        tags = JSON.parse(req.body.tags);
      }
    } catch (parseError) {
      res.status(400).json({
        error: 'Invalid JSON in request body',
        message: 'Please check the format of isPublic, permissions, and tags fields'
      });
      return;
    }

    // Validate file size
    if (req.file.size > config.upload.maxFileSize) {
      res.status(413).json({
        error: 'File too large',
        message: `File size exceeds the maximum allowed size of ${config.upload.maxFileSize} bytes`
      });
      return;
    }

    // Validate MIME type if restrictions are configured
    if (config.upload.allowedMimeTypes.length > 0 && 
        !config.upload.allowedMimeTypes.includes('*') &&
        !config.upload.allowedMimeTypes.includes(req.file.mimetype)) {
      res.status(400).json({
        error: 'File type not allowed',
        message: `File type ${req.file.mimetype} is not allowed`
      });
      return;
    }

    const uploadRequest = {
      buffer: req.file.buffer,
      originalName: req.file.originalname,
      mimetype: req.file.mimetype,
      size: req.file.size,
      ownerId: req.user.userId,
      isPublic,
      permissions,
      tags
    };

    const result = await fileService.uploadFile(uploadRequest);

    logger.info('File uploaded successfully via API', {
      fileId: result._id?.toString(),
      filename: result.originalName,
      size: result.size,
      userId: req.user.userId,
      ip: req.ip
    });

    res.status(201).json({
      success: true,
      data: result,
      message: 'File uploaded successfully'
    });
  } catch (error) {
    logger.error('File upload failed via API', {
      error: error instanceof Error ? error.message : error,
      filename: req.file?.originalname,
      userId: req.user?.userId,
      ip: req.ip
    });

    res.status(500).json({
      error: 'Upload failed',
      message: 'An error occurred while uploading the file'
    });
  }
});

// List files
router.get('/', optionalAuth, async (req: Request, res: Response): Promise<void> => {
  try {
    // Validate query parameters
    const queryResult = FileListQuerySchema.safeParse(req.query);
    if (!queryResult.success) {
      res.status(400).json({
        error: 'Invalid query parameters',
        message: 'Please check your query parameters',
        details: queryResult.error.errors
      });
      return;
    }

    const result = await fileService.listFiles(queryResult.data, req.user?.userId);

    res.json({
      success: true,
      data: result,
      message: 'Files retrieved successfully'
    });
  } catch (error) {
    logger.error('Failed to list files via API', {
      error: error instanceof Error ? error.message : error,
      query: req.query,
      userId: req.user?.userId,
      ip: req.ip
    });

    res.status(500).json({
      error: 'Failed to retrieve files',
      message: 'An error occurred while retrieving files'
    });
  }
});

// Get file metadata
router.get('/:id', optionalAuth, async (req: Request, res: Response): Promise<void> => {
  try {
    const { id } = req.params;
    if (!id) {
      res.status(400).json({
        error: 'File ID required',
        message: 'File ID parameter is required'
      });
      return;
    }

    const file = await fileService.getFileMetadata(id, req.user?.userId);

    res.json({
      success: true,
      data: file,
      message: 'File metadata retrieved successfully'
    });
  } catch (error) {
    logger.error('Failed to get file metadata via API', {
      error: error instanceof Error ? error.message : error,
      fileId: req.params['id'],
      userId: req.user?.userId,
      ip: req.ip
    });

    if (error instanceof Error && error.message.includes('not found')) {
      res.status(404).json({
        error: 'File not found',
        message: 'The requested file does not exist'
      });
      return;
    }

    if (error instanceof Error && error.message.includes('Access denied')) {
      res.status(403).json({
        error: 'Access denied',
        message: 'You do not have permission to access this file'
      });
      return;
    }

    res.status(500).json({
      error: 'Failed to retrieve file metadata',
      message: 'An error occurred while retrieving file metadata'
    });
  }
});

// Download file
router.get('/:id/download', optionalAuth, async (req: Request, res: Response): Promise<void> => {
  try {
    const { id } = req.params;
    if (!id) {
      res.status(400).json({
        error: 'File ID required',
        message: 'File ID parameter is required'
      });
      return;
    }

    const result = await fileService.downloadFile(id, req.user?.userId);

    // Set appropriate headers
    res.setHeader('Content-Type', result.mimetype);
    res.setHeader('Content-Length', result.size);
    res.setHeader('Content-Disposition', `attachment; filename="${result.filename}"`);

    logger.info('File downloaded via API', {
      fileId: id,
      filename: result.filename,
      userId: req.user?.userId,
      ip: req.ip
    });

    res.send(result.buffer);
  } catch (error) {
    logger.error('Failed to download file via API', {
      error: error instanceof Error ? error.message : error,
      fileId: req.params['id'],
      userId: req.user?.userId,
      ip: req.ip
    });

    if (error instanceof Error && error.message.includes('not found')) {
      res.status(404).json({
        error: 'File not found',
        message: 'The requested file does not exist'
      });
      return;
    }

    if (error instanceof Error && error.message.includes('Access denied')) {
      res.status(403).json({
        error: 'Access denied',
        message: 'You do not have permission to download this file'
      });
      return;
    }

    res.status(500).json({
      error: 'Download failed',
      message: 'An error occurred while downloading the file'
    });
  }
});

// Get thumbnail
router.get('/:id/thumbnail/:size', optionalAuth, async (req: Request, res: Response): Promise<void> => {
  try {
    const { id, size } = req.params;
    if (!id || !size) {
      res.status(400).json({
        error: 'Parameters required',
        message: 'File ID and size parameters are required'
      });
      return;
    }

    const result = await fileService.getThumbnail(id, size, req.user?.userId);

    // Set appropriate headers
    res.setHeader('Content-Type', result.mimetype);
    res.setHeader('Content-Length', result.size);
    res.setHeader('Cache-Control', 'public, max-age=86400'); // Cache for 24 hours

    res.send(result.buffer);
  } catch (error) {
    logger.error('Failed to get thumbnail via API', {
      error: error instanceof Error ? error.message : error,
      fileId: req.params['id'],
      size: req.params['size'],
      userId: req.user?.userId,
      ip: req.ip
    });

    if (error instanceof Error && error.message.includes('not found')) {
      res.status(404).json({
        error: 'Thumbnail not found',
        message: 'The requested thumbnail does not exist'
      });
      return;
    }

    if (error instanceof Error && error.message.includes('Access denied')) {
      res.status(403).json({
        error: 'Access denied',
        message: 'You do not have permission to access this thumbnail'
      });
      return;
    }

    res.status(500).json({
      error: 'Failed to retrieve thumbnail',
      message: 'An error occurred while retrieving the thumbnail'
    });
  }
});

// Update file permissions
router.patch('/:id/permissions', requireAuth, async (req: Request, res: Response): Promise<void> => {
  try {
    const { id } = req.params;
    if (!id) {
      res.status(400).json({
        error: 'File ID required',
        message: 'File ID parameter is required'
      });
      return;
    }

    if (!req.user) {
      res.status(401).json({
        error: 'Authentication required',
        message: 'User authentication is required'
      });
      return;
    }

    // Validate request body
    const validationResult = PermissionUpdateRequestSchema.safeParse(req.body);
    if (!validationResult.success) {
      res.status(400).json({
        error: 'Invalid request body',
        message: 'Please check your request data',
        details: validationResult.error.errors
      });
      return;
    }

    const updatedFile = await fileService.updatePermissions(id, {
      permissions: validationResult.data.permissions || [],
      isPublic: validationResult.data.isPublic
    }, req.user.userId);

    logger.info('File permissions updated via API', {
      fileId: id,
      userId: req.user.userId,
      ip: req.ip
    });

    res.json({
      success: true,
      data: updatedFile,
      message: 'File permissions updated successfully'
    });
  } catch (error) {
    logger.error('Failed to update file permissions via API', {
      error: error instanceof Error ? error.message : error,
      fileId: req.params['id'],
      userId: req.user?.userId,
      ip: req.ip
    });

    if (error instanceof Error && error.message.includes('not found')) {
      res.status(404).json({
        error: 'File not found',
        message: 'The requested file does not exist'
      });
      return;
    }

    if (error instanceof Error && error.message.includes('Only file owner')) {
      res.status(403).json({
        error: 'Access denied',
        message: 'Only the file owner can update permissions'
      });
      return;
    }

    res.status(500).json({
      error: 'Failed to update permissions',
      message: 'An error occurred while updating file permissions'
    });
  }
});

// Delete file
router.delete('/:id', requireAuth, async (req: Request, res: Response): Promise<void> => {
  try {
    const { id } = req.params;
    if (!id) {
      res.status(400).json({
        error: 'File ID required',
        message: 'File ID parameter is required'
      });
      return;
    }

    if (!req.user) {
      res.status(401).json({
        error: 'Authentication required',
        message: 'User authentication is required'
      });
      return;
    }

    await fileService.deleteFile(id, req.user.userId);

    logger.info('File deleted via API', {
      fileId: id,
      userId: req.user.userId,
      ip: req.ip
    });

    res.json({
      success: true,
      message: 'File deleted successfully'
    });
  } catch (error) {
    logger.error('Failed to delete file via API', {
      error: error instanceof Error ? error.message : error,
      fileId: req.params['id'],
      userId: req.user?.userId,
      ip: req.ip
    });

    if (error instanceof Error && error.message.includes('not found')) {
      res.status(404).json({
        error: 'File not found',
        message: 'The requested file does not exist'
      });
      return;
    }

    if (error instanceof Error && error.message.includes('Access denied')) {
      res.status(403).json({
        error: 'Access denied',
        message: 'You do not have permission to delete this file'
      });
      return;
    }

    res.status(500).json({
      error: 'Failed to delete file',
      message: 'An error occurred while deleting the file'
    });
  }
});

// Generate secure URL
router.post('/:id/secure-url', requireAuth, async (req: Request, res: Response): Promise<void> => {
  try {
    const { id } = req.params;
    if (!id) {
      res.status(400).json({
        error: 'File ID required',
        message: 'File ID parameter is required'
      });
      return;
    }

    const { expiresIn } = req.body;

    if (!req.user) {
      res.status(401).json({
        error: 'Authentication required',
        message: 'User authentication is required'
      });
      return;
    }

    const secureUrl = await fileService.generateSecureUrl(
      id, 
      req.user.userId, 
      expiresIn || 3600
    );

    res.json({
      success: true,
      data: { secureUrl },
      message: 'Secure URL generated successfully'
    });
  } catch (error) {
    logger.error('Failed to generate secure URL via API', {
      error: error instanceof Error ? error.message : error,
      fileId: req.params['id'],
      userId: req.user?.userId,
      ip: req.ip
    });

    if (error instanceof Error && error.message.includes('not found')) {
      res.status(404).json({
        error: 'File not found',
        message: 'The requested file does not exist'
      });
      return;
    }

    if (error instanceof Error && error.message.includes('Access denied')) {
      res.status(403).json({
        error: 'Access denied',
        message: 'You do not have permission to generate a secure URL for this file'
      });
      return;
    }

    res.status(500).json({
      error: 'Failed to generate secure URL',
      message: 'An error occurred while generating the secure URL'
    });
  }
});

// Serve secure file
router.get('/secure/:id', async (req: Request, res: Response): Promise<void> => {
  try {
    const { id } = req.params;
    if (!id) {
      res.status(400).json({
        error: 'File ID required',
        message: 'File ID parameter is required'
      });
      return;
    }

    const { token } = req.query;

    if (!token || typeof token !== 'string') {
      res.status(400).json({
        error: 'Token required',
        message: 'A valid token is required to access this file'
      });
      return;
    }

    const result = await fileService.serveSecureFile(id, token);

    // Set appropriate headers
    res.setHeader('Content-Type', result.mimetype);
    res.setHeader('Content-Length', result.size);
    res.setHeader('Content-Disposition', `inline; filename="${result.filename}"`);

    res.send(result.buffer);
  } catch (error) {
    logger.error('Failed to serve secure file via API', {
      error: error instanceof Error ? error.message : error,
      fileId: req.params['id'],
      ip: req.ip
    });

    if (error instanceof Error && (error.message.includes('invalid') || error.message.includes('expired'))) {
      res.status(401).json({
        error: 'Invalid or expired token',
        message: 'The provided token is invalid or has expired'
      });
      return;
    }

    if (error instanceof Error && error.message.includes('not found')) {
      res.status(404).json({
        error: 'File not found',
        message: 'The requested file does not exist'
      });
      return;
    }

    res.status(500).json({
      error: 'Failed to serve file',
      message: 'An error occurred while serving the file'
    });
  }
});

// Get storage statistics (admin only)
router.get('/admin/stats', requireAuth, async (req: Request, res: Response): Promise<void> => {
  try {
    if (!req.user) {
      res.status(401).json({
        error: 'Authentication required',
        message: 'User authentication is required'
      });
      return;
    }

    // Check if user has admin permissions
    if (typeof req.user.permissions !== 'number' || (req.user.permissions & PERMISSIONS.ADMIN) !== PERMISSIONS.ADMIN) {
      res.status(403).json({
        error: 'Admin access required',
        message: 'You need admin permissions to access storage statistics'
      });
      return;
    }

    const stats = await fileService.getStorageStats();

    res.json({
      success: true,
      data: stats,
      message: 'Storage statistics retrieved successfully'
    });
  } catch (error) {
    logger.error('Failed to get storage statistics via API', {
      error: error instanceof Error ? error.message : error,
      userId: req.user?.userId,
      ip: req.ip
    });

    res.status(500).json({
      error: 'Failed to retrieve statistics',
      message: 'An error occurred while retrieving storage statistics'
    });
  }
});

export default router;
