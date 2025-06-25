import { Router } from 'express';
import { requireAuth, optionalAuth } from '@/middleware/auth';
import { uploadMultiple, uploadSingle } from '@/middleware/upload';
import fileController from '@/controllers/file-controller';

const router = Router();

/**
 * File routes
 * 
 * These routes handle file-related operations:
 * - File upload with metadata
 * - File listing and filtering
 * - File metadata retrieval
 * - File download and streaming
 * - Thumbnail generation and serving
 * - Permission management
 * - Secure URL generation
 * - Storage statistics (admin only)
 */

// Upload single file
router.post('/upload', requireAuth, uploadSingle, fileController.uploadFile.bind(fileController));

// Upload multiple files
router.post('/upload-multiple', requireAuth, uploadMultiple(10), fileController.uploadFiles.bind(fileController));

// List files
router.get('/', optionalAuth, fileController.listFiles.bind(fileController));

// Get file metadata
router.get('/:id', optionalAuth, fileController.getFileMetadata.bind(fileController));

// Get file metadata
router.get('/:id/metadata', optionalAuth, fileController.getFileMetadata.bind(fileController));
router.get('/:id/metadata/detailed', optionalAuth, fileController.getFileMetadataDetailed.bind(fileController));

// Download file
router.get('/:id/download', optionalAuth, fileController.downloadFile.bind(fileController));

// Get thumbnail
router.get('/:id/thumbnail/:size', optionalAuth, fileController.getThumbnail.bind(fileController));

// Update file permissions
router.patch('/:id/permissions', requireAuth, fileController.updatePermissions.bind(fileController));

// Delete file
router.delete('/:id', requireAuth, fileController.deleteFile.bind(fileController));

// Generate secure URL
router.post('/:id/secure-url', requireAuth, fileController.generateSecureUrl.bind(fileController));

// Serve secure file
router.get('/secure/:id', fileController.serveSecureFile.bind(fileController));

// Get storage statistics (admin only)
router.get('/admin/stats', requireAuth, fileController.getStorageStats.bind(fileController));

export default router;
