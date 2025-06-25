import { Request, Response } from 'express';
import { FileService } from '@/services/file-service';
import { MetadataProcessor } from '@/services/metadata-processor';
import { CompressionService, CompressionType } from '@/services/compression-service';
import { FileListQuerySchema, FileNotFoundError, PermissionUpdateRequestSchema } from '@/types';
import { config } from '@/utils/config';
import { logger } from '@/utils/logger';
import { extractFileMetadata } from '@/middleware/upload';
import { PERMISSIONS } from '@/middleware/auth';

export class FileController {
  private fileService: FileService;
  private metadataProcessor: MetadataProcessor;
  private compressionService: CompressionService;

  constructor() {
    this.fileService = new FileService();
    this.metadataProcessor = new MetadataProcessor();
    this.compressionService = new CompressionService();
  }

  /**
   * Handle file upload
   */
  async uploadFile(req: Request, res: Response): Promise<void> {
    logger.info('File upload request received', {
      userId: req.user?.userId,
      ip: req.ip,
      contentType: req.headers['content-type'],
      fileReceived: !!req.file
    });

    try {
      // Check if file exists in request
      if (!req.file) {
        logger.warn('No file provided in upload request', {
          userId: req.user?.userId,
          ip: req.ip
        });
        res.status(400).json({
          error: 'No file provided',
          message: 'Please select a file to upload'
        });
        return;
      }

      logger.info('File received in upload request', {
        filename: req.file.originalname,
        mimetype: req.file.mimetype,
        size: req.file.size,
        userId: req.user?.userId
      });

      // Check authentication
      if (!req.user) {
        logger.warn('Unauthenticated upload attempt', {
          ip: req.ip,
          filename: req.file.originalname
        });
        res.status(401).json({
          error: 'Authentication required',
          message: 'User authentication is required'
        });
        return;
      }

      logger.info('Processing metadata from request body', {
        hasIsPublic: !!req.body.isPublic,
        hasPermissions: !!req.body.permissions,
        hasTags: !!req.body.tags,
        userId: req.user.userId
      });

      // Extract and validate metadata
      let metadata;
      try {
        metadata = extractFileMetadata(req.body);
      } catch (parseError) {
        logger.error('Failed to parse JSON metadata', {
          error: parseError instanceof Error ? parseError.message : parseError,
          userId: req.user.userId,
          ip: req.ip
        });
        res.status(400).json({
          error: 'Invalid JSON in request body',
          message: 'Please check the format of isPublic, permissions, and tags fields'
        });
        return;
      }

      // Validate file size
      logger.info('Validating file size', {
        fileSize: req.file.size,
        maxAllowedSize: config.upload.maxFileSize,
        filename: req.file.originalname
      });

      if (req.file.size > config.upload.maxFileSize) {
        logger.warn('File size exceeds limit', {
          fileSize: req.file.size,
          maxAllowedSize: config.upload.maxFileSize,
          filename: req.file.originalname,
          userId: req.user.userId
        });
        res.status(413).json({
          error: 'File too large',
          message: `File size exceeds the maximum allowed size of ${config.upload.maxFileSize} bytes`
        });
        return;
      }

      const uploadRequest = {
        buffer: req.file.buffer,
        originalName: req.file.originalname,
        mimetype: req.file.mimetype,
        size: req.file.size,
        ownerId: req.user.userId,
        isPublic: metadata.isPublic,
        permissions: metadata.permissions,
        tags: metadata.tags
      };

      logger.info('Preparing to upload file to storage', {
        filename: req.file.originalname,
        mimetype: req.file.mimetype,
        size: req.file.size,
        userId: req.user.userId,
        storageProvider: config.storage.provider
      });

      const result = await this.fileService.uploadFile(uploadRequest);

      logger.info('File uploaded successfully to storage', {
        fileId: result._id?.toString(),
        filename: result.originalName,
        size: result.size,
        storageKey: result.storageKey,
        userId: req.user.userId,
        storageProvider: config.storage.provider,
        hasMetadata: !!result.extractedMetadata,
        hasExif: !!result.extractedMetadata?.exif,
        hasGps: !!result.extractedMetadata?.gps,
        hasDimensions: !!result.extractedMetadata?.dimensions
      });

      res.status(201).json({
        success: true,
        data: {
          ...result,
          // Include metadata summary in response
          metadataSummary: result.extractedMetadata ? {
            hasExif: !!result.extractedMetadata.exif,
            hasGps: !!result.extractedMetadata.gps,
            hasDimensions: !!result.extractedMetadata.dimensions,
            fileType: result.extractedMetadata.fileType,
            dimensions: result.extractedMetadata.dimensions,
            gpsLocation: result.extractedMetadata.gps ? {
              latitude: result.extractedMetadata.gps.latitude,
              longitude: result.extractedMetadata.gps.longitude,
              altitude: result.extractedMetadata.gps.altitude
            } : undefined
          } : undefined
        },
        message: 'File uploaded successfully with comprehensive metadata extraction'
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
  }

  /**
   * Handle multiple files upload
   */
  async uploadFiles(req: Request, res: Response): Promise<void> {
    logger.info('Multiple file upload request received', {
      userId: req.user?.userId,
      ip: req.ip,
      contentType: req.headers['content-type'],
      filesReceived: req.files ? Array.isArray(req.files) ? req.files.length : 0 : 0
    });

    try {
      // Check if files exist in request
      if (!req.files || !Array.isArray(req.files) || req.files.length === 0) {
        logger.warn('No files provided in upload request', {
          userId: req.user?.userId,
          ip: req.ip
        });
        res.status(400).json({
          error: 'No files provided',
          message: 'Please select at least one file to upload'
        });
        return;
      }

      // Check authentication
      if (!req.user) {
        logger.warn('Unauthenticated upload attempt', {
          ip: req.ip,
          filesCount: req.files.length
        });
        res.status(401).json({
          error: 'Authentication required',
          message: 'User authentication is required'
        });
        return;
      }

      logger.info('Processing metadata from request body', {
        hasIsPublic: !!req.body.isPublic,
        hasPermissions: !!req.body.permissions,
        hasTags: !!req.body.tags,
        userId: req.user.userId
      });

      // Extract and validate metadata
      let metadata;
      try {
        metadata = extractFileMetadata(req.body);
      } catch (parseError) {
        logger.error('Failed to parse JSON metadata', {
          error: parseError instanceof Error ? parseError.message : parseError,
          userId: req.user.userId,
          ip: req.ip
        });
        res.status(400).json({
          error: 'Invalid JSON in request body',
          message: 'Please check the format of isPublic, permissions, and tags fields'
        });
        return;
      }

      // Process each file in parallel
      const uploadPromises = req.files.map(async (file) => {
        // Validate file size
        if (file.size > config.upload.maxFileSize) {
          logger.warn('File size exceeds limit', {
            fileSize: file.size,
            maxAllowedSize: config.upload.maxFileSize,
            filename: file.originalname,
            userId: req.user?.userId
          });
          return {
            success: false,
            filename: file.originalname,
            error: `File size exceeds the maximum allowed size of ${config.upload.maxFileSize} bytes`
          };
        }

        try {
          const uploadRequest = {
            buffer: file.buffer,
            originalName: file.originalname,
            mimetype: file.mimetype,
            size: file.size,
            ownerId: req.user!.userId,
            isPublic: metadata.isPublic,
            permissions: metadata.permissions,
            tags: metadata.tags
          };

          logger.info('Preparing to upload file to storage', {
            filename: file.originalname,
            mimetype: file.mimetype,
            size: file.size,
            userId: req.user?.userId,
            storageProvider: config.storage.provider
          });

          const result = await this.fileService.uploadFile(uploadRequest);

          logger.info('File uploaded successfully to storage', {
            fileId: result._id?.toString(),
            filename: result.originalName,
            size: result.size,
            storageKey: result.storageKey,
            userId: req.user?.userId,
            storageProvider: config.storage.provider,
            hasMetadata: !!result.extractedMetadata,
            hasExif: !!result.extractedMetadata?.exif,
            hasGps: !!result.extractedMetadata?.gps,
            hasDimensions: !!result.extractedMetadata?.dimensions
          });

          return {
            success: true,
            data: {
              ...result,
              // Include metadata summary in response
              metadataSummary: result.extractedMetadata ? {
                hasExif: !!result.extractedMetadata.exif,
                hasGps: !!result.extractedMetadata.gps,
                hasDimensions: !!result.extractedMetadata.dimensions,
                fileType: result.extractedMetadata.fileType,
                dimensions: result.extractedMetadata.dimensions,
                gpsLocation: result.extractedMetadata.gps ? {
                  latitude: result.extractedMetadata.gps.latitude,
                  longitude: result.extractedMetadata.gps.longitude,
                  altitude: result.extractedMetadata.gps.altitude
                } : undefined
              } : undefined
            }
          };
        } catch (error) {
          logger.error('File upload failed', {
            error: error instanceof Error ? error.message : error,
            filename: file.originalname,
            userId: req.user?.userId
          });

          return {
            success: false,
            filename: file.originalname,
            error: error instanceof Error ? error.message : 'An unknown error occurred'
          };
        }
      });

      const results = await Promise.all(uploadPromises);
      
      // Count successful and failed uploads
      const successCount = results.filter(r => r.success).length;
      const failureCount = results.filter(r => !r.success).length;
      
      logger.info('Multiple file upload completed', {
        totalFiles: results.length,
        successCount,
        failureCount,
        userId: req.user.userId
      });

      res.status(201).json({
        success: true,
        message: `${successCount} files uploaded successfully${failureCount > 0 ? `, ${failureCount} files failed` : ''}`,
        results
      });
    } catch (error) {
      logger.error('Multiple file upload failed via API', {
        error: error instanceof Error ? error.message : error,
        userId: req.user?.userId,
        ip: req.ip
      });

      res.status(500).json({
        error: 'Upload failed',
        message: 'An error occurred while uploading the files'
      });
    }
  }

  /**
   * List files with optional filtering
   */
  async listFiles(req: Request, res: Response): Promise<void> {
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

      const result = await this.fileService.listFiles(queryResult.data, req.user?.userId);
      
      // Generate URLs for each file
      const baseUrl = `${req.protocol}://${req.get('host')}`;
      const filesWithUrls = result.files.map(file => {
        // Create URLs for the original file and thumbnails
        const fileUrls = {
          ...file,
          originalUrl: `${baseUrl}/api/files/${file._id}/download`,
          streamUrl: `${baseUrl}/api/files/${file._id}/stream`,
          thumbnails: {
            small: `${baseUrl}/api/files/${file._id}/thumbnail/small`,
            medium: `${baseUrl}/api/files/${file._id}/thumbnail/medium`
          }
        };
        
        return fileUrls;
      });

      res.json({
        success: true,
        data: {
          ...result,
          files: filesWithUrls
        },
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
  }

  /**
   * Get file metadata by ID
   */
  async getFileMetadata(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      if (!id) {
        res.status(400).json({
          error: 'File ID required',
          message: 'File ID parameter is required'
        });
        return;
      }

      const file = await this.fileService.getFileMetadata(id, req.user?.userId);

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
  }

  /**
   * Download a file with optional metadata processing
   * Query parameters:
   * - preserveMetadata: boolean (default: false) - preserve all metadata
   * - preserveExif: boolean (default: false) - preserve EXIF data only
   * - preserveIcc: boolean (default: false) - preserve color profile
   * - preserveOrientation: boolean (default: true) - preserve image orientation
   * - stripGps: boolean (default: true) - strip GPS data even when preserving metadata
   * - compress: boolean (default: false) - compress the file
   */
  async downloadFile(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      if (!id) {
        res.status(400).json({
          error: 'File ID required',
          message: 'File ID parameter is required'
        });
        return;
      }

      // Parse metadata processing options from query parameters
      const metadataOptions = this.metadataProcessor.parseMetadataOptions(req.query);

      logger.info('File download requested', {
        fileId: id,
        userId: req.user?.userId,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        metadataOptions
      });

      // Get file metadata first to check size
      const metadata = await this.fileService.getFileMetadata(id, req.user?.userId);
      const fileSizeThreshold = 1024 * 1024; // 1MB

      if (metadata.size > fileSizeThreshold) {
        // Use streaming for large files
        logger.info('Using streaming download for large file', {
          fileId: id,
          fileSize: metadata.size,
          filename: metadata.originalName
        });

        const streamResult = await this.fileService.downloadFileStream(id, req.user?.userId);
        
        // Set headers
        res.setHeader('Content-Type', streamResult.mimetype);
        res.setHeader('Content-Length', streamResult.size.toString());
        res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(streamResult.filename)}`);
        
        // Add metadata processing info to headers
        res.setHeader('X-Metadata-Processing', this.metadataProcessor.getMetadataSummary(metadataOptions));

        // Handle stream errors
        streamResult.stream.on('error', (error) => {
          logger.error('Stream error during file download', {
            fileId: id,
            error: error.message,
            userId: req.user?.userId
          });
          
          if (!res.headersSent) {
            res.status(500).json({
              error: 'Download failed',
              message: 'An error occurred while streaming the file'
            });
          }
        });

        // For large files, we'll note that metadata processing is limited for streaming
        if (metadataOptions.preserveMetadata === false && streamResult.mimetype.startsWith('image/')) {
          logger.warn('Metadata stripping not available for streaming downloads', {
            fileId: id,
            fileSize: metadata.size
          });
          res.setHeader('X-Metadata-Warning', 'Metadata processing not available for large file streaming');
        }

        // Pipe the stream to response
        streamResult.stream.pipe(res);
      } else {
        // Use buffer download for smaller files with metadata processing
        logger.info('Using buffer download for small file', {
          fileId: id,
          fileSize: metadata.size,
          filename: metadata.originalName
        });

        const downloadResult = await this.fileService.downloadFile(id, req.user?.userId);
        
        // Process metadata based on options (only for images)
        let processedBuffer = downloadResult.buffer;
        if (downloadResult.mimetype.startsWith('image/')) {
          processedBuffer = await this.metadataProcessor.processImageBuffer(
            downloadResult.buffer,
            downloadResult.mimetype,
            metadataOptions
          );
        }

        // Compress the file if requested
        if (req.query['compress'] === 'true') {
          const compressionType = req.query['compressionType'] as CompressionType;
          const compressionResult = await this.compressionService.compressBuffer(processedBuffer, metadata.mimetype, { type: compressionType });
          processedBuffer = compressionResult.buffer;
        }

        // Set headers
        res.setHeader('Content-Type', downloadResult.mimetype);
        res.setHeader('Content-Length', processedBuffer.length.toString());
        res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(downloadResult.filename)}`);
        res.setHeader('X-Metadata-Processing', this.metadataProcessor.getMetadataSummary(metadataOptions));

        logger.info('File download completed', {
          fileId: id,
          filename: downloadResult.filename,
          originalSize: downloadResult.buffer.length,
          processedSize: processedBuffer.length,
          metadataProcessed: downloadResult.mimetype.startsWith('image/'),
          userId: req.user?.userId
        });

        res.send(processedBuffer);
      }
    } catch (error) {
      logger.error('Failed to download file', {
        error: error instanceof Error ? error.message : error,
        fileId: req.params['id'],
        userId: req.user?.userId,
        ip: req.ip
      });

      if (error instanceof FileNotFoundError) {
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
  }

  /**
   * Get thumbnail for a file
   */
  async getThumbnail(req: Request, res: Response): Promise<void> {
    try {
      const { id, size } = req.params;
      if (!id || !size) {
        res.status(400).json({
          error: 'Parameters required',
          message: 'File ID and size parameters are required'
        });
        return;
      }

      // Map common size names to actual numeric sizes if needed
      let thumbnailSize = size;
      const sizeMapping: Record<string, string> = {
        'small': '128',
        'medium': '512'
      };

      // If a named size was provided, map it to the corresponding numeric size
      if (sizeMapping[size]) {
        thumbnailSize = sizeMapping[size];
      }

      try {
        const result = await this.fileService.getThumbnail(id, thumbnailSize, req.user?.userId || undefined);

        // Set appropriate headers for browser display
        res.setHeader('Content-Type', result.mimetype);
        res.setHeader('Content-Length', result.size);
        res.setHeader('Cache-Control', 'public, max-age=86400'); // Cache for 24 hours
        res.setHeader('Content-Disposition', 'inline'); // Display in browser

        // Send the buffer directly to the client
        res.send(result.buffer);
        return;
      } catch (error) {
        // If the requested size doesn't exist, try to find any available thumbnail
        if (error instanceof Error && error.message.includes('Thumbnail not found')) {
          // Try to get the file metadata to see what thumbnails are available
          const file = await this.fileService.getFileMetadata(id, req.user?.userId);
          
          if (file && file.thumbnails && Object.keys(file.thumbnails).length > 0) {
            // Use the first available thumbnail
            const availableSize = Object.keys(file.thumbnails)[0];
            logger.info(`Requested thumbnail size ${size} not found, using ${availableSize} instead`, {
              fileId: id,
              requestedSize: size,
              availableSize
            });
            
            const fallbackResult = await this.fileService.getThumbnail(id, availableSize!, req.user?.userId);
            
            // Set headers and send the fallback thumbnail
            res.setHeader('Content-Type', fallbackResult.mimetype);
            res.setHeader('Content-Length', fallbackResult.size);
            res.setHeader('Cache-Control', 'public, max-age=86400');
            res.setHeader('Content-Disposition', 'inline');
            
            res.send(fallbackResult.buffer);
            return;
          }
        }
        
        // If we reach here, rethrow the error to be caught by the outer catch block
        throw error;
      }
    } catch (error) {
      logger.error('Failed to get thumbnail via API', {
        error: error instanceof Error ? error.message : error,
        fileId: req.params['id'],
        size: req.params['size'],
        userId: req.user?.userId,
        ip: req.ip
      });

      if (error instanceof Error && (error.message.includes('not found') || error.message.includes('Thumbnail not found'))) {
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
  }

  /**
   * Update file permissions
   */
  async updatePermissions(req: Request, res: Response): Promise<void> {
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

      const updatedFile = await this.fileService.updatePermissions(id, {
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
  }

  /**
   * Delete file by ID
   */
  async deleteFile(req: Request, res: Response): Promise<void> {
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

      await this.fileService.deleteFile(id, req.user.userId);

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
  }

  /**
   * Generate secure URL for file access
   */
  async generateSecureUrl(req: Request, res: Response): Promise<void> {
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

      const secureUrl = await this.fileService.generateSecureUrl(
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
  }

  /**
   * Serve a file via secure URL with optional metadata processing
   * Query parameters:
   * - token: string (required) - secure access token
   * - preserveMetadata: boolean (default: false) - preserve all metadata
   * - preserveExif: boolean (default: false) - preserve EXIF data only
   * - preserveIcc: boolean (default: false) - preserve color profile
   * - preserveOrientation: boolean (default: true) - preserve image orientation
   * - stripGps: boolean (default: true) - strip GPS data even when preserving metadata
   */
  async serveSecureFile(req: Request, res: Response): Promise<void> {
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

      // Parse metadata processing options from query parameters
      const metadataOptions = this.metadataProcessor.parseMetadataOptions(req.query);

      logger.info('Secure file access requested', {
        fileId: id,
        token: token.substring(0, 8) + '...',
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        metadataOptions
      });

      const result = await this.fileService.serveSecureFile(id, token);
      
      // Check file size for potential streaming (future enhancement)
      const fileSizeThreshold = 1024 * 1024; // 1MB
      if (result.size > fileSizeThreshold) {
        logger.warn('Large file served as buffer - streaming not yet implemented for secure URLs', {
          fileId: id,
          fileSize: result.size,
          threshold: fileSizeThreshold,
          token: token.substring(0, 8) + '...'
        });
      }

      // Process metadata based on options (only for images)
      let processedBuffer = result.buffer;
      if (result.mimetype.startsWith('image/')) {
        processedBuffer = await this.metadataProcessor.processImageBuffer(
          result.buffer,
          result.mimetype,
          metadataOptions
        );
      }

      // Compress the file if requested
      if (req.query['compress'] === 'true') {
        const compressionType = req.query['compressionType'] as CompressionType;
        const compressionResult = await this.compressionService.compressBuffer(processedBuffer, result.mimetype, { type: compressionType });
        processedBuffer = compressionResult.buffer;
      }

      // Set headers
      res.setHeader('Content-Type', result.mimetype);
      res.setHeader('Content-Length', processedBuffer.length.toString());
      res.setHeader('Cache-Control', 'private, max-age=3600'); // Cache for 1 hour
      res.setHeader('X-Metadata-Processing', this.metadataProcessor.getMetadataSummary(metadataOptions));

      logger.info('Secure file served', {
        fileId: id,
        token: token.substring(0, 8) + '...',
        mimetype: result.mimetype,
        originalSize: result.buffer.length,
        processedSize: processedBuffer.length,
        metadataProcessed: result.mimetype.startsWith('image/'),
        ip: req.ip
      });

      res.send(processedBuffer);
    } catch (error) {
      logger.error('Failed to serve secure file', {
        error: error instanceof Error ? error.message : error,
        fileId: req.params['id'],
        token: req.query['token']?.toString().substring(0, 8) + '...',
        ip: req.ip
      });

      if (error instanceof Error && error.message.includes('Invalid or expired')) {
        res.status(401).json({
          error: 'Invalid token',
          message: 'The secure token is invalid or has expired'
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
  }

  /**
   * Get storage statistics (admin only)
   */
  async getStorageStats(req: Request, res: Response): Promise<void> {
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

      const stats = await this.fileService.getStorageStats();

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
  }

  /**
   * Get detailed file metadata including extracted metadata
   */
  async getFileMetadataDetailed(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      if (!id) {
        res.status(400).json({
          error: 'File ID required',
          message: 'File ID parameter is required'
        });
        return;
      }

      const metadata = await this.fileService.getFileMetadata(id, req.user?.userId);

      logger.info('Detailed metadata retrieved', {
        fileId: id,
        filename: metadata.originalName,
        hasExtractedMetadata: !!metadata.extractedMetadata,
        userId: req.user?.userId,
        ip: req.ip
      });

      res.json({
        success: true,
        data: {
          ...metadata,
          // Include full extracted metadata
          extractedMetadata: metadata.extractedMetadata || null
        },
        message: 'File metadata retrieved successfully'
      });
    } catch (error) {
      logger.error('Failed to retrieve detailed file metadata', {
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
          message: 'You do not have permission to access this file metadata'
        });
        return;
      }

      res.status(500).json({
        error: 'Failed to retrieve metadata',
        message: 'An error occurred while retrieving file metadata'
      });
    }
  }
}

export default new FileController();
