import { FileMetadata, FileListQuery, PermissionUpdateRequest, FileNotFoundError, ValidationError } from '@/types';
import { FileRepository } from '@/database/file-repository';
import { getStorageProvider } from '@/storage';
import { ThumbnailService } from './thumbnail-service';
import { logger } from '@/utils/logger';
import { config } from '@/utils/config';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { Readable } from 'stream';

export interface UploadFileRequest {
  buffer: Buffer;
  originalName: string;
  mimetype: string;
  size: number;
  ownerId: string;
  tags?: string[];
  isPublic?: boolean;
  permissions?: Array<{ userId: string; actions: number }>;
}

export interface FileDownloadResult {
  buffer: Buffer;
  mimetype: string;
  size: number;
  filename: string;
}

export class FileService {
  private fileRepository: FileRepository;
  private storageProvider: ReturnType<typeof getStorageProvider>;
  private thumbnailService: ThumbnailService;

  constructor() {
    this.fileRepository = new FileRepository();
    this.storageProvider = getStorageProvider();
    this.thumbnailService = new ThumbnailService(this.storageProvider);
  }

  async uploadFile(request: UploadFileRequest): Promise<FileMetadata> {
    try {
      // Validate file size
      if (request.size > config.upload.maxFileSize) {
        throw new ValidationError(`File size exceeds maximum allowed size of ${config.upload.maxFileSize} bytes`);
      }

      // Validate file type
      if (config.upload.allowedMimeTypes.length > 0 && 
          !config.upload.allowedMimeTypes.includes('*') &&
          !config.upload.allowedMimeTypes.some(type => {
            // Allow wildcard subtypes like 'image/*'
            if (type.endsWith('/*')) {
              const mainType = type.split('/')[0];
              const fileMainType = request.mimetype.split('/')[0];
              return mainType === fileMainType;
            }
            return type === request.mimetype;
          })) {
        throw new ValidationError(`File type ${request.mimetype} is not allowed`);
      }

      // Generate a unique storage key using UUID
      const fileExtension = request.originalName.split('.').pop() || '';
      const uniqueStorageKey = `${uuidv4()}${fileExtension ? '.' + fileExtension : ''}`;
      
      logger.info('Starting file upload', {
        originalName: request.originalName,
        mimetype: request.mimetype,
        size: request.size,
        ownerId: request.ownerId,
        storageKey: uniqueStorageKey
      });

      // Upload file to storage with the generated storage key
      const storageResult = await this.storageProvider.upload(
        request.buffer,
        uniqueStorageKey, // Use the generated key instead of original filename
        request.mimetype
      );

      // Generate thumbnails if supported
      let thumbnails: Record<string, any> = {};
      if (ThumbnailService.supportsThumbnails(request.mimetype)) {
        try {
          thumbnails = await this.thumbnailService.generateThumbnails(
            request.buffer,
            uniqueStorageKey, // Use the same key for thumbnails
            request.mimetype
          );
          logger.info('Thumbnails generated', {
            originalName: request.originalName,
            storageKey: uniqueStorageKey,
            thumbnailCount: Object.keys(thumbnails).length
          });
        } catch (error) {
          logger.warn('Failed to generate thumbnails, continuing without them', {
            error: error instanceof Error ? error.message : error,
            originalName: request.originalName,
            storageKey: uniqueStorageKey
          });
        }
      }

      // Create file metadata
      const fileMetadata: Omit<FileMetadata, '_id'> = {
        originalName: request.originalName,
        storageKey: storageResult.storageKey || uniqueStorageKey, // Fallback to our generated key if needed
        mimetype: request.mimetype,
        size: request.size,
        ownerId: request.ownerId,
        tags: request.tags || [],
        isPublic: request.isPublic || false,
        permissions: request.permissions || [],
        customPermissions: {},
        thumbnails,
        createdAt: new Date(),
        updatedAt: new Date()
      };

      const savedFile = await this.fileRepository.create(fileMetadata);

      logger.info('File uploaded successfully', {
        fileId: savedFile._id?.toString(),
        originalName: request.originalName,
        storageKey: storageResult.storageKey,
        ownerId: request.ownerId
      });

      return savedFile;
    } catch (error) {
      logger.error('Failed to upload file', {
        error: error instanceof Error ? error.message : error,
        originalName: request.originalName,
        ownerId: request.ownerId
      });
      throw error;
    }
  }

  async downloadFile(fileId: string, userId?: string): Promise<FileDownloadResult> {
    try {
      const file = await this.fileRepository.findById(fileId);
      
      if (!file) {
        throw new FileNotFoundError();
      }

      // Check permissions
      if (userId && !await this.checkFileAccess(file, userId, 0x01)) { // READ permission
        throw new Error('Access denied');
      }

      const downloadResult = await this.storageProvider.download(file.storageKey);

      logger.info('File downloaded', {
        fileId,
        originalName: file.originalName,
        userId
      });

      return {
        buffer: downloadResult.buffer,
        mimetype: downloadResult.mimetype,
        size: downloadResult.size,
        filename: file.originalName
      };
    } catch (error) {
      logger.error('Failed to download file', {
        error: error instanceof Error ? error.message : error,
        fileId,
        userId
      });
      throw error;
    }
  }

  async downloadFileStream(fileId: string, userId?: string): Promise<{
    stream: Readable;
    mimetype: string;
    size: number;
    filename: string;
  }> {
    try {
      const file = await this.fileRepository.findById(fileId);
      
      if (!file) {
        throw new FileNotFoundError();
      }

      // Check permissions
      if (userId && !await this.checkFileAccess(file, userId, 0x01)) { // READ permission
        throw new Error('Access denied');
      }

      // Check if storage provider supports streaming
      if (!('downloadStream' in this.storageProvider)) {
        throw new Error('Storage provider does not support streaming');
      }

      const stream = await (this.storageProvider as any).downloadStream(file.storageKey);

      logger.info('File downloaded as stream', {
        fileId,
        originalName: file.originalName,
        size: file.size,
        userId
      });

      return {
        stream,
        mimetype: file.mimetype,
        size: file.size,
        filename: file.originalName
      };
    } catch (error) {
      logger.error('Failed to download file as stream', {
        error: error instanceof Error ? error.message : error,
        fileId,
        userId
      });
      throw error;
    }
  }

  async getFileMetadata(fileId: string, userId?: string): Promise<FileMetadata> {
    try {
      const file = await this.fileRepository.findById(fileId);
      
      if (!file) {
        throw new FileNotFoundError();
      }

      // Check permissions
      if (userId && !await this.checkFileAccess(file, userId, 0x01)) { // READ permission
        throw new Error('Access denied');
      }

      return file;
    } catch (error) {
      logger.error('Failed to get file metadata', {
        error: error instanceof Error ? error.message : error,
        fileId,
        userId
      });
      throw error;
    }
  }

  async listFiles(query: FileListQuery, userId?: string): Promise<{ files: FileMetadata[]; total: number; page: number; limit: number }> {
    try {
      const result = await this.fileRepository.findMany(query, userId);

      logger.debug('Files listed', {
        count: result.files.length,
        total: result.total,
        page: result.page,
        userId
      });

      return result;
    } catch (error) {
      logger.error('Failed to list files', {
        error: error instanceof Error ? error.message : error,
        query,
        userId
      });
      throw error;
    }
  }

  async updatePermissions(fileId: string, permissionUpdate: PermissionUpdateRequest, userId: string): Promise<FileMetadata> {
    try {
      const file = await this.fileRepository.findById(fileId);
      
      if (!file) {
        throw new FileNotFoundError();
      }

      // Only owner can update permissions
      if (file.ownerId !== userId) {
        throw new Error('Only file owner can update permissions');
      }

      const updatedFile = await this.fileRepository.updatePermissions(fileId, permissionUpdate);

      logger.info('File permissions updated', {
        fileId,
        ownerId: userId,
        isPublic: permissionUpdate.isPublic,
        permissionsCount: permissionUpdate.permissions.length
      });

      return updatedFile;
    } catch (error) {
      logger.error('Failed to update file permissions', {
        error: error instanceof Error ? error.message : error,
        fileId,
        userId
      });
      throw error;
    }
  }

  async deleteFile(fileId: string, userId: string): Promise<void> {
    try {
      const file = await this.fileRepository.findById(fileId);
      
      if (!file) {
        throw new FileNotFoundError();
      }

      // Check if user has delete permission
      if (!await this.checkFileAccess(file, userId, 0x04)) { // DELETE permission
        throw new Error('Access denied');
      }

      // Delete from storage
      await this.storageProvider.delete(file.storageKey);

      // Delete thumbnails
      if (file.thumbnails && Object.keys(file.thumbnails).length > 0) {
        try {
          // Convert ThumbnailInfo to ThumbnailResult for deletion
          const thumbnailResults: Record<string, { storageKey: string; size: number; fileSize: number; mimetype: string }> = {};
          for (const [size, info] of Object.entries(file.thumbnails)) {
            thumbnailResults[size] = {
              storageKey: info.storageKey,
              size: info.size || 0,
              fileSize: info.size || 0,
              mimetype: info.mimetype || 'image/jpeg'
            };
          }
          await this.thumbnailService.deleteThumbnails(thumbnailResults);
        } catch (error) {
          logger.warn('Failed to delete thumbnails', {
            error: error instanceof Error ? error.message : error,
            fileId
          });
        }
      }

      // Delete metadata
      await this.fileRepository.delete(fileId);

      logger.info('File deleted successfully', {
        fileId,
        originalName: file.originalName,
        userId
      });
    } catch (error) {
      logger.error('Failed to delete file', {
        error: error instanceof Error ? error.message : error,
        fileId,
        userId
      });
      throw error;
    }
  }

  async getThumbnail(fileId: string, size: string, userId?: string): Promise<{ buffer: Buffer; mimetype: string; size: number }> {
    try {
      const file = await this.fileRepository.findById(fileId);
      
      if (!file) {
        throw new FileNotFoundError();
      }

      // Check permissions
      if (userId && !await this.checkFileAccess(file, userId, 0x01)) { // READ permission
        throw new Error('Access denied');
      }

      if (!file.thumbnails || !file.thumbnails[size]) {
        throw new Error('Thumbnail not found');
      }

      const thumbnail = file.thumbnails[size];
      const result = await this.thumbnailService.getThumbnail(thumbnail.storageKey);

      logger.debug('Thumbnail served', {
        fileId,
        size,
        userId
      });

      return result;
    } catch (error) {
      logger.error('Failed to get thumbnail', {
        error: error instanceof Error ? error.message : error,
        fileId,
        size,
        userId
      });
      throw error;
    }
  }

  async generateSecureUrl(fileId: string, userId: string, expiresIn = 3600): Promise<string> {
    try {
      const file = await this.fileRepository.findById(fileId);
      
      if (!file) {
        throw new FileNotFoundError();
      }

      // Check permissions
      if (!await this.checkFileAccess(file, userId, 0x01)) { // READ permission
        throw new Error('Access denied');
      }

      // Generate JWT token for secure access
      const token = jwt.sign(
        {
          fileId,
          userId,
          storageKey: file.storageKey,
          exp: Math.floor(Date.now() / 1000) + expiresIn
        },
        config.jwt.secret
      );

      const secureUrl = `/api/files/secure/${fileId}?token=${token}`;

      logger.info('Secure URL generated', {
        fileId,
        userId,
        expiresIn
      });

      return secureUrl;
    } catch (error) {
      logger.error('Failed to generate secure URL', {
        error: error instanceof Error ? error.message : error,
        fileId,
        userId
      });
      throw error;
    }
  }

  async serveSecureFile(fileId: string, token: string): Promise<FileDownloadResult> {
    try {
      // Verify token
      const decoded = jwt.verify(token, config.jwt.secret) as any;
      
      if (decoded.fileId !== fileId) {
        throw new Error('Invalid token for this file');
      }

      const file = await this.fileRepository.findById(fileId);
      
      if (!file) {
        throw new FileNotFoundError();
      }

      if (file.storageKey !== decoded.storageKey) {
        throw new Error('File has been modified since token generation');
      }

      const downloadResult = await this.storageProvider.download(file.storageKey);

      logger.info('Secure file served', {
        fileId,
        userId: decoded.userId
      });

      return {
        buffer: downloadResult.buffer,
        mimetype: downloadResult.mimetype,
        size: downloadResult.size,
        filename: file.originalName
      };
    } catch (error) {
      logger.error('Failed to serve secure file', {
        error: error instanceof Error ? error.message : error,
        fileId
      });
      throw error;
    }
  }

  private async checkFileAccess(file: FileMetadata, userId: string, requiredAction: number): Promise<boolean> {
    // Owner has all permissions
    if (file.ownerId === userId) {
      return true;
    }

    // Public files can be read by anyone
    if (file.isPublic && requiredAction === 0x01) { // READ permission
      return true;
    }

    // Check explicit permissions
    const userPermission = file.permissions.find(p => p.userId === userId);
    if (userPermission && (userPermission.actions & requiredAction) === requiredAction) {
      return true;
    }

    // Check custom permissions
    if (file.customPermissions && file.customPermissions[userId]) {
      const customActions = file.customPermissions[userId];
      if ((customActions & requiredAction) === requiredAction) {
        return true;
      }
    }

    return false;
  }

  // Get storage statistics
  async getStorageStats(): Promise<{ files: { totalFiles: number; totalSize: number; totalOwners: number }; storage: { totalFiles: number; totalSize: number } }> {
    try {
      const [dbStats, storageStats] = await Promise.all([
        this.fileRepository.getStorageStats(),
        (this.storageProvider as any).getStorageStats?.() || { totalFiles: 0, totalSize: 0 }
      ]);

      return {
        files: dbStats,
        storage: storageStats
      };
    } catch (error) {
      logger.error('Failed to get storage statistics', {
        error: error instanceof Error ? error.message : error
      });
      throw error;
    }
  }
}
