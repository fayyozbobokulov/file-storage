import fs from 'fs/promises';
import path from 'path';
import { StorageProvider, StorageResult, DownloadResult, StorageError } from '@/types';
import { logger } from '@/utils/logger';
import { config } from '@/utils/config';

export class LocalStorageProvider implements StorageProvider {
  private storagePath: string;
  private thumbnailsPath: string;

  constructor() {
    this.storagePath = config.storage.local?.storagePath || './uploads';
    this.thumbnailsPath = config.storage.local?.thumbnailsPath || './uploads/thumbnails';
    this.ensureDirectories();
  }

  private async ensureDirectories(): Promise<void> {
    try {
      await fs.mkdir(this.storagePath, { recursive: true });
      await fs.mkdir(this.thumbnailsPath, { recursive: true });
      logger.debug('Local storage directories ensured', {
        storagePath: this.storagePath,
        thumbnailsPath: this.thumbnailsPath
      });
    } catch (error) {
      logger.error('Failed to create storage directories', {
        error: error instanceof Error ? error.message : error,
        storagePath: this.storagePath,
        thumbnailsPath: this.thumbnailsPath
      });
      throw new StorageError('Failed to initialize local storage directories');
    }
  }

  private generateStorageKey(filename: string, isThumbnail = false): string {
    const timestamp = Date.now();
    const randomSuffix = Math.random().toString(36).substring(2, 15);
    const extension = path.extname(filename);
    const baseName = path.basename(filename, extension);
    
    const storageKey = `${timestamp}-${randomSuffix}-${baseName}${extension}`;
    
    return isThumbnail 
      ? path.join('thumbnails', storageKey)
      : storageKey;
  }

  private getFullPath(storageKey: string): string {
    if (storageKey.startsWith('thumbnails/')) {
      return path.join(this.thumbnailsPath, path.basename(storageKey));
    }
    return path.join(this.storagePath, storageKey);
  }

  async upload(buffer: Buffer, filename: string, mimetype: string): Promise<StorageResult> {
    try {
      const storageKey = this.generateStorageKey(filename);
      const fullPath = this.getFullPath(storageKey);

      await fs.writeFile(fullPath, buffer);

      const stats = await fs.stat(fullPath);

      logger.info('File uploaded to local storage', {
        storageKey,
        filename,
        size: stats.size,
        mimetype
      });

      return {
        storageKey,
        size: stats.size,
        mimetype
      };
    } catch (error) {
      logger.error('Failed to upload file to local storage', {
        error: error instanceof Error ? error.message : error,
        filename,
        mimetype
      });
      throw new StorageError(`Failed to upload file: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async download(storageKey: string): Promise<DownloadResult> {
    try {
      const fullPath = this.getFullPath(storageKey);
      
      // Check if file exists
      await fs.access(fullPath);
      
      const buffer = await fs.readFile(fullPath);
      const stats = await fs.stat(fullPath);

      // Try to determine mimetype from file extension
      const extension = path.extname(storageKey).toLowerCase();
      const mimetypeMap: Record<string, string> = {
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.png': 'image/png',
        '.gif': 'image/gif',
        '.webp': 'image/webp',
        '.pdf': 'application/pdf',
        '.txt': 'text/plain',
        '.json': 'application/json',
        '.mp4': 'video/mp4',
        '.avi': 'video/x-msvideo',
        '.mov': 'video/quicktime'
      };

      const mimetype = mimetypeMap[extension] || 'application/octet-stream';

      logger.debug('File downloaded from local storage', {
        storageKey,
        size: stats.size,
        mimetype
      });

      return {
        buffer,
        mimetype,
        size: stats.size
      };
    } catch (error) {
      logger.error('Failed to download file from local storage', {
        error: error instanceof Error ? error.message : error,
        storageKey
      });
      
      if (error instanceof Error && error.message.includes('ENOENT')) {
        throw new StorageError('File not found');
      }
      
      throw new StorageError(`Failed to download file: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async delete(storageKey: string): Promise<void> {
    try {
      const fullPath = this.getFullPath(storageKey);
      await fs.unlink(fullPath);

      logger.info('File deleted from local storage', { storageKey });
    } catch (error) {
      logger.error('Failed to delete file from local storage', {
        error: error instanceof Error ? error.message : error,
        storageKey
      });

      if (error instanceof Error && error.message.includes('ENOENT')) {
        // File doesn't exist, consider it already deleted
        logger.warn('Attempted to delete non-existent file', { storageKey });
        return;
      }

      throw new StorageError(`Failed to delete file: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async exists(storageKey: string): Promise<boolean> {
    try {
      const fullPath = this.getFullPath(storageKey);
      await fs.access(fullPath);
      return true;
    } catch {
      return false;
    }
  }

  async getUrl(storageKey: string): Promise<string> {
    // For local storage, we return a proxy URL through our API
    // This ensures all access goes through our authentication system
    return `/api/files/secure/${storageKey}`;
  }

  // Utility method to upload thumbnails
  async uploadThumbnail(buffer: Buffer, originalFilename: string, size: number, mimetype: string): Promise<StorageResult> {
    try {
      const extension = path.extname(originalFilename);
      const baseName = path.basename(originalFilename, extension);
      const thumbnailFilename = `${baseName}_${size}${extension}`;
      
      const storageKey = this.generateStorageKey(thumbnailFilename, true);
      const fullPath = this.getFullPath(storageKey);

      await fs.writeFile(fullPath, buffer);
      const stats = await fs.stat(fullPath);

      logger.info('Thumbnail uploaded to local storage', {
        storageKey,
        originalFilename,
        size: stats.size,
        thumbnailSize: size,
        mimetype
      });

      return {
        storageKey,
        size: stats.size,
        mimetype
      };
    } catch (error) {
      logger.error('Failed to upload thumbnail to local storage', {
        error: error instanceof Error ? error.message : error,
        originalFilename,
        thumbnailSize: size
      });
      throw new StorageError(`Failed to upload thumbnail: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  // Get storage statistics
  async getStorageStats(): Promise<{ totalFiles: number; totalSize: number }> {
    try {
      const files = await fs.readdir(this.storagePath);
      let totalSize = 0;
      let totalFiles = 0;

      for (const file of files) {
        try {
          const filePath = path.join(this.storagePath, file);
          const stats = await fs.stat(filePath);
          if (stats.isFile()) {
            totalSize += stats.size;
            totalFiles++;
          }
        } catch {
          // Skip files that can't be accessed
        }
      }

      return { totalFiles, totalSize };
    } catch (error) {
      logger.error('Failed to get storage statistics', {
        error: error instanceof Error ? error.message : error
      });
      return { totalFiles: 0, totalSize: 0 };
    }
  }
}
