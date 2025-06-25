import { Collection, ObjectId, Filter, UpdateFilter } from 'mongodb';
import { FileMetadata, FileListQuery, PermissionUpdateRequest, FileNotFoundError } from '@/types';
import { dbConnection } from './connection';
import { logger } from '@/utils/logger';

export class FileRepository {
  private getCollection(): Collection<FileMetadata> {
    return dbConnection.getDb().collection<FileMetadata>('files');
  }

  async create(fileData: Omit<FileMetadata, '_id'>): Promise<FileMetadata> {
    try {
      const collection = this.getCollection();
      const now = new Date();
      
      const fileMetadata: Omit<FileMetadata, '_id'> = {
        ...fileData,
        createdAt: now,
        updatedAt: now
      };

      const result = await collection.insertOne(fileMetadata);
      
      const createdFile = await collection.findOne({ _id: result.insertedId });
      
      if (!createdFile) {
        throw new Error('Failed to retrieve created file');
      }

      logger.info('File metadata created', {
        fileId: result.insertedId.toString(),
        originalName: fileData.originalName,
        ownerId: fileData.ownerId
      });

      return createdFile;
    } catch (error) {
      logger.error('Failed to create file metadata', {
        error: error instanceof Error ? error.message : error,
        originalName: fileData.originalName,
        ownerId: fileData.ownerId
      });
      throw error;
    }
  }

  async findById(id: string): Promise<FileMetadata | null> {
    try {
      const collection = this.getCollection();
      const objectId = new ObjectId(id);
      
      const file = await collection.findOne({ _id: objectId });
      
      if (file) {
        logger.debug('File metadata retrieved', { fileId: id });
      }
      
      return file;
    } catch (error) {
      logger.error('Failed to find file by ID', {
        error: error instanceof Error ? error.message : error,
        fileId: id
      });
      return null;
    }
  }

  async findByStorageKey(storageKey: string): Promise<FileMetadata | null> {
    try {
      const collection = this.getCollection();
      
      const file = await collection.findOne({ storageKey });
      
      if (file) {
        logger.debug('File metadata retrieved by storage key', { storageKey });
      }
      
      return file;
    } catch (error) {
      logger.error('Failed to find file by storage key', {
        error: error instanceof Error ? error.message : error,
        storageKey
      });
      return null;
    }
  }

  async findMany(query: FileListQuery, userId?: string): Promise<{ files: FileMetadata[]; total: number; page: number; limit: number }> {
    try {
      const collection = this.getCollection();
      
      // Build MongoDB filter
      const filter: Filter<FileMetadata> = {};
      
      // Owner filter
      if (query.ownerId) {
        filter.ownerId = query.ownerId;
      } else if (userId) {
        // If no specific owner requested, show files the user has access to
        filter.$or = [
          { ownerId: userId },
          { isPublic: true },
          { 'permissions.userId': userId }
        ];
      }
      
      // Mimetype filter
      if (query.mimetype) {
        filter.mimetype = { $regex: query.mimetype, $options: 'i' };
      }
      
      // Tags filter
      if (query.tags && query.tags.length > 0) {
        filter.tags = { $in: query.tags };
      }
      
      // Text search
      if (query.search) {
        filter.$text = { $search: query.search };
      }

      // Build sort options
      const sortField = query.sortBy || 'createdAt';
      const sortOrder = query.sortOrder === 'asc' ? 1 : -1;
      const sort = { [sortField]: sortOrder };

      // Pagination
      const page = query.page || 1;
      const limit = Math.min(query.limit || 20, 100); // Cap at 100
      const skip = (page - 1) * limit;

      // Execute queries
      const [files, total] = await Promise.all([
        collection
          .find(filter)
          .sort(sort as any)
          .skip(skip)
          .limit(limit)
          .toArray(),
        collection.countDocuments(filter)
      ]);

      logger.debug('Files retrieved', {
        count: files.length,
        total,
        page,
        limit,
        userId
      });

      return {
        files,
        total,
        page,
        limit
      };
    } catch (error) {
      logger.error('Failed to find files', {
        error: error instanceof Error ? error.message : error,
        query,
        userId
      });
      throw error;
    }
  }

  async updatePermissions(id: string, permissionUpdate: PermissionUpdateRequest): Promise<FileMetadata> {
    try {
      const collection = this.getCollection();
      const objectId = new ObjectId(id);
      
      const updateDoc: UpdateFilter<FileMetadata> = {
        $set: {
          permissions: permissionUpdate.permissions,
          updatedAt: new Date()
        }
      };

      if (permissionUpdate.isPublic !== undefined) {
        (updateDoc.$set as any).isPublic = permissionUpdate.isPublic;
      }

      if (permissionUpdate.customPermissions) {
        (updateDoc.$set as any).customPermissions = permissionUpdate.customPermissions;
      }

      const result = await collection.findOneAndUpdate(
        { _id: objectId },
        updateDoc,
        { returnDocument: 'after' }
      );

      if (!result) {
        throw new FileNotFoundError();
      }

      logger.info('File permissions updated', {
        fileId: id,
        isPublic: permissionUpdate.isPublic,
        permissionsCount: permissionUpdate.permissions.length
      });

      return result;
    } catch (error) {
      logger.error('Failed to update file permissions', {
        error: error instanceof Error ? error.message : error,
        fileId: id
      });
      throw error;
    }
  }

  async updateThumbnails(id: string, thumbnails: Record<string, any>): Promise<FileMetadata> {
    try {
      const collection = this.getCollection();
      const objectId = new ObjectId(id);
      
      const result = await collection.findOneAndUpdate(
        { _id: objectId },
        {
          $set: {
            thumbnails,
            updatedAt: new Date()
          }
        },
        { returnDocument: 'after' }
      );

      if (!result) {
        throw new FileNotFoundError();
      }

      logger.info('File thumbnails updated', {
        fileId: id,
        thumbnailSizes: Object.keys(thumbnails)
      });

      return result;
    } catch (error) {
      logger.error('Failed to update file thumbnails', {
        error: error instanceof Error ? error.message : error,
        fileId: id
      });
      throw error;
    }
  }

  async delete(id: string): Promise<void> {
    try {
      const collection = this.getCollection();
      const objectId = new ObjectId(id);
      
      const result = await collection.deleteOne({ _id: objectId });
      
      if (result.deletedCount === 0) {
        throw new FileNotFoundError();
      }

      logger.info('File metadata deleted', { fileId: id });
    } catch (error) {
      logger.error('Failed to delete file metadata', {
        error: error instanceof Error ? error.message : error,
        fileId: id
      });
      throw error;
    }
  }

  async deleteByStorageKey(storageKey: string): Promise<void> {
    try {
      const collection = this.getCollection();
      
      const result = await collection.deleteOne({ storageKey });
      
      if (result.deletedCount === 0) {
        throw new FileNotFoundError();
      }

      logger.info('File metadata deleted by storage key', { storageKey });
    } catch (error) {
      logger.error('Failed to delete file metadata by storage key', {
        error: error instanceof Error ? error.message : error,
        storageKey
      });
      throw error;
    }
  }

  // Check if user has permission to access file
  async checkPermission(fileId: string, userId: string, requiredAction: number): Promise<boolean> {
    try {
      const file = await this.findById(fileId);
      
      if (!file) {
        return false;
      }

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
    } catch (error) {
      logger.error('Failed to check file permission', {
        error: error instanceof Error ? error.message : error,
        fileId,
        userId,
        requiredAction
      });
      return false;
    }
  }

  // Get files by owner
  async findByOwner(ownerId: string, limit = 50): Promise<FileMetadata[]> {
    try {
      const collection = this.getCollection();
      
      const files = await collection
        .find({ ownerId })
        .sort({ createdAt: -1 })
        .limit(limit)
        .toArray();

      logger.debug('Files retrieved by owner', {
        ownerId,
        count: files.length
      });

      return files;
    } catch (error) {
      logger.error('Failed to find files by owner', {
        error: error instanceof Error ? error.message : error,
        ownerId
      });
      throw error;
    }
  }

  // Get storage statistics
  async getStorageStats(): Promise<{ totalFiles: number; totalSize: number; totalOwners: number }> {
    try {
      const collection = this.getCollection();
      
      const [totalFiles, sizeResult, ownersResult] = await Promise.all([
        collection.countDocuments(),
        collection.aggregate([
          { $group: { _id: null, totalSize: { $sum: '$size' } } }
        ]).toArray(),
        collection.distinct('ownerId')
      ]);

      const totalSize = sizeResult[0]?.['totalSize'] || 0;
      const totalOwners = ownersResult.length;

      return {
        totalFiles,
        totalSize,
        totalOwners
      };
    } catch (error) {
      logger.error('Failed to get storage statistics', {
        error: error instanceof Error ? error.message : error
      });
      return {
        totalFiles: 0,
        totalSize: 0,
        totalOwners: 0
      };
    }
  }
}
