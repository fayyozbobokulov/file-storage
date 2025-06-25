import { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand, ListObjectsV2Command, DeleteObjectsCommand, HeadObjectCommand, ServerSideEncryption } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { StorageProvider, StorageResult, DownloadResult, StorageError } from '@/types';
import { logger } from '@/utils/logger';
import { config } from '@/utils/config';
import { Readable } from 'stream';

export class S3StorageProvider implements StorageProvider {
  private s3: S3Client;
  private bucketName: string;
  private thumbnailsBucket: string;

  constructor() {
    if (!config.storage.s3) {
      throw new StorageError('S3 configuration is missing');
    }

    this.bucketName = config.storage.s3.bucketName;
    this.thumbnailsBucket = config.storage.s3.thumbnailsBucket || config.storage.s3.bucketName;

    // Configure AWS SDK v3
    this.s3 = new S3Client({
      region: config.storage.s3.region,
      credentials: {
        accessKeyId: config.storage.s3.accessKeyId,
        secretAccessKey: config.storage.s3.secretAccessKey
      }
    });

    logger.info('S3 Storage Provider initialized', {
      region: config.storage.s3.region,
      bucket: this.bucketName,
      thumbnailsBucket: this.thumbnailsBucket
    });
  }

  private generateStorageKey(filename: string, isThumbnail = false): string {
    const timestamp = Date.now();
    const randomSuffix = Math.random().toString(36).substring(2, 15);
    const extension = filename.split('.').pop();
    const baseName = filename.replace(/\.[^/.]+$/, '');
    
    const storageKey = `${timestamp}-${randomSuffix}-${baseName}.${extension}`;
    
    return isThumbnail 
      ? `thumbnails/${storageKey}`
      : `files/${storageKey}`;
  }

  private getBucket(storageKey: string): string {
    return storageKey.startsWith('thumbnails/') 
      ? this.thumbnailsBucket 
      : this.bucketName;
  }

  async upload(buffer: Buffer, filename: string, mimetype: string): Promise<StorageResult> {
    try {
      const storageKey = this.generateStorageKey(filename);
      const bucket = this.getBucket(storageKey);

      const uploadParams = {
        Bucket: bucket,
        Key: storageKey,
        Body: buffer,
        ContentType: mimetype,
        ServerSideEncryption: ServerSideEncryption.AES256,
        Metadata: {
          originalName: filename,
          uploadedAt: new Date().toISOString()
        }
      };

      const command = new PutObjectCommand(uploadParams);
      await this.s3.send(command);
      
      // Construct URL manually since SDK v3 doesn't return Location
      const region = config.storage.s3?.region;
      const url = `https://${bucket}.s3.${region}.amazonaws.com/${storageKey}`;

      logger.info('File uploaded to S3', {
        storageKey,
        filename,
        size: buffer.length,
        mimetype,
        bucket,
        url
      });

      return {
        storageKey,
        size: buffer.length,
        mimetype,
        url
      };
    } catch (error) {
      logger.error('Failed to upload file to S3', {
        error: error instanceof Error ? error.message : error,
        filename,
        mimetype
      });
      throw new StorageError(`Failed to upload file to S3: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async download(storageKey: string): Promise<DownloadResult> {
    try {
      const bucket = this.getBucket(storageKey);

      const downloadParams = {
        Bucket: bucket,
        Key: storageKey
      };

      const command = new GetObjectCommand(downloadParams);
      const result = await this.s3.send(command);

      if (!result.Body) {
        throw new StorageError('File body is empty');
      }

      // In v3, Body is a ReadableStream, we need to convert it to Buffer
      const chunks: Uint8Array[] = [];
      for await (const chunk of result.Body as any) {
        chunks.push(chunk);
      }
      const buffer = Buffer.concat(chunks);
      
      const mimetype = result.ContentType || 'application/octet-stream';
      const size = result.ContentLength || buffer.length;

      logger.debug('File downloaded from S3', {
        storageKey,
        size,
        mimetype,
        bucket
      });

      return {
        buffer,
        mimetype,
        size
      };
    } catch (error) {
      logger.error('Failed to download file from S3', {
        error: error instanceof Error ? error.message : error,
        storageKey
      });

      if (error instanceof Error && error.message.includes('NoSuchKey')) {
        throw new StorageError('File not found');
      }

      throw new StorageError(`Failed to download file from S3: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async downloadStream(storageKey: string): Promise<Readable> {
    try {
      const bucket = this.getBucket(storageKey);

      const downloadParams = {
        Bucket: bucket,
        Key: storageKey
      };

      const command = new GetObjectCommand(downloadParams);
      const result = await this.s3.send(command);

      if (!result.Body) {
        throw new StorageError('File body is empty');
      }

      logger.debug('File downloaded from S3 as stream', {
        storageKey,
        bucket
      });

      return result.Body as any;
    } catch (error) {
      logger.error('Failed to download file from S3 as stream', {
        error: error instanceof Error ? error.message : error,
        storageKey
      });

      if (error instanceof Error && error.message.includes('NoSuchKey')) {
        throw new StorageError('File not found');
      }

      throw new StorageError(`Failed to download file from S3: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async delete(storageKey: string): Promise<void> {
    try {
      const bucket = this.getBucket(storageKey);

      const deleteParams = {
        Bucket: bucket,
        Key: storageKey
      };

      const command = new DeleteObjectCommand(deleteParams);
      await this.s3.send(command);

      logger.info('File deleted from S3', {
        storageKey,
        bucket
      });
    } catch (error) {
      logger.error('Failed to delete file from S3', {
        error: error instanceof Error ? error.message : error,
        storageKey
      });
      throw new StorageError(`Failed to delete file from S3: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async exists(storageKey: string): Promise<boolean> {
    try {
      const bucket = this.getBucket(storageKey);

      const headParams = {
        Bucket: bucket,
        Key: storageKey
      };

      const command = new HeadObjectCommand(headParams);
      await this.s3.send(command);
      return true;
    } catch (error) {
      if (error instanceof Error && error.name === 'NotFound') {
        return false;
      }

      // For other errors, log but still return false
      logger.error('Error checking if file exists in S3', {
        error: error instanceof Error ? error.message : error,
        storageKey
      });
      return false;
    }
  }

  async getUrl(storageKey: string, expiresIn = 3600): Promise<string> {
    try {
      const bucket = this.getBucket(storageKey);

      const params = {
        Bucket: bucket,
        Key: storageKey,
        ResponseContentDisposition: 'inline'
      };

      const command = new GetObjectCommand(params);
      const url = await getSignedUrl(this.s3, command, { expiresIn });

      logger.debug('Generated signed URL for S3 object', {
        storageKey,
        bucket,
        expiresIn
      });

      return url;
    } catch (error) {
      logger.error('Failed to generate signed URL for S3 object', {
        error: error instanceof Error ? error.message : error,
        storageKey
      });
      throw new StorageError(`Failed to generate signed URL: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  // Utility method to upload thumbnails
  async uploadThumbnail(buffer: Buffer, originalFilename: string, size: number, mimetype: string): Promise<StorageResult> {
    try {
      const extension = originalFilename.split('.').pop();
      const baseName = originalFilename.replace(/\.[^/.]+$/, '');
      const thumbnailFilename = `${baseName}_${size}.${extension}`;
      
      const storageKey = this.generateStorageKey(thumbnailFilename, true);
      const bucket = this.getBucket(storageKey);

      const uploadParams = {
        Bucket: bucket,
        Key: storageKey,
        Body: buffer,
        ContentType: mimetype,
        ServerSideEncryption: ServerSideEncryption.AES256,
        Metadata: {
          originalName: originalFilename,
          thumbnailSize: size.toString(),
          uploadedAt: new Date().toISOString()
        }
      };

      const command = new PutObjectCommand(uploadParams);
      await this.s3.send(command);
      
      // Construct URL manually since SDK v3 doesn't return Location
      const region = config.storage?.s3?.region;
      const url = `https://${bucket}.s3.${region}.amazonaws.com/${storageKey}`;

      logger.info('Thumbnail uploaded to S3', {
        storageKey,
        originalFilename,
        size: buffer.length,
        thumbnailSize: size,
        mimetype,
        bucket,
        url
      });

      return {
        storageKey,
        size: buffer.length,
        mimetype,
        url
      };
    } catch (error) {
      logger.error('Failed to upload thumbnail to S3', {
        error: error instanceof Error ? error.message : error,
        originalFilename,
        thumbnailSize: size
      });
      throw new StorageError(`Failed to upload thumbnail to S3: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  // Get storage statistics (this is expensive for S3, use with caution)
  async getStorageStats(): Promise<{ totalFiles: number; totalSize: number }> {
    try {
      const listParams = {
        Bucket: this.bucketName,
        Prefix: 'files/'
      };

      let totalFiles = 0;
      let totalSize = 0;
      let continuationToken: string | undefined;

      do {
        const command = new ListObjectsV2Command({
          ...listParams,
          ContinuationToken: continuationToken
        });
        
        const result = await this.s3.send(command);

        if (result.Contents) {
          totalFiles += result.Contents.length;
          totalSize += result.Contents.reduce((sum, obj) => sum + (obj.Size || 0), 0);
        }

        continuationToken = result.NextContinuationToken;
      } while (continuationToken);

      return { totalFiles, totalSize };
    } catch (error) {
      logger.error('Failed to get S3 storage statistics', {
        error: error instanceof Error ? error.message : error
      });
      return { totalFiles: 0, totalSize: 0 };
    }
  }

  // Batch delete files (useful for cleanup)
  async batchDelete(storageKeys: string[]): Promise<void> {
    try {
      // Group by bucket
      const bucketGroups: Record<string, string[]> = {};
      
      for (const key of storageKeys) {
        const bucket = this.getBucket(key);
        if (!bucketGroups[bucket]) {
          bucketGroups[bucket] = [];
        }
        bucketGroups[bucket]!.push(key);
      }

      // Delete from each bucket
      for (const [bucket, keys] of Object.entries(bucketGroups)) {
        const deleteParams = {
          Bucket: bucket,
          Delete: {
            Objects: keys.map(key => ({ Key: key })),
            Quiet: true
          }
        };

        const command = new DeleteObjectsCommand(deleteParams);
        await this.s3.send(command);
        
        logger.info('Batch deleted files from S3', {
          bucket,
          count: keys.length
        });
      }
    } catch (error) {
      logger.error('Failed to batch delete files from S3', {
        error: error instanceof Error ? error.message : error,
        storageKeysCount: storageKeys.length
      });
      throw new StorageError(`Failed to batch delete files: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }
}
