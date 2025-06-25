import sharp from 'sharp';
import ffmpeg from 'fluent-ffmpeg';
import path from 'path';
import fs from 'fs/promises';
import { StorageProvider } from '@/types';
import { logger } from '@/utils/logger';
import { config } from '@/utils/config';

// Try to set ffmpeg path if available
try {
  const ffmpegStatic = require('ffmpeg-static');
  if (ffmpegStatic) {
    ffmpeg.setFfmpegPath(ffmpegStatic);
  }
} catch (error) {
  // ffmpeg-static not available, use system ffmpeg
  logger.warn('ffmpeg-static not available, using system ffmpeg');
}

export interface ThumbnailOptions {
  sizes: number[];
  quality: number;
  format: 'jpeg' | 'png' | 'webp';
}

export interface ThumbnailResult {
  size: number;
  storageKey: string;
  mimetype: string;
  fileSize: number;
}

export class ThumbnailService {
  private storageProvider: StorageProvider;
  private defaultOptions: ThumbnailOptions;

  constructor(storageProvider: StorageProvider) {
    this.storageProvider = storageProvider;
    this.defaultOptions = {
      sizes: config.thumbnails.sizes,
      quality: config.thumbnails.quality,
      format: config.thumbnails.format as 'jpeg' | 'png' | 'webp'
    };
  }

  async generateThumbnails(
    buffer: Buffer,
    originalFilename: string,
    mimetype: string,
    options?: Partial<ThumbnailOptions>
  ): Promise<Record<string, ThumbnailResult>> {
    const opts = { ...this.defaultOptions, ...options };
    const thumbnails: Record<string, ThumbnailResult> = {};

    try {
      if (this.isImageType(mimetype)) {
        const imageThumbnails = await this.generateImageThumbnails(buffer, originalFilename, opts);
        Object.assign(thumbnails, imageThumbnails);
      } else if (this.isVideoType(mimetype)) {
        const videoThumbnails = await this.generateVideoThumbnails(buffer, originalFilename, opts);
        Object.assign(thumbnails, videoThumbnails);
      } else {
        logger.debug('Unsupported file type for thumbnail generation', {
          mimetype,
          originalFilename
        });
      }

      logger.info('Thumbnails generated successfully', {
        originalFilename,
        mimetype,
        thumbnailCount: Object.keys(thumbnails).length,
        sizes: Object.keys(thumbnails)
      });

      return thumbnails;
    } catch (error) {
      logger.error('Failed to generate thumbnails', {
        error: error instanceof Error ? error.message : error,
        originalFilename,
        mimetype
      });
      throw error;
    }
  }

  private async generateImageThumbnails(
    buffer: Buffer,
    originalFilename: string,
    options: ThumbnailOptions
  ): Promise<Record<string, ThumbnailResult>> {
    const thumbnails: Record<string, ThumbnailResult> = {};

    for (const size of options.sizes) {
      try {
        const thumbnailBuffer = await sharp(buffer)
          .resize(size, size, {
            fit: 'inside',
            withoutEnlargement: true
          })
          .jpeg({ quality: options.quality })
          .toBuffer();

        const result = await this.storageProvider.upload(
          thumbnailBuffer,
          this.getThumbnailFilename(originalFilename, size, 'jpeg'),
          'image/jpeg'
        );

        thumbnails[`${size}`] = {
          size,
          storageKey: result.storageKey,
          mimetype: 'image/jpeg',
          fileSize: result.size
        };

        logger.debug('Image thumbnail generated', {
          originalFilename,
          size,
          fileSize: result.size
        });
      } catch (error) {
        logger.error('Failed to generate image thumbnail', {
          error: error instanceof Error ? error.message : error,
          originalFilename,
          size
        });
        // Continue with other sizes even if one fails
      }
    }

    return thumbnails;
  }

  private async generateVideoThumbnails(
    buffer: Buffer,
    originalFilename: string,
    options: ThumbnailOptions
  ): Promise<Record<string, ThumbnailResult>> {
    const thumbnails: Record<string, ThumbnailResult> = {};
    const tempDir = path.join(process.cwd(), 'temp');
    const tempInputFile = path.join(tempDir, `input-${Date.now()}-${Math.random().toString(36).substring(2)}.tmp`);

    try {
      // Ensure temp directory exists
      await fs.mkdir(tempDir, { recursive: true });

      // Write buffer to temporary file
      await fs.writeFile(tempInputFile, buffer);

      for (const size of options.sizes) {
        try {
          const thumbnailBuffer = await this.extractVideoFrame(tempInputFile, size, options.quality);

          const result = await this.storageProvider.upload(
            thumbnailBuffer,
            this.getThumbnailFilename(originalFilename, size, 'jpeg'),
            'image/jpeg'
          );

          thumbnails[`${size}`] = {
            size,
            storageKey: result.storageKey,
            mimetype: 'image/jpeg',
            fileSize: result.size
          };

          logger.debug('Video thumbnail generated', {
            originalFilename,
            size,
            fileSize: result.size
          });
        } catch (error) {
          logger.error('Failed to generate video thumbnail', {
            error: error instanceof Error ? error.message : error,
            originalFilename,
            size
          });
          // Continue with other sizes even if one fails
        }
      }
    } finally {
      // Clean up temporary file
      try {
        await fs.unlink(tempInputFile);
      } catch (error) {
        logger.warn('Failed to clean up temporary file', {
          error: error instanceof Error ? error.message : error,
          tempFile: tempInputFile
        });
      }
    }

    return thumbnails;
  }

  private async extractVideoFrame(inputPath: string, size: number, quality: number): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const tempOutputFile = path.join(
        path.dirname(inputPath),
        `thumb-${Date.now()}-${Math.random().toString(36).substring(2)}.jpg`
      );

      ffmpeg(inputPath)
        .seekInput(1) // Seek to 1 second to avoid black frames
        .frames(1)
        .size(`${size}x${size}`)
        .aspect('1:1')
        .videoCodec('mjpeg')
        .outputOptions([
          '-q:v', quality.toString(),
          '-vf', `scale=${size}:${size}:force_original_aspect_ratio=decrease,pad=${size}:${size}:(ow-iw)/2:(oh-ih)/2:black`
        ])
        .output(tempOutputFile)
        .on('end', async () => {
          try {
            const buffer = await fs.readFile(tempOutputFile);
            await fs.unlink(tempOutputFile); // Clean up
            resolve(buffer);
          } catch (error) {
            reject(error);
          }
        })
        .on('error', (error) => {
          // Clean up on error
          fs.unlink(tempOutputFile).catch(() => {});
          reject(error);
        })
        .run();
    });
  }

  private getThumbnailFilename(originalFilename: string, size: number, format: string): string {
    const extension = path.extname(originalFilename);
    const baseName = path.basename(originalFilename, extension);
    return `${baseName}_thumb_${size}.${format}`;
  }

  private isImageType(mimetype: string): boolean {
    return mimetype.startsWith('image/') && !mimetype.includes('svg');
  }

  private isVideoType(mimetype: string): boolean {
    return mimetype.startsWith('video/');
  }

  // Get thumbnail by storage key
  async getThumbnail(storageKey: string): Promise<{ buffer: Buffer; mimetype: string; size: number }> {
    try {
      const result = await this.storageProvider.download(storageKey);
      
      return {
        buffer: result.buffer,
        mimetype: result.mimetype,
        size: result.size
      };
    } catch (error) {
      logger.error('Failed to get thumbnail', {
        error: error instanceof Error ? error.message : error,
        storageKey
      });
      throw error;
    }
  }

  // Delete thumbnails
  async deleteThumbnails(thumbnails: Record<string, ThumbnailResult>): Promise<void> {
    const deletePromises = Object.values(thumbnails).map(async (thumbnail) => {
      try {
        await this.storageProvider.delete(thumbnail.storageKey);
        logger.debug('Thumbnail deleted', { storageKey: thumbnail.storageKey });
      } catch (error) {
        logger.error('Failed to delete thumbnail', {
          error: error instanceof Error ? error.message : error,
          storageKey: thumbnail.storageKey
        });
      }
    });

    await Promise.allSettled(deletePromises);
  }

  // Check if file type supports thumbnail generation
  static supportsThumbnails(mimetype: string): boolean {
    return mimetype.startsWith('image/') && !mimetype.includes('svg') || 
           mimetype.startsWith('video/');
  }

  // Get supported image formats for thumbnails
  static getSupportedImageFormats(): string[] {
    return [
      'image/jpeg',
      'image/jpg',
      'image/png',
      'image/gif',
      'image/webp',
      'image/bmp',
      'image/tiff'
    ];
  }

  // Get supported video formats for thumbnails
  static getSupportedVideoFormats(): string[] {
    return [
      'video/mp4',
      'video/avi',
      'video/mov',
      'video/wmv',
      'video/flv',
      'video/webm',
      'video/mkv',
      'video/m4v'
    ];
  }

  // Validate thumbnail configuration
  static validateConfig(config: Partial<ThumbnailOptions>): boolean {
    if (config.sizes && (!Array.isArray(config.sizes) || config.sizes.some(s => s <= 0))) {
      return false;
    }

    if (config.quality && (config.quality < 1 || config.quality > 100)) {
      return false;
    }

    if (config.format && !['jpeg', 'png', 'webp'].includes(config.format)) {
      return false;
    }

    return true;
  }
}
