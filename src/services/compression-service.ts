import { createGzip, createDeflate, createBrotliCompress } from 'zlib';
import { pipeline } from 'stream/promises';
import { Readable, PassThrough } from 'stream';
import { logger } from '@/utils/logger';

export type CompressionType = 'gzip' | 'deflate' | 'br' | 'none';

export interface CompressionOptions {
  type: CompressionType;
  level?: number; // Compression level (1-9 for gzip/deflate, 0-11 for brotli)
  threshold?: number; // Minimum file size to compress (default: 1024 bytes)
}

export interface CompressionResult {
  compressed: boolean;
  originalSize: number;
  compressedSize?: number;
  compressionRatio?: number;
  encoding?: string;
}

export class CompressionService {
  private static readonly DEFAULT_THRESHOLD = 1024; // 1KB
  private static readonly COMPRESSIBLE_TYPES = [
    'text/',
    'application/json',
    'application/javascript',
    'application/xml',
    'application/xhtml+xml',
    'application/rss+xml',
    'application/atom+xml',
    'image/svg+xml',
    'application/pdf', // PDFs can benefit from compression
    'application/msword',
    'application/vnd.openxmlformats-officedocument'
  ];

  /**
   * Check if a MIME type is compressible
   */
  static isCompressible(mimetype: string): boolean {
    return this.COMPRESSIBLE_TYPES.some(type => mimetype.startsWith(type));
  }

  /**
   * Determine the best compression type based on client Accept-Encoding header
   */
  static getBestCompression(acceptEncoding?: string): CompressionType {
    if (!acceptEncoding) {
      return 'none';
    }

    const encoding = acceptEncoding.toLowerCase();
    
    // Prefer Brotli for better compression
    if (encoding.includes('br')) {
      return 'br';
    }
    
    // Then gzip for good compression and wide support
    if (encoding.includes('gzip')) {
      return 'gzip';
    }
    
    // Fallback to deflate
    if (encoding.includes('deflate')) {
      return 'deflate';
    }
    
    return 'none';
  }

  /**
   * Compress a buffer
   */
  async compressBuffer(
    buffer: Buffer, 
    mimetype: string, 
    options: CompressionOptions
  ): Promise<{ buffer: Buffer; result: CompressionResult }> {
    const originalSize = buffer.length;
    
    // Check if compression should be applied
    if (!this.shouldCompress(buffer, mimetype, options)) {
      return {
        buffer,
        result: {
          compressed: false,
          originalSize,
          compressionRatio: 1
        }
      };
    }

    try {
      const compressedBuffer = await this.performCompression(buffer, options);
      const compressedSize = compressedBuffer.length;
      const compressionRatio = originalSize / compressedSize;

      // Only use compression if it actually reduces size significantly
      if (compressedSize >= originalSize * 0.95) {
        logger.debug('Compression not beneficial, using original', {
          originalSize,
          compressedSize,
          mimetype,
          compressionType: options.type
        });
        
        return {
          buffer,
          result: {
            compressed: false,
            originalSize,
            compressionRatio: 1
          }
        };
      }

      logger.info('File compressed successfully', {
        originalSize,
        compressedSize,
        compressionRatio: Math.round(compressionRatio * 100) / 100,
        mimetype,
        compressionType: options.type,
        spaceSaved: originalSize - compressedSize
      });

      return {
        buffer: compressedBuffer,
        result: {
          compressed: true,
          originalSize,
          compressedSize,
          compressionRatio,
          encoding: options.type
        }
      };
    } catch (error) {
      logger.error('Compression failed, using original buffer', {
        error: error instanceof Error ? error.message : error,
        originalSize,
        mimetype,
        compressionType: options.type
      });

      return {
        buffer,
        result: {
          compressed: false,
          originalSize,
          compressionRatio: 1
        }
      };
    }
  }

  /**
   * Compress a stream
   */
  async compressStream(
    inputStream: Readable,
    mimetype: string,
    options: CompressionOptions
  ): Promise<{ stream: Readable; result: CompressionResult }> {
    // For streams, we can't easily check size beforehand
    // So we'll apply compression if the type is compressible
    if (options.type === 'none' || !CompressionService.isCompressible(mimetype)) {
      return {
        stream: inputStream,
        result: {
          compressed: false,
          originalSize: 0 // Unknown for streams
        }
      };
    }

    try {
      const compressionStream = this.createCompressionStream(options);
      const outputStream = new PassThrough();

      // Pipeline the streams
      pipeline(inputStream, compressionStream, outputStream).catch(error => {
        logger.error('Stream compression pipeline failed', {
          error: error instanceof Error ? error.message : error,
          mimetype,
          compressionType: options.type
        });
      });

      logger.info('Stream compression initiated', {
        mimetype,
        compressionType: options.type
      });

      return {
        stream: outputStream,
        result: {
          compressed: true,
          originalSize: 0, // Unknown for streams
          encoding: options.type
        }
      };
    } catch (error) {
      logger.error('Failed to setup stream compression', {
        error: error instanceof Error ? error.message : error,
        mimetype,
        compressionType: options.type
      });

      return {
        stream: inputStream,
        result: {
          compressed: false,
          originalSize: 0
        }
      };
    }
  }

  /**
   * Check if compression should be applied
   */
  private shouldCompress(buffer: Buffer, mimetype: string, options: CompressionOptions): boolean {
    // Don't compress if type is 'none'
    if (options.type === 'none') {
      return false;
    }

    // Check file size threshold
    const threshold = options.threshold || CompressionService.DEFAULT_THRESHOLD;
    if (buffer.length < threshold) {
      return false;
    }

    // Check if MIME type is compressible
    if (!CompressionService.isCompressible(mimetype)) {
      return false;
    }

    return true;
  }

  /**
   * Perform the actual compression
   */
  private async performCompression(buffer: Buffer, options: CompressionOptions): Promise<Buffer> {
    const compressionStream = this.createCompressionStream(options);
    const chunks: Buffer[] = [];

    return new Promise((resolve, reject) => {
      compressionStream.on('data', (chunk: Buffer) => {
        chunks.push(chunk);
      });

      compressionStream.on('end', () => {
        resolve(Buffer.concat(chunks));
      });

      compressionStream.on('error', (error) => {
        reject(error);
      });

      compressionStream.write(buffer);
      compressionStream.end();
    });
  }

  /**
   * Create appropriate compression stream
   */
  private createCompressionStream(options: CompressionOptions) {
    const level = options.level;

    switch (options.type) {
      case 'gzip':
        return createGzip({ level });
      case 'deflate':
        return createDeflate({ level });
      case 'br':
        return createBrotliCompress({ 
          params: level !== undefined ? {
            [require('zlib').constants.BROTLI_PARAM_QUALITY]: level
          } : undefined
        });
      default:
        throw new Error(`Unsupported compression type: ${options.type}`);
    }
  }

  /**
   * Get compression headers for response
   */
  static getCompressionHeaders(result: CompressionResult): Record<string, string> {
    const headers: Record<string, string> = {};

    if (result.compressed && result.encoding) {
      headers['Content-Encoding'] = result.encoding;
      headers['Vary'] = 'Accept-Encoding';
    }

    // Add custom headers for debugging/monitoring
    headers['X-Compression-Applied'] = result.compressed ? 'true' : 'false';
    
    if (result.compressed && result.compressionRatio) {
      headers['X-Compression-Ratio'] = result.compressionRatio.toFixed(2);
    }

    if (result.compressedSize !== undefined) {
      headers['X-Original-Size'] = result.originalSize.toString();
      headers['X-Compressed-Size'] = result.compressedSize.toString();
    }

    return headers;
  }
}
