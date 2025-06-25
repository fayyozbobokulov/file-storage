import sharp from 'sharp';
import { logger } from '@/utils/logger';

export interface MetadataProcessingOptions {
  preserveMetadata?: boolean; // Preserve all metadata (default: false for privacy)
  preserveExif?: boolean; // Legacy option - not fully implemented
  preserveIcc?: boolean; // Legacy option - not fully implemented  
  preserveOrientation?: boolean; // Handle image orientation (default: true)
  stripGps?: boolean; // Strip GPS data even when preserving metadata (default: true)
}

export class MetadataProcessor {
  /**
   * Process image buffer based on metadata preservation options
   * By default, strips all metadata for privacy and security
   * 
   * Note: This implementation focuses on reliable metadata stripping rather than
   * selective preservation due to Sharp library limitations with buffer-based metadata.
   */
  async processImageBuffer(
    buffer: Buffer, 
    mimetype: string, 
    options: MetadataProcessingOptions = {}
  ): Promise<Buffer> {
    try {
      // Only process images
      if (!this.isImage(mimetype)) {
        return buffer;
      }

      const {
        preserveMetadata = false,
        preserveExif = false,
        preserveIcc = false,
        preserveOrientation = true, // Keep orientation by default for proper display
        stripGps = true // Strip GPS by default for privacy
      } = options;

      // If preserveMetadata is true, return original buffer (unless GPS stripping is requested)
      if (preserveMetadata && !stripGps) {
        logger.debug('Preserving all metadata as requested');
        return buffer;
      }

      const image = sharp(buffer);
      
      // Get image metadata to understand what we're working with
      const metadata = await image.metadata();
      
      logger.debug('Processing image metadata', {
        format: metadata.format,
        width: metadata.width,
        height: metadata.height,
        hasExif: !!metadata.exif,
        hasIcc: !!metadata.icc,
        orientation: metadata.orientation,
        preserveMetadata,
        preserveExif,
        preserveIcc,
        preserveOrientation,
        stripGps
      });

      // Configure Sharp processing options
      let processedImage = image;

      // Handle metadata preservation/stripping
      if (!preserveMetadata) {
        // Strip all metadata by default
        processedImage = processedImage.withMetadata({});
        
        // Note: Selective metadata preservation (EXIF, ICC) is complex with Sharp
        // as it expects specific formats. For now, we focus on complete stripping
        // or complete preservation for privacy/security purposes.
        
        if (preserveExif || preserveIcc) {
          logger.info('Selective metadata preservation not fully supported - metadata stripped for security');
        }
        
        // Handle orientation separately if needed
        if (!preserveOrientation && metadata.orientation && metadata.orientation !== 1) {
          // Apply the orientation transformation and remove the EXIF orientation tag
          processedImage = processedImage.rotate();
        }
      } else if (stripGps) {
        // Preserve metadata but strip GPS data
        // This is a simplified approach that removes all EXIF (including GPS)
        processedImage = await this.stripGpsData(processedImage);
      }

      // Convert back to buffer
      const processedBuffer = await processedImage.toBuffer();

      logger.info('Image metadata processed', {
        originalSize: buffer.length,
        processedSize: processedBuffer.length,
        sizeDifference: buffer.length - processedBuffer.length,
        preserveMetadata,
        stripGps
      });

      return processedBuffer;
    } catch (error) {
      logger.error('Failed to process image metadata', {
        error: error instanceof Error ? error.message : error,
        mimetype,
        options
      });
      
      // Return original buffer if processing fails
      return buffer;
    }
  }

  /**
   * Strip GPS data from image while preserving other metadata
   * This removes all EXIF data (which includes GPS) but keeps the image displayable
   */
  private async stripGpsData(image: sharp.Sharp): Promise<sharp.Sharp> {
    try {
      logger.debug('Stripping GPS data from image');
      
      // Remove all metadata to ensure GPS is stripped
      // This is the safest approach to guarantee privacy
      return image.withMetadata({});
    } catch (error) {
      logger.warn('Failed to strip GPS data, removing all metadata', {
        error: error instanceof Error ? error.message : error
      });
      // Fallback: remove all metadata
      return image.withMetadata({});
    }
  }

  /**
   * Get metadata processing options from query parameters
   */
  parseMetadataOptions(query: any): MetadataProcessingOptions {
    return {
      preserveMetadata: this.parseBoolean(query.preserveMetadata, false),
      preserveExif: this.parseBoolean(query.preserveExif, false),
      preserveIcc: this.parseBoolean(query.preserveIcc, false),
      preserveOrientation: this.parseBoolean(query.preserveOrientation, true),
      stripGps: this.parseBoolean(query.stripGps, true)
    };
  }

  /**
   * Parse boolean from query parameter
   */
  private parseBoolean(value: any, defaultValue: boolean): boolean {
    if (value === undefined || value === null) {
      return defaultValue;
    }
    
    if (typeof value === 'boolean') {
      return value;
    }
    
    if (typeof value === 'string') {
      return value.toLowerCase() === 'true' || value === '1';
    }
    
    return defaultValue;
  }

  /**
   * Check if file is an image
   */
  private isImage(mimetype: string): boolean {
    return mimetype.startsWith('image/');
  }

  /**
   * Get metadata summary for response headers
   */
  getMetadataSummary(options: MetadataProcessingOptions): string {
    const summary = [];
    
    if (options.preserveMetadata) {
      summary.push('metadata-preserved');
    } else {
      summary.push('metadata-stripped');
    }
    
    if (options.stripGps) {
      summary.push('gps-removed');
    }
    
    if (options.preserveOrientation) {
      summary.push('orientation-preserved');
    }
    
    return summary.join(', ');
  }
}
