import exifr from 'exifr';
import sharp from 'sharp';
import { fileTypeFromBuffer } from 'file-type';
import { parseBuffer as parseAudioMetadata } from 'music-metadata';
import pdfParse from 'pdf-parse';
import { logger } from '@/utils/logger';

export interface ExtractedMetadata {
  // Basic file info
  fileType?: {
    ext: string;
    mime: string;
  };
  
  // Image dimensions and properties
  dimensions?: {
    width: number;
    height: number;
    channels: number;
    density: number;
    hasAlpha: boolean;
    hasProfile: boolean;
  };

  // EXIF data
  exif?: {
    // Camera info
    make?: string;
    model?: string;
    software?: string;
    
    // Image settings
    iso?: number;
    fNumber?: number;
    exposureTime?: number;
    focalLength?: number;
    flash?: string;
    whiteBalance?: string;
    
    // Date/time
    dateTime?: string;
    dateTimeOriginal?: string;
    dateTimeDigitized?: string;
    
    // Orientation
    orientation?: number;
    
    // Color space
    colorSpace?: string;
    
    // Resolution
    xResolution?: number;
    yResolution?: number;
    resolutionUnit?: string;
  };

  // GPS/Location data
  gps?: {
    latitude?: number;
    longitude?: number;
    altitude?: number;
    latitudeRef?: string;
    longitudeRef?: string;
    altitudeRef?: number;
    timestamp?: string;
    datestamp?: string;
    mapDatum?: string;
    processingMethod?: string;
  };

  // Additional technical metadata
  technical?: {
    compression?: string;
    bitsPerSample?: number[];
    samplesPerPixel?: number;
    photometricInterpretation?: string;
    planarConfiguration?: string;
    artist?: string;
    copyright?: string;
    imageDescription?: string;
    userComment?: string;
  };

  // Video metadata (if applicable)
  video?: {
    duration?: number;
    frameRate?: number;
    bitRate?: number;
    codec?: string;
    resolution?: string;
  };

  // Audio metadata (if applicable)
  audio?: {
    duration?: number | undefined;
    bitRate?: number | undefined;
    sampleRate?: number | undefined;
    channels?: number | undefined;
    codec?: string | undefined;
    title?: string | undefined;
    artist?: string | undefined;
    album?: string | undefined;
    year?: number | undefined;
    genre?: string | undefined;
  };

  // Document metadata (if applicable)
  document?: {
    title?: string;
    author?: string;
    subject?: string;
    creator?: string;
    producer?: string;
    creationDate?: string;
    modificationDate?: string;
    keywords?: string[];
    pageCount?: number;
  };
}

export class MetadataExtractor {
  /**
   * Extract comprehensive metadata from file buffer
   */
  async extractMetadata(buffer: Buffer, filename: string, mimetype: string): Promise<ExtractedMetadata> {
    const metadata: ExtractedMetadata = {};

    try {
      logger.info('Starting metadata extraction', {
        filename,
        mimetype,
        bufferSize: buffer.length
      });

      // Extract file type information
      await this.extractFileType(buffer, metadata);

      // Extract image metadata if it's an image
      if (this.isImage(mimetype)) {
        await this.extractImageMetadata(buffer, metadata);
        await this.extractExifData(buffer, metadata);
      }

      // Extract video metadata if it's a video
      if (this.isVideo(mimetype)) {
        await this.extractVideoMetadata(buffer, metadata);
      }

      // Extract audio metadata if it's audio
      if (this.isAudio(mimetype)) {
        await this.extractAudioMetadata(buffer, metadata);
      }

      // Extract document metadata if it's a document
      if (this.isDocument(mimetype)) {
        await this.extractDocumentMetadata(buffer, metadata);
      }

      logger.info('Metadata extraction completed', {
        filename,
        hasExif: !!metadata.exif,
        hasGps: !!metadata.gps,
        hasDimensions: !!metadata.dimensions,
        extractedFields: Object.keys(metadata)
      });

      return metadata;
    } catch (error) {
      logger.error('Failed to extract metadata', {
        error: error instanceof Error ? error.message : error,
        filename,
        mimetype
      });
      return metadata; // Return partial metadata even if extraction fails
    }
  }

  /**
   * Extract file type information
   */
  private async extractFileType(buffer: Buffer, metadata: ExtractedMetadata): Promise<void> {
    try {
      const fileType = await fileTypeFromBuffer(buffer);
      if (fileType) {
        metadata.fileType = {
          ext: fileType.ext,
          mime: fileType.mime
        };
      }
    } catch (error) {
      logger.warn('Failed to extract file type', {
        error: error instanceof Error ? error.message : error
      });
    }
  }

  /**
   * Extract image metadata using Sharp
   */
  private async extractImageMetadata(buffer: Buffer, metadata: ExtractedMetadata): Promise<void> {
    try {
      const image = sharp(buffer);
      const imageMetadata = await image.metadata();

      metadata.dimensions = {
        width: imageMetadata.width || 0,
        height: imageMetadata.height || 0,
        channels: imageMetadata.channels || 0,
        density: imageMetadata.density || 0,
        hasAlpha: imageMetadata.hasAlpha || false,
        hasProfile: imageMetadata.hasProfile || false
      };

      logger.debug('Extracted image dimensions', metadata.dimensions);
    } catch (error) {
      logger.warn('Failed to extract image metadata with Sharp', {
        error: error instanceof Error ? error.message : error
      });
    }
  }

  /**
   * Extract comprehensive EXIF data
   */
  private async extractExifData(buffer: Buffer, metadata: ExtractedMetadata): Promise<void> {
    try {
      // Extract all available EXIF data
      const exifData = await exifr.parse(buffer, {
        tiff: true,
        exif: true,
        gps: true,
        interop: true,
        ifd1: true,
        iptc: true,
        icc: true,
        jfif: true,
        ihdr: true,
        xmp: true,
        pick: [
          // Camera info
          'Make', 'Model', 'Software', 'LensModel', 'LensMake',
          
          // Image settings
          'ISO', 'FNumber', 'ExposureTime', 'FocalLength', 'Flash', 'WhiteBalance',
          'ExposureMode', 'MeteringMode', 'SceneCaptureType', 'Contrast', 'Saturation',
          'Sharpness', 'DigitalZoomRatio', 'ExposureBiasValue',
          
          // Date/time
          'DateTime', 'DateTimeOriginal', 'DateTimeDigitized', 'SubSecTime',
          'SubSecTimeOriginal', 'SubSecTimeDigitized',
          
          // Orientation and color
          'Orientation', 'ColorSpace', 'ComponentsConfiguration',
          
          // Resolution
          'XResolution', 'YResolution', 'ResolutionUnit',
          
          // GPS data
          'GPSLatitude', 'GPSLongitude', 'GPSAltitude', 'GPSLatitudeRef',
          'GPSLongitudeRef', 'GPSAltitudeRef', 'GPSTimeStamp', 'GPSDateStamp',
          'GPSMapDatum', 'GPSProcessingMethod', 'GPSAreaInformation',
          
          // Additional metadata
          'Artist', 'Copyright', 'ImageDescription', 'UserComment',
          'Compression', 'BitsPerSample', 'SamplesPerPixel',
          'PhotometricInterpretation', 'PlanarConfiguration'
        ]
      });

      if (exifData) {
        // Basic EXIF data
        metadata.exif = {
          make: exifData.Make,
          model: exifData.Model,
          software: exifData.Software,
          iso: exifData.ISO,
          fNumber: exifData.FNumber,
          exposureTime: exifData.ExposureTime,
          focalLength: exifData.FocalLength,
          flash: exifData.Flash,
          whiteBalance: exifData.WhiteBalance,
          dateTime: exifData.DateTime,
          dateTimeOriginal: exifData.DateTimeOriginal,
          dateTimeDigitized: exifData.DateTimeDigitized,
          orientation: exifData.Orientation,
          colorSpace: exifData.ColorSpace,
          xResolution: exifData.XResolution,
          yResolution: exifData.YResolution,
          resolutionUnit: exifData.ResolutionUnit
        };

        // GPS data
        if (exifData.GPSLatitude && exifData.GPSLongitude) {
          metadata.gps = {
            latitude: exifData.GPSLatitude,
            longitude: exifData.GPSLongitude,
            altitude: exifData.GPSAltitude,
            latitudeRef: exifData.GPSLatitudeRef,
            longitudeRef: exifData.GPSLongitudeRef,
            altitudeRef: exifData.GPSAltitudeRef,
            timestamp: exifData.GPSTimeStamp,
            datestamp: exifData.GPSDateStamp,
            mapDatum: exifData.GPSMapDatum,
            processingMethod: exifData.GPSProcessingMethod
          };
        }

        // Technical metadata
        metadata.technical = {
          compression: exifData.Compression,
          bitsPerSample: exifData.BitsPerSample,
          samplesPerPixel: exifData.SamplesPerPixel,
          photometricInterpretation: exifData.PhotometricInterpretation,
          planarConfiguration: exifData.PlanarConfiguration,
          artist: exifData.Artist,
          copyright: exifData.Copyright,
          imageDescription: exifData.ImageDescription,
          userComment: exifData.UserComment
        };

        logger.debug('Extracted EXIF data', {
          hasGps: !!metadata.gps,
          hasCameraInfo: !!(metadata.exif.make || metadata.exif.model),
          hasDateTime: !!metadata.exif.dateTimeOriginal
        });
      }
    } catch (error) {
      logger.warn('Failed to extract EXIF data', {
        error: error instanceof Error ? error.message : error
      });
    }
  }

  /**
   * Extract video metadata (placeholder - would need additional libraries like ffprobe)
   */
  private async extractVideoMetadata(_buffer: Buffer, metadata: ExtractedMetadata): Promise<void> {
    try {
      // This would require additional libraries like node-ffmpeg or ffprobe-static
      // For now, we'll just log that video metadata extraction is not implemented
      logger.info('Video metadata extraction not yet implemented');
      
      metadata.video = {
        // Placeholder - would extract actual video metadata
      };
    } catch (error) {
      logger.warn('Failed to extract video metadata', {
        error: error instanceof Error ? error.message : error
      });
    }
  }

  /**
   * Extract audio metadata using music-metadata
   */
  private async extractAudioMetadata(buffer: Buffer, metadata: ExtractedMetadata): Promise<void> {
    try {
      const audioMetadata = await parseAudioMetadata(buffer);

      metadata.audio = {
        duration: audioMetadata.format.duration || undefined,
        bitRate: audioMetadata.format.bitrate || undefined,
        sampleRate: audioMetadata.format.sampleRate || undefined,
        channels: audioMetadata.format.numberOfChannels || undefined,
        codec: audioMetadata.format.codec || undefined,
        title: audioMetadata.common.title || undefined,
        artist: audioMetadata.common.artist || undefined,
        album: audioMetadata.common.album || undefined,
        year: audioMetadata.common.year || undefined,
        genre: audioMetadata.common.genre ? audioMetadata.common.genre.join(', ') : undefined
      };

      logger.debug('Extracted audio metadata', {
        duration: metadata.audio?.duration,
        bitRate: metadata.audio?.bitRate,
        title: metadata.audio?.title,
        artist: metadata.audio?.artist
      });
    } catch (error) {
      logger.warn('Failed to extract audio metadata', {
        error: error instanceof Error ? error.message : error
      });
    }
  }

  /**
   * Extract document metadata using pdf-parse for PDFs
   */
  private async extractDocumentMetadata(buffer: Buffer, metadata: ExtractedMetadata): Promise<void> {
    try {
      // Handle PDF files
      if (buffer.subarray(0, 4).toString() === '%PDF') {
        const pdfData = await pdfParse(buffer);
        
        metadata.document = {
          title: pdfData.info?.Title,
          author: pdfData.info?.Author,
          subject: pdfData.info?.Subject,
          creator: pdfData.info?.Creator,
          producer: pdfData.info?.Producer,
          creationDate: pdfData.info?.CreationDate,
          modificationDate: pdfData.info?.ModDate,
          keywords: pdfData.info?.Keywords ? pdfData.info.Keywords.split(',').map((k: string) => k.trim()) : undefined,
          pageCount: pdfData.numpages
        };

        logger.debug('Extracted PDF metadata', {
          title: metadata.document.title,
          author: metadata.document.author,
          pageCount: metadata.document.pageCount
        });
      } else {
        logger.info('Document metadata extraction only supports PDF files currently');
      }
    } catch (error) {
      logger.warn('Failed to extract document metadata', {
        error: error instanceof Error ? error.message : error
      });
    }
  }

  /**
   * Check if file is an image
   */
  private isImage(mimetype: string): boolean {
    return mimetype.startsWith('image/');
  }

  /**
   * Check if file is a video
   */
  private isVideo(mimetype: string): boolean {
    return mimetype.startsWith('video/');
  }

  /**
   * Check if file is audio
   */
  private isAudio(mimetype: string): boolean {
    return mimetype.startsWith('audio/');
  }

  /**
   * Check if file is a document
   */
  private isDocument(mimetype: string): boolean {
    return mimetype.includes('pdf') || 
           mimetype.includes('document') || 
           mimetype.includes('text') ||
           mimetype.includes('spreadsheet') ||
           mimetype.includes('presentation');
  }
}
