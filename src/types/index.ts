import { ObjectId } from 'mongodb';
import { z } from 'zod';

// Permission system types
export enum PermissionAction {
  READ = 0x01,
  WRITE = 0x02,
  OWNER = 0x04,
  DELETE = 0x08
}

export interface UserPermission {
  userId: string;
  actions: number; // Bitwise combination of PermissionAction
}

export interface GroupPermission {
  groupId: string;
  actions: number;
}

// File metadata types
export interface ThumbnailInfo {
  storageKey: string;
  mimetype: string;
  size: number;
}

export interface FileMetadata {
  _id?: ObjectId;
  originalName: string;
  storageKey: string;
  mimetype: string;
  size: number;
  ownerId: string;
  permissions: UserPermission[];
  isPublic: boolean;
  customPermissions?: Record<string, number>;
  createdAt: Date;
  updatedAt: Date;
  thumbnails?: Record<string, ThumbnailInfo>;
  tags?: string[];
  description?: string;
}

// Storage provider interface
export interface StorageProvider {
  upload(buffer: Buffer, filename: string, mimetype: string): Promise<StorageResult>;
  download(storageKey: string): Promise<DownloadResult>;
  delete(storageKey: string): Promise<void>;
  exists(storageKey: string): Promise<boolean>;
  getUrl?(storageKey: string, expiresIn?: number): Promise<string>;
}

export interface StorageResult {
  storageKey: string;
  size: number;
  mimetype: string;
  url?: string;
}

export interface DownloadResult {
  buffer: Buffer;
  mimetype: string;
  size: number;
}

// JWT and authentication types
export interface JWTPayload {
  jti?: string; // JWT ID
  userId: string;
  email?: string;
  role?: string;
  permissions?: number;
  iat?: number;
  exp?: number;
}

export interface SecureUrlPayload extends JWTPayload {
  fileId: string;
  action: 'download' | 'stream' | 'thumbnail';
  thumbnailSize?: string;
  expiresAt: number;
  singleUse?: boolean;
}

// API request/response types
export interface UploadRequest {
  file: Express.Multer.File;
  isPublic?: boolean;
  permissions?: UserPermission[];
  tags?: string[];
  description?: string;
}

export interface FileListQuery {
  page?: number | undefined;
  limit?: number | undefined;
  ownerId?: string | undefined;
  mimetype?: string | undefined;
  tags?: string[] | undefined;
  search?: string | undefined;
  sortBy?: 'createdAt' | 'size' | 'originalName' | undefined;
  sortOrder?: 'asc' | 'desc' | undefined;
}

export interface PermissionUpdateRequest {
  permissions: UserPermission[];
  isPublic?: boolean | undefined;
  customPermissions?: Record<string, number> | undefined;
}

// Zod validation schemas
export const FileMetadataSchema = z.object({
  originalName: z.string().min(1).max(255),
  storageKey: z.string().min(1),
  mimetype: z.string().min(1),
  size: z.number().positive(),
  ownerId: z.string().min(1),
  permissions: z.array(z.object({
    userId: z.string().min(1),
    actions: z.number().int().min(0).max(15)
  })),
  isPublic: z.boolean(),
  customPermissions: z.record(z.string(), z.number().int().min(0).max(15)).optional(),
  createdAt: z.date(),
  updatedAt: z.date(),
  thumbnails: z.record(z.string(), z.object({
    storageKey: z.string().min(1),
    mimetype: z.string().min(1),
    size: z.number().positive()
  })).optional(),
  tags: z.array(z.string()).optional(),
  description: z.string().max(1000).optional()
});

export const UploadRequestSchema = z.object({
  isPublic: z.boolean().optional().default(false),
  permissions: z.array(z.object({
    userId: z.string().min(1),
    actions: z.number().int().min(0).max(15)
  })).optional().default([]),
  tags: z.array(z.string()).optional().default([]),
  description: z.string().max(1000).optional()
});

export const FileListQuerySchema = z.object({
  page: z.coerce.number().min(1).default(1),
  limit: z.coerce.number().min(1).max(100).default(20),
  sortBy: z.enum(['createdAt', 'size', 'originalName']).default('createdAt'),
  sortOrder: z.enum(['asc', 'desc']).default('desc'),
  mimetype: z.string().optional(),
  ownerId: z.string().optional(),
  tags: z.array(z.string()).optional(),
  search: z.string().optional()
});

export const PermissionUpdateSchema = z.object({
  permissions: z.array(z.object({
    userId: z.string(),
    actions: z.number()
  })),
  isPublic: z.boolean().optional(),
  customPermissions: z.record(z.string(), z.number().int().min(0).max(15)).optional()
});

export const PermissionUpdateRequestSchema = z.object({
  isPublic: z.boolean().optional(),
  permissions: z.array(z.object({
    userId: z.string(),
    actions: z.number()
  })).optional()
});

export const JWTPayloadSchema = z.object({
  jti: z.string().optional(),
  userId: z.string(),
  email: z.string().optional(),
  role: z.string().optional(),
  permissions: z.number().optional(),
  iat: z.number().optional(),
  exp: z.number().optional()
});

// Error types
export class FileStorageError extends Error {
  constructor(
    message: string,
    public statusCode: number = 500,
    public code?: string
  ) {
    super(message);
    this.name = 'FileStorageError';
  }
}

export class PermissionError extends FileStorageError {
  constructor(message: string = 'Permission denied') {
    super(message, 403, 'PERMISSION_DENIED');
  }
}

export class FileNotFoundError extends FileStorageError {
  constructor(message: string = 'File not found') {
    super(message, 404, 'FILE_NOT_FOUND');
  }
}

export class ValidationError extends FileStorageError {
  constructor(message: string) {
    super(message, 400, 'VALIDATION_ERROR');
  }
}

export class StorageError extends FileStorageError {
  constructor(message: string) {
    super(message, 500, 'STORAGE_ERROR');
  }
}

// Configuration types
export interface AppConfig {
  port: number;
  nodeEnv: string;
  mongodb: {
    uri: string;
    dbName: string;
  };
  jwt: {
    secret: string;
    expiresIn: string;
  };
  storage: {
    provider: 'local' | 's3';
    local?: {
      storagePath: string;
      thumbnailsPath: string;
    };
    s3?: {
      accessKeyId: string;
      secretAccessKey: string;
      region: string;
      bucketName: string;
      thumbnailsBucket: string;
    };
  };
  upload: {
    maxFileSize: number;
    allowedMimeTypes: string[];
  };
  thumbnails: {
    sizes: number[];
    quality: number;
    format: 'jpeg' | 'png' | 'webp';
  };
  security: {
    corsOrigin: string;
    rateLimitWindowMs: number;
    rateLimitMaxRequests: number;
  };
  logging: {
    level: string;
    file?: string;
  };
}
