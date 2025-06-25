import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { JWTPayload } from '@/types';
import { config } from '@/utils/config';
import { logger } from '@/utils/logger';

// Extend Express Request type to include user
declare global {
  namespace Express {
    interface Request {
      user?: JWTPayload;
    }
  }
}

export interface AuthOptions {
  required?: boolean;
  permissions?: number[];
}

export const authenticateToken = (options: AuthOptions = { required: true }) => {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const token = req.headers.authorization;

      if (!token) {
        if (options.required) {
          logger.warn('Authentication required but no token provided', {
            path: req.path,
            method: req.method,
            ip: req.ip
          });
          res.status(401).json({
            error: 'Authentication required',
            message: 'Access token is required'
          });
          return;
        } else {
          // Token not required, continue without user
          next();
          return;
        }
      }

      // Verify token
      const decoded = jwt.verify(token, config.jwt.secret) as JWTPayload;
      
      // Validate token structure
      if (!decoded.userId || !decoded.permissions) {
        logger.warn('Invalid token structure', {
          tokenId: decoded.jti,
          userId: decoded.userId
        });
        res.status(401).json({
          error: 'Invalid token',
          message: 'Token structure is invalid'
        });
        return;
      }

      // Check if token is expired (additional check)
      if (decoded.exp && Date.now() >= decoded.exp * 1000) {
        logger.warn('Expired token used', {
          tokenId: decoded.jti,
          userId: decoded.userId,
          expiredAt: new Date(decoded.exp * 1000)
        });
        res.status(401).json({
          error: 'Token expired',
          message: 'Access token has expired'
        });
        return;
      }

      // Check required permissions
      if (options.permissions && options.permissions.length > 0) {
        const requiredPermissions = options.permissions;
        const hasPermissions = requiredPermissions.every(
          permission => ((decoded.permissions || 0) & permission) === permission
        );

        if (!hasPermissions) {
          logger.warn('Insufficient permissions', {
            userId: decoded.userId,
            requiredPermissions: options.permissions,
            userPermissions: decoded.permissions,
            path: req.path,
            method: req.method
          });
          res.status(403).json({
            error: 'Insufficient permissions',
            message: 'You do not have the required permissions for this action'
          });
          return;
        }
      }

      // Attach user to request
      req.user = decoded;

      logger.debug('User authenticated successfully', {
        userId: decoded.userId,
        permissions: decoded.permissions,
        tokenId: decoded.jti
      });

      next();
    } catch (error) {
      if (error instanceof jwt.JsonWebTokenError) {
        logger.warn('Invalid JWT token', {
          error: error.message,
          path: req.path,
          method: req.method,
          ip: req.ip
        });
        res.status(401).json({
          error: 'Invalid token',
          message: 'Access token is invalid or malformed'
        });
        return;
      }

      if (error instanceof jwt.TokenExpiredError) {
        logger.warn('Expired JWT token', {
          error: error.message,
          expiredAt: error.expiredAt,
          path: req.path,
          method: req.method,
          ip: req.ip
        });
        res.status(401).json({
          error: 'Token expired',
          message: 'Access token has expired'
        });
        return;
      }

      logger.error('Authentication error', {
        error: error instanceof Error ? error.message : error,
        path: req.path,
        method: req.method,
        ip: req.ip
      });

      res.status(500).json({
        error: 'Authentication error',
        message: 'An error occurred during authentication'
      });
    }
  };
};

// Convenience middleware for required authentication
export const requireAuth = authenticateToken({ required: true });

// Convenience middleware for optional authentication
export const optionalAuth = authenticateToken({ required: false });

// Middleware to require specific permissions
export const requirePermissions = (permissions: number[]) => {
  return authenticateToken({ required: true, permissions });
};

// Permission constants for convenience
export const PERMISSIONS = {
  READ: 0x01,
  WRITE: 0x02,
  DELETE: 0x04,
  OWNER: 0x08,
  ADMIN: 0x10
} as const;

// Utility function to generate JWT tokens (for testing/development)
export const generateToken = (payload: { userId: string; email?: string; role?: string; permissions?: number }): string => {
  const tokenPayload: JWTPayload = {
    userId: payload.userId,
    email: payload.email || '',
    role: payload.role || 'user',
    permissions: payload.permissions || 0,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + Number(config.jwt.expiresIn),
  };

  return jwt.sign(tokenPayload, config.jwt.secret);
};

// Utility function to verify and decode token without middleware
export const verifyToken = (token: string): JWTPayload | null => {
  try {
    const decoded = jwt.verify(token, config.jwt.secret) as JWTPayload;
    return decoded;
  } catch (error) {
    logger.debug('Token verification failed', {
      error: error instanceof Error ? error.message : error
    });
    return null;
  }
};

// Middleware to extract user ID from token for logging purposes
export const extractUserId = (req: Request, _res: Response, next: NextFunction): void => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];

    if (token) {
      const decoded = verifyToken(token);
      if (decoded) {
        // Add user ID to request for logging
        (req as any).userId = decoded.userId;
      }
    }
  } catch (error) {
    // Ignore errors in user ID extraction
  }
  
  next();
};

// Rate limiting by user ID
export const createUserRateLimit = (windowMs: number, max: number) => {
  const userRequests = new Map<string, { count: number; resetTime: number }>();

  return (req: Request, res: Response, next: NextFunction): void => {
    const userId = req.user?.userId || req.ip || 'anonymous';
    const now = Date.now();

    // Clean up expired entries
    for (const [key, value] of userRequests.entries()) {
      if (now > value.resetTime) {
        userRequests.delete(key);
      }
    }

    const userLimit = userRequests.get(userId);
    
    if (!userLimit) {
      userRequests.set(userId, {
        count: 1,
        resetTime: now + windowMs
      });
      next();
      return;
    }

    if (userLimit.count >= max) {
      logger.warn('Rate limit exceeded', {
        userId,
        count: userLimit.count,
        max,
        path: req.path,
        method: req.method
      });

      res.status(429).json({
        error: 'Rate limit exceeded',
        message: `Too many requests. Try again in ${Math.ceil((userLimit.resetTime - now) / 1000)} seconds.`,
        retryAfter: Math.ceil((userLimit.resetTime - now) / 1000)
      });
      return;
    }

    userLimit.count++;
    next();
  };
};
