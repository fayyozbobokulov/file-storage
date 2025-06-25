import { Request, Response } from 'express';
import { generateToken, verifyToken, PERMISSIONS } from '@/middleware/auth';
import { logger } from '@/utils/logger';
import { z } from 'zod';
import { config } from '@/utils/config';

// Schema for token generation request
export const TokenRequestSchema = z.object({
  userId: z.string().min(1, 'User ID is required'),
  email: z.string().email(),
  role: z.string(),
  permissions: z.number().int().min(0).optional().default(0)
});

export class AuthController {
  /**
   * Generate JWT token (for development/testing)
   * In production, this would be replaced with proper authentication
   */
  async generateToken(req: Request, res: Response): Promise<void> {
    try {
      const validationResult = TokenRequestSchema.safeParse(req.body);
      
      if (!validationResult.success) {
        res.status(400).json({
          error: 'Invalid request data',
          message: 'Please check your request parameters',
          details: validationResult.error.errors
        });
        return;
      }

      const { userId, email, role, permissions } = validationResult.data;

      const token = generateToken({
        userId,
        email,
        role,
        permissions
      });

      logger.info('JWT token generated', {
        userId,
        email,
        role,
        permissions
      });

      res.json({
        success: true,
        data: {
          token,
          expiresIn: config.jwt.expiresIn
        },
        message: 'Token generated successfully'
      });
    } catch (error) {
      logger.error('Failed to generate token', {
        error: error instanceof Error ? error.message : error,
        body: req.body
      });

      res.status(500).json({
        error: 'Token generation failed',
        message: 'An error occurred while generating the token'
      });
    }
  }

  /**
   * Validate a JWT token
   */
  async validateToken(req: Request, res: Response): Promise<void> {
    try {
      const { token } = req.body;

      if (!token) {
        res.status(400).json({
          error: 'Missing token',
          message: 'Token is required for validation'
        });
        return;
      }

      const decoded = verifyToken(token);

      if (!decoded) {
        res.status(401).json({
          error: 'Invalid token',
          message: 'The provided token is invalid or expired'
        });
        return;
      }

      res.json({
        success: true,
        data: {
          valid: true,
          payload: decoded
        },
        message: 'Token is valid'
      });
    } catch (error) {
      logger.error('Token validation failed', {
        error: error instanceof Error ? error.message : error
      });

      res.status(500).json({
        error: 'Validation failed',
        message: 'An error occurred while validating the token'
      });
    }
  }

  /**
   * Get permission constants (for reference)
   */
  getPermissions(_req: Request, res: Response): void {
    res.json({
      success: true,
      data: PERMISSIONS,
      message: 'Permission constants retrieved successfully'
    });
  }
}

export default new AuthController();
