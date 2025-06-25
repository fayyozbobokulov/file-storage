import { Router } from 'express';
import authController from '@/controllers/auth-controller';

const router = Router();

/**
 * Auth routes
 * 
 * These routes handle authentication-related operations:
 * - Token generation (for development/testing)
 * - Token validation
 * - Permission constants reference
 */

// Generate JWT token (for development/testing)
router.post('/token', authController.generateToken.bind(authController));

// Validate token
router.post('/validate', authController.validateToken.bind(authController));

// Get permission constants (for reference)
router.get('/permissions', authController.getPermissions.bind(authController));

export default router;
