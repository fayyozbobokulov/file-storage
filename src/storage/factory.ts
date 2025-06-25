import { StorageProvider } from '@/types';
import { LocalStorageProvider } from './local-provider';
import { S3StorageProvider } from './s3-provider';
import { config } from '@/utils/config';
import { logger } from '@/utils/logger';

export class StorageFactory {
  private static instance: StorageProvider | null = null;

  static getProvider(): StorageProvider {
    if (!this.instance) {
      this.instance = this.createProvider();
    }
    return this.instance;
  }

  private static createProvider(): StorageProvider {
    const providerType = config.storage.provider;

    logger.info('Initializing storage provider', { provider: providerType });

    switch (providerType) {
      case 'local':
        return new LocalStorageProvider();
      
      case 's3':
        return new S3StorageProvider();
      
      default:
        logger.error('Unknown storage provider', { provider: providerType });
        throw new Error(`Unsupported storage provider: ${providerType}`);
    }
  }

  // For testing purposes - allows resetting the singleton
  static reset(): void {
    this.instance = null;
    logger.info('Storage provider reset');
  }

  // Get provider type
  static getProviderType(): string {
    return config.storage.provider;
  }

  // Health check for the current provider
  static async healthCheck(): Promise<{ healthy: boolean; provider: string; details?: any }> {
    try {
      const provider = this.getProvider();
      
      // Basic health check - try to check if provider exists
      if (provider.exists) {
        // For providers that support existence check, use a dummy key
        await provider.exists('health-check-dummy');
      }

      return {
        healthy: true,
        provider: config.storage.provider,
        details: {
          type: config.storage.provider,
          timestamp: new Date().toISOString()
        }
      };
    } catch (error) {
      logger.error('Storage provider health check failed', {
        error: error instanceof Error ? error.message : error,
        provider: config.storage.provider
      });

      return {
        healthy: false,
        provider: config.storage.provider,
        details: {
          error: error instanceof Error ? error.message : error,
          timestamp: new Date().toISOString()
        }
      };
    }
  }
}

// Export a convenience function to get the provider
export const getStorageProvider = (): StorageProvider => {
  return StorageFactory.getProvider();
};
