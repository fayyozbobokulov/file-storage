import { MongoClient, Db } from 'mongodb';
import { config } from '@/utils/config';
import { logger } from '@/utils/logger';

class DatabaseConnection {
  private client: MongoClient | null = null;
  private db: Db | null = null;
  private isConnected = false;

  async connect(): Promise<void> {
    try {
      if (this.isConnected && this.client && this.db) {
        return;
      }

      logger.info('Connecting to MongoDB...', { uri: config.mongodb.uri.replace(/\/\/[^@]+@/, '//***:***@') });
      
      this.client = new MongoClient(config.mongodb.uri, {
        maxPoolSize: 10,
        serverSelectionTimeoutMS: 5000,
        socketTimeoutMS: 45000,
      });

      await this.client.connect();
      this.db = this.client.db(config.mongodb.dbName);
      this.isConnected = true;

      // Test the connection
      await this.db.admin().ping();
      
      logger.info('Successfully connected to MongoDB', { database: config.mongodb.dbName });

      // Setup indexes
      await this.setupIndexes();

    } catch (error) {
      logger.error('Failed to connect to MongoDB', { error: error instanceof Error ? error.message : error });
      throw error;
    }
  }

  async disconnect(): Promise<void> {
    try {
      if (this.client) {
        await this.client.close();
        this.client = null;
        this.db = null;
        this.isConnected = false;
        logger.info('Disconnected from MongoDB');
      }
    } catch (error) {
      logger.error('Error disconnecting from MongoDB', { error: error instanceof Error ? error.message : error });
      throw error;
    }
  }

  getDb(): Db {
    if (!this.db || !this.isConnected) {
      throw new Error('Database not connected. Call connect() first.');
    }
    return this.db;
  }

  getClient(): MongoClient {
    if (!this.client || !this.isConnected) {
      throw new Error('Database not connected. Call connect() first.');
    }
    return this.client;
  }

  isHealthy(): boolean {
    return this.isConnected && this.client !== null && this.db !== null;
  }

  private async setupIndexes(): Promise<void> {
    try {
      const db = this.getDb();
      const filesCollection = db.collection('files');

      // Create indexes for better query performance
      await Promise.all([
        // Index for file ownership and permissions
        filesCollection.createIndex({ ownerId: 1 }),
        filesCollection.createIndex({ 'permissions.userId': 1 }),
        
        // Index for public files
        filesCollection.createIndex({ isPublic: 1 }),
        
        // Index for file metadata queries
        filesCollection.createIndex({ mimetype: 1 }),
        filesCollection.createIndex({ createdAt: -1 }),
        filesCollection.createIndex({ size: 1 }),
        
        // Index for text search
        filesCollection.createIndex({ 
          originalName: 'text', 
          description: 'text', 
          tags: 'text' 
        }),
        
        // Compound indexes for common queries
        filesCollection.createIndex({ ownerId: 1, createdAt: -1 }),
        filesCollection.createIndex({ ownerId: 1, mimetype: 1 }),
        filesCollection.createIndex({ isPublic: 1, createdAt: -1 }),
        
        // Index for storage key (unique)
        filesCollection.createIndex({ storageKey: 1 }, { unique: true }),
      ]);

      logger.info('Database indexes created successfully');
    } catch (error) {
      logger.error('Failed to create database indexes', { error: error instanceof Error ? error.message : error });
      // Don't throw here as the app can still function without indexes, just slower
    }
  }

  // Health check method
  async healthCheck(): Promise<{ status: string; database: string; connected: boolean }> {
    try {
      if (!this.isHealthy()) {
        return {
          status: 'unhealthy',
          database: config.mongodb.dbName,
          connected: false
        };
      }

      // Ping the database
      await this.getDb().admin().ping();
      
      return {
        status: 'healthy',
        database: config.mongodb.dbName,
        connected: true
      };
    } catch (error) {
      logger.error('Database health check failed', { error: error instanceof Error ? error.message : error });
      return {
        status: 'unhealthy',
        database: config.mongodb.dbName,
        connected: false
      };
    }
  }
}

// Singleton instance
export const dbConnection = new DatabaseConnection();

// Graceful shutdown
process.on('SIGINT', async () => {
  logger.info('Received SIGINT, closing database connection...');
  await dbConnection.disconnect();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  logger.info('Received SIGTERM, closing database connection...');
  await dbConnection.disconnect();
  process.exit(0);
});
