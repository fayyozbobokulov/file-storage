import { config } from './config';

export enum LogLevel {
  ERROR = 0,
  WARN = 1,
  INFO = 2,
  DEBUG = 3
}

class Logger {
  private level: LogLevel;

  constructor() {
    this.level = this.parseLogLevel(config.logging.level);
  }

  private parseLogLevel(level: string): LogLevel {
    switch (level.toLowerCase()) {
      case 'error': return LogLevel.ERROR;
      case 'warn': return LogLevel.WARN;
      case 'info': return LogLevel.INFO;
      case 'debug': return LogLevel.DEBUG;
      default: return LogLevel.INFO;
    }
  }

  private formatMessage(level: string, message: string, meta?: any): string {
    const timestamp = new Date().toISOString();
    const metaStr = meta ? ` ${JSON.stringify(meta)}` : '';
    return `[${timestamp}] ${level.toUpperCase()}: ${message}${metaStr}`;
  }

  private log(level: LogLevel, levelName: string, message: string, meta?: any): void {
    if (level <= this.level) {
      const formattedMessage = this.formatMessage(levelName, message, meta);
      
      if (level === LogLevel.ERROR) {
        console.error(formattedMessage);
      } else if (level === LogLevel.WARN) {
        console.warn(formattedMessage);
      } else {
        console.log(formattedMessage);
      }

      // TODO: Implement file logging if config.logging.file is set
      if (config.logging.file) {
        // File logging implementation would go here
      }
    }
  }

  error(message: string, meta?: any): void {
    this.log(LogLevel.ERROR, 'error', message, meta);
  }

  warn(message: string, meta?: any): void {
    this.log(LogLevel.WARN, 'warn', message, meta);
  }

  info(message: string, meta?: any): void {
    this.log(LogLevel.INFO, 'info', message, meta);
  }

  debug(message: string, meta?: any): void {
    this.log(LogLevel.DEBUG, 'debug', message, meta);
  }

  // Audit logging for security events
  audit(action: string, userId: string, fileId?: string, details?: any): void {
    this.info(`AUDIT: ${action}`, {
      userId,
      fileId,
      timestamp: new Date().toISOString(),
      ...details
    });
  }
}

export const logger = new Logger();
