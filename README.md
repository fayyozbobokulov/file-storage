# File Storage Service

A secure, extensible file storage and serving backend built with Node.js, Express, TypeScript, and MongoDB. Supports multiple storage backends (Local FS, S3), JWT-based authentication, granular permissions, and automatic thumbnail generation.

## Features

- 🔐 **Secure Authentication**: JWT-based authentication with granular permissions
- 📁 **Multiple Storage Backends**: Local filesystem and S3-compatible storage
- 🖼️ **Automatic Thumbnails**: Generate thumbnails for images and videos (128px, 512px)
- 🔒 **Permission System**: Bitwise permissions (read/write/owner/public)
- 🌊 **Streaming Support**: Efficient file streaming with range request support
- 🔗 **Secure URLs**: Generate time-limited, signed URLs for file access
- 📊 **Full Type Safety**: Built with TypeScript and Zod validation
- 🚀 **Scalable**: Stateless design for horizontal scaling
- 📝 **Audit Logging**: Complete audit trail for all file operations

## Quick Start

### Prerequisites

- Node.js 18+ 
- MongoDB 4.4+
- (Optional) AWS S3 account for cloud storage

### Installation

1. **Clone and setup the project:**
```bash
git clone <repository-url>
cd file-service
npm install
```

2. **Configure environment:**
```bash
cp .env.example .env
# Edit .env with your configuration
```

3. **Start MongoDB** (if running locally):
```bash
# Using Docker
docker run -d -p 27017:27017 --name mongodb mongo:latest

# Or install MongoDB locally
# https://docs.mongodb.com/manual/installation/
```

4. **Start the development server:**
```bash
npm run dev
```

The server will start on `http://localhost:3000`

### Environment Configuration

Key environment variables in `.env`:

```env
# Server
PORT=3000
NODE_ENV=development

# Database
MONGODB_URI=mongodb://localhost:27017/file-storage-service

# Security
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production

# Storage (choose one)
STORAGE_PROVIDER=local  # or 's3'

# For local storage
LOCAL_STORAGE_PATH=./uploads

# For S3 storage
AWS_ACCESS_KEY_ID=your-aws-access-key
AWS_SECRET_ACCESS_KEY=your-aws-secret-key
S3_BUCKET_NAME=your-bucket-name
```

## API Endpoints

### Health & Info
- `GET /health` - Service health check
- `GET /api/info` - API information

### File Operations (Coming Soon)
- `POST /api/files/upload` - Upload a file
- `GET /api/files/:id/download` - Download a file
- `GET /api/files/:id/stream` - Stream a file
- `GET /api/files/:id/thumbnail/:size` - Get thumbnail
- `GET /api/files` - List files with pagination
- `PATCH /api/files/:id/permissions` - Update file permissions
- `POST /api/files/:id/url` - Generate secure download URL

## Development

### Project Structure

```
src/
├── types/           # TypeScript type definitions
├── utils/           # Utility functions (config, logger)
├── database/        # MongoDB connection and operations
├── storage/         # Storage provider implementations
├── middleware/      # Express middleware
├── routes/          # API route handlers
├── services/        # Business logic services
├── controllers/     # Request/response controllers
└── index.ts         # Application entry point
```

### Available Scripts

```bash
npm run dev          # Start development server with hot reload
npm run build        # Build for production
npm run start        # Start production server
npm run test         # Run tests
npm run lint         # Run ESLint
npm run type-check   # TypeScript type checking
```

### Development Workflow

1. **Phase 1 ✅**: Project setup and foundation
2. **Phase 2**: Core types and interfaces
3. **Phase 3**: Storage backend implementation
4. **Phase 4**: Database layer
5. **Phase 5**: Authentication & authorization
6. **Phase 6**: Core API endpoints
7. **Phase 7**: Thumbnail system
8. **Phase 8**: Secure URL system
9. **Phase 9**: Testing & QA
10. **Phase 10**: Documentation & deployment

## Architecture

### Storage Providers
The system uses a pluggable storage interface supporting:
- **Local Filesystem**: Files stored on server disk
- **S3 Compatible**: AWS S3, MinIO, DigitalOcean Spaces, etc.

### Permission System
Bitwise permission system with:
- `0x01` - READ: Can download/view files
- `0x02` - WRITE: Can update file metadata
- `0x04` - OWNER: Can delete files and manage permissions
- `0x08` - DELETE: Can delete files

### Security Features
- All API endpoints require JWT authentication
- No direct storage URLs exposed
- Secure URL generation with expiration
- Input validation with Zod schemas
- Rate limiting and CORS protection

## Production Deployment

### Environment Setup
1. Set `NODE_ENV=production`
2. Use strong `JWT_SECRET`
3. Configure production MongoDB instance
4. Setup S3 bucket for cloud storage
5. Configure reverse proxy (nginx)
6. Setup SSL/TLS certificates

### Monitoring
- Health check endpoint at `/health`
- Structured logging with configurable levels
- Audit trail for all file operations
- Database connection monitoring

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Run linting and type checking
5. Submit a pull request

## License

MIT License - see LICENSE file for details

---

**Current Status**: Phase 1 Complete ✅
- ✅ Project structure created
- ✅ TypeScript configuration
- ✅ Basic Express server with middleware
- ✅ MongoDB connection setup
- ✅ Configuration management
- ✅ Logging system
- ✅ Health check endpoints

**Next Steps**: Implementing storage providers and core API endpoints.
