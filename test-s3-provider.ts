import { S3StorageProvider } from './src/storage/s3-provider';
import { config } from './src/utils/config';
import fs from 'fs/promises';
import path from 'path';

// Force S3 provider for testing
process.env.STORAGE_PROVIDER = 's3';

// Ensure AWS credentials are set
if (!config.storage.s3?.accessKeyId || !config.storage.s3?.secretAccessKey || !config.storage.s3?.bucketName) {
  console.error('❌ S3 configuration is incomplete. Please set AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and S3_BUCKET_NAME');
  process.exit(1);
}

async function testS3Provider() {
  try {
    console.log('🔍 Testing S3StorageProvider with AWS SDK v3...');
    
    // Initialize provider
    console.log('📦 Initializing S3StorageProvider...');
    const s3Provider = new S3StorageProvider();
    console.log('✅ S3StorageProvider initialized successfully');
    
    // Create a test file
    const testFileName = `test-file-${Date.now()}.txt`;
    const testContent = Buffer.from('This is a test file for S3StorageProvider with AWS SDK v3');
    const testMimetype = 'text/plain';
    
    // Test upload
    console.log(`📤 Testing upload with file: ${testFileName}`);
    const uploadResult = await s3Provider.upload(testContent, testFileName, testMimetype);
    console.log('✅ Upload successful:', uploadResult);
    
    // Test exists
    console.log(`🔍 Testing exists with key: ${uploadResult.storageKey}`);
    const existsResult = await s3Provider.exists(uploadResult.storageKey);
    console.log(`✅ Exists check: ${existsResult}`);
    
    // Test getUrl
    console.log(`🔗 Testing getUrl with key: ${uploadResult.storageKey}`);
    const url = await s3Provider.getUrl(uploadResult.storageKey);
    console.log(`✅ Generated URL: ${url}`);
    
    // Test download
    console.log(`📥 Testing download with key: ${uploadResult.storageKey}`);
    const downloadResult = await s3Provider.download(uploadResult.storageKey);
    console.log('✅ Download successful:', {
      size: downloadResult.size,
      mimetype: downloadResult.mimetype,
      content: downloadResult.buffer.toString().substring(0, 50) + '...'
    });
    
    // Test getStorageStats
    console.log('📊 Testing getStorageStats...');
    const stats = await s3Provider.getStorageStats();
    console.log('✅ Storage stats:', stats);
    
    // Test delete
    console.log(`🗑️ Testing delete with key: ${uploadResult.storageKey}`);
    await s3Provider.delete(uploadResult.storageKey);
    console.log('✅ Delete successful');
    
    // Verify deletion
    console.log(`🔍 Verifying deletion with key: ${uploadResult.storageKey}`);
    const existsAfterDelete = await s3Provider.exists(uploadResult.storageKey);
    console.log(`✅ Exists after delete: ${existsAfterDelete} (should be false)`);
    
    // Test batch delete with a new file
    console.log('📤 Uploading another test file for batch delete...');
    const batchTestFileName = `batch-test-file-${Date.now()}.txt`;
    const batchUploadResult = await s3Provider.upload(testContent, batchTestFileName, testMimetype);
    console.log('✅ Batch test file uploaded:', batchUploadResult.storageKey);
    
    // Test batch delete
    console.log(`🗑️ Testing batchDelete with key: ${batchUploadResult.storageKey}`);
    await s3Provider.batchDelete([batchUploadResult.storageKey]);
    console.log('✅ Batch delete successful');
    
    // Test thumbnail upload
    console.log('🖼️ Testing uploadThumbnail...');
    const thumbnailFileName = `thumbnail-test-${Date.now()}.txt`;
    const thumbnailResult = await s3Provider.uploadThumbnail(testContent, thumbnailFileName, 128, testMimetype);
    console.log('✅ Thumbnail upload successful:', thumbnailResult);
    
    // Clean up thumbnail
    console.log(`🗑️ Cleaning up thumbnail with key: ${thumbnailResult.storageKey}`);
    await s3Provider.delete(thumbnailResult.storageKey);
    console.log('✅ Thumbnail cleanup successful');
    
    console.log('\n🎉 All S3 operations tested successfully with AWS SDK v3!');
  } catch (error) {
    console.error('❌ Error testing S3 provider:', error);
    process.exit(1);
  }
}

testS3Provider();
