/**
 * API Endpoint Testing Script for File Service
 * 
 * This script tests the key endpoints of the file service API to verify
 * functionality after the AWS SDK v3 migration.
 */

const axios = require('axios');
const fs = require('fs');
const FormData = require('form-data');
const path = require('path');

// Configuration
const API_URL = process.env.API_URL || 'http://localhost:3000/api';
const AUTH_TOKEN = process.env.AUTH_TOKEN || 'YOUR_JWT_TOKEN_HERE';

// Test file path - create a small test file if it doesn't exist
const TEST_FILE_PATH = path.join(__dirname, 'test-file.txt');
if (!fs.existsSync(TEST_FILE_PATH)) {
  fs.writeFileSync(TEST_FILE_PATH, 'This is a test file for API endpoint testing.');
}

// Axios instance with default config
const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Authorization': `Bearer ${AUTH_TOKEN}`
  }
});

// Store test data between tests
const testData = {
  fileId: null,
  secureUrl: null
};

/**
 * Helper function to log test results
 */
function logTest(name, success, data = null, error = null) {
  console.log(`\n----- ${name} -----`);
  if (success) {
    console.log('✅ SUCCESS');
    if (data) {
      console.log('Response data:', JSON.stringify(data, null, 2));
    }
  } else {
    console.log('❌ FAILED');
    if (error) {
      console.log('Error:', error.response?.data || error.message);
    }
  }
}

/**
 * Test file upload
 */
async function testUploadFile() {
  try {
    const form = new FormData();
    form.append('file', fs.createReadStream(TEST_FILE_PATH));
    form.append('isPublic', 'true');
    form.append('tags', JSON.stringify(['test', 'api']));
    
    const response = await api.post('/files/upload', form, {
      headers: {
        ...form.getHeaders()
      }
    });
    
    testData.fileId = response.data.data._id;
    logTest('Upload File', true, response.data);
    return true;
  } catch (error) {
    logTest('Upload File', false, null, error);
    return false;
  }
}

/**
 * Test list files
 */
async function testListFiles() {
  try {
    const response = await api.get('/files', {
      params: {
        limit: 5,
        tags: 'test'
      }
    });
    
    logTest('List Files', true, response.data);
    return true;
  } catch (error) {
    logTest('List Files', false, null, error);
    return false;
  }
}

/**
 * Test get file metadata
 */
async function testGetFileMetadata() {
  if (!testData.fileId) {
    logTest('Get File Metadata', false, null, new Error('No file ID available. Upload test must succeed first.'));
    return false;
  }
  
  try {
    const response = await api.get(`/files/${testData.fileId}`);
    logTest('Get File Metadata', true, response.data);
    return true;
  } catch (error) {
    logTest('Get File Metadata', false, null, error);
    return false;
  }
}

/**
 * Test download file
 */
async function testDownloadFile() {
  if (!testData.fileId) {
    logTest('Download File', false, null, new Error('No file ID available. Upload test must succeed first.'));
    return false;
  }
  
  try {
    const response = await api.get(`/files/${testData.fileId}/download`, {
      responseType: 'arraybuffer'
    });
    
    // Write to a temp file to verify download worked
    const downloadPath = path.join(__dirname, 'downloaded-test-file.txt');
    fs.writeFileSync(downloadPath, Buffer.from(response.data));
    
    logTest('Download File', true, {
      fileSize: response.data.length,
      contentType: response.headers['content-type'],
      savedTo: downloadPath
    });
    return true;
  } catch (error) {
    logTest('Download File', false, null, error);
    return false;
  }
}

/**
 * Test generate secure URL
 */
async function testGenerateSecureUrl() {
  if (!testData.fileId) {
    logTest('Generate Secure URL', false, null, new Error('No file ID available. Upload test must succeed first.'));
    return false;
  }
  
  try {
    const response = await api.get(`/files/${testData.fileId}/secure-url`, {
      params: {
        expiresIn: 3600
      }
    });
    
    testData.secureUrl = response.data.data.secureUrl;
    logTest('Generate Secure URL', true, response.data);
    return true;
  } catch (error) {
    logTest('Generate Secure URL', false, null, error);
    return false;
  }
}

/**
 * Test access secure URL
 */
async function testAccessSecureUrl() {
  if (!testData.secureUrl) {
    logTest('Access Secure URL', false, null, new Error('No secure URL available. Generate secure URL test must succeed first.'));
    return false;
  }
  
  try {
    // Extract token from the secure URL
    const url = new URL(testData.secureUrl);
    const token = url.searchParams.get('token');
    const fileId = url.pathname.split('/').pop();
    
    // Make request to the secure endpoint
    const response = await axios.get(`${API_URL}/files/secure/${fileId}?token=${token}`, {
      responseType: 'arraybuffer'
    });
    
    logTest('Access Secure URL', true, {
      fileSize: response.data.length,
      contentType: response.headers['content-type']
    });
    return true;
  } catch (error) {
    logTest('Access Secure URL', false, null, error);
    return false;
  }
}

/**
 * Test update file permissions
 */
async function testUpdatePermissions() {
  if (!testData.fileId) {
    logTest('Update Permissions', false, null, new Error('No file ID available. Upload test must succeed first.'));
    return false;
  }
  
  try {
    const response = await api.patch(`/files/${testData.fileId}/permissions`, {
      isPublic: false,
      permissions: [
        {
          userId: 'test-user-123',
          access: 1
        }
      ]
    });
    
    logTest('Update Permissions', true, response.data);
    return true;
  } catch (error) {
    logTest('Update Permissions', false, null, error);
    return false;
  }
}

/**
 * Test delete file
 */
async function testDeleteFile() {
  if (!testData.fileId) {
    logTest('Delete File', false, null, new Error('No file ID available. Upload test must succeed first.'));
    return false;
  }
  
  try {
    const response = await api.delete(`/files/${testData.fileId}`);
    logTest('Delete File', true, response.data);
    return true;
  } catch (error) {
    logTest('Delete File', false, null, error);
    return false;
  }
}

/**
 * Test admin stats (requires admin permissions)
 */
async function testAdminStats() {
  try {
    const response = await api.get('/files/admin/stats');
    logTest('Admin Stats', true, response.data);
    return true;
  } catch (error) {
    logTest('Admin Stats', false, null, error);
    return false;
  }
}

/**
 * Run all tests in sequence
 */
async function runTests() {
  console.log('🚀 Starting API endpoint tests...');
  console.log(`API URL: ${API_URL}`);
  console.log('Auth token is ' + (AUTH_TOKEN === 'YOUR_JWT_TOKEN_HERE' ? 'NOT SET ⚠️' : 'set ✓'));
  
  // Run tests in sequence
  await testUploadFile();
  await testListFiles();
  await testGetFileMetadata();
  await testDownloadFile();
  await testGenerateSecureUrl();
  await testAccessSecureUrl();
  await testUpdatePermissions();
  
  // Admin test - might fail if not admin
  await testAdminStats();
  
  // Delete should be last
  await testDeleteFile();
  
  console.log('\n✨ All tests completed!');
}

// Run the tests
runTests().catch(err => {
  console.error('Test runner error:', err);
});
