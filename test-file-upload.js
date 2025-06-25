/**
 * Simple File Upload Test Script
 * 
 * This script tests the file upload functionality of the file service API
 * after the AWS SDK v3 migration.
 */

const fs = require('fs');
const path = require('path');
const http = require('http');

// Configuration
const API_HOST = 'localhost';
const API_PORT = 3000;
const API_PATH = '/api/files/upload';
const AUTH_TOKEN = process.env.AUTH_TOKEN || 'YOUR_JWT_TOKEN_HERE'; // Replace with your actual JWT token

// Create a test file if it doesn't exist
const TEST_FILE_PATH = path.join(__dirname, 'test-file.txt');
if (!fs.existsSync(TEST_FILE_PATH)) {
  fs.writeFileSync(TEST_FILE_PATH, 'This is a test file for API endpoint testing.');
  console.log(`Created test file at ${TEST_FILE_PATH}`);
}

// Generate a boundary for multipart/form-data
const boundary = '----WebKitFormBoundary' + Math.random().toString(16).substr(2);

// Prepare the multipart form data
function createMultipartData() {
  const fileContent = fs.readFileSync(TEST_FILE_PATH);
  const filename = path.basename(TEST_FILE_PATH);
  
  let data = '';
  
  // Add file part
  data += `--${boundary}\r\n`;
  data += `Content-Disposition: form-data; name="file"; filename="${filename}"\r\n`;
  data += 'Content-Type: text/plain\r\n\r\n';
  
  // Convert the file content to a Buffer
  const fileBuffer = Buffer.from(fileContent);
  
  // Add metadata parts
  const isPublicPart = `--${boundary}\r\nContent-Disposition: form-data; name="isPublic"\r\n\r\ntrue\r\n`;
  const tagsPart = `--${boundary}\r\nContent-Disposition: form-data; name="tags"\r\n\r\n["test","api"]\r\n`;
  const endBoundary = `--${boundary}--\r\n`;
  
  // Combine all parts
  const startBuffer = Buffer.from(data);
  const isPublicBuffer = Buffer.from(isPublicPart);
  const tagsBuffer = Buffer.from(tagsPart);
  const endBuffer = Buffer.from(endBoundary);
  
  return Buffer.concat([startBuffer, fileBuffer, Buffer.from('\r\n'), isPublicBuffer, tagsBuffer, endBuffer]);
}

// Make the HTTP request
function uploadFile() {
  const formData = createMultipartData();
  
  const options = {
    hostname: API_HOST,
    port: API_PORT,
    path: API_PATH,
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${AUTH_TOKEN}`,
      'Content-Type': `multipart/form-data; boundary=${boundary}`,
      'Content-Length': formData.length
    }
  };
  
  console.log(`Sending request to ${options.hostname}:${options.port}${options.path}`);
  
  const req = http.request(options, (res) => {
    console.log(`Status Code: ${res.statusCode}`);
    
    let responseData = '';
    res.on('data', (chunk) => {
      responseData += chunk;
    });
    
    res.on('end', () => {
      try {
        const parsedData = JSON.parse(responseData);
        console.log('Response:');
        console.log(JSON.stringify(parsedData, null, 2));
        
        if (res.statusCode === 201 && parsedData.success) {
          console.log('\n✅ File upload test SUCCESSFUL');
          console.log(`File ID: ${parsedData.data._id}`);
          console.log(`URL: ${parsedData.data.url}`);
        } else {
          console.log('\n❌ File upload test FAILED');
        }
      } catch (e) {
        console.error('Error parsing response:', e);
        console.log('Raw response:', responseData);
      }
    });
  });
  
  req.on('error', (error) => {
    console.error('Error making request:', error);
  });
  
  req.write(formData);
  req.end();
}

// Run the test
console.log('🚀 Starting file upload test...');
uploadFile();
