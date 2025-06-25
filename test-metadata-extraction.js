const fs = require('fs');
const path = require('path');

/**
 * Test script to demonstrate comprehensive metadata extraction
 * This script tests the metadata extraction API endpoint
 */

const API_BASE_URL = 'http://localhost:3000/api';

async function testMetadataExtraction() {
  console.log('🔍 Testing Comprehensive Metadata Extraction\n');

  try {
    // First, get an authentication token
    console.log('1. Getting authentication token...');
    const authResponse = await fetch(`${API_BASE_URL}/auth/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        userId: 'test-user-123',
        email: 'test@example.com'
      })
    });

    if (!authResponse.ok) {
      throw new Error(`Auth failed: ${authResponse.status}`);
    }

    const authData = await authResponse.json();
    const token = authData.data.token;
    console.log('✅ Authentication successful\n');

    // Test with different file types if available
    const testFiles = [
      // You can add test files here
      // { path: './test-files/sample-image.jpg', type: 'image/jpeg' },
      // { path: './test-files/sample-audio.mp3', type: 'audio/mpeg' },
      // { path: './test-files/sample-document.pdf', type: 'application/pdf' }
    ];

    if (testFiles.length === 0) {
      console.log('📝 No test files specified. To test with actual files, add them to the testFiles array.');
      console.log('   Example test files you can use:');
      console.log('   - JPEG image with EXIF/GPS data');
      console.log('   - MP3 audio file with ID3 tags');
      console.log('   - PDF document with metadata');
      return;
    }

    for (const testFile of testFiles) {
      if (!fs.existsSync(testFile.path)) {
        console.log(`⚠️  Test file not found: ${testFile.path}`);
        continue;
      }

      console.log(`2. Testing metadata extraction for: ${path.basename(testFile.path)}`);
      
      // Upload file
      const formData = new FormData();
      const fileBuffer = fs.readFileSync(testFile.path);
      const blob = new Blob([fileBuffer], { type: testFile.type });
      formData.append('file', blob, path.basename(testFile.path));
      formData.append('isPublic', 'true');
      formData.append('tags', JSON.stringify(['test', 'metadata-extraction']));

      const uploadResponse = await fetch(`${API_BASE_URL}/files/upload`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`
        },
        body: formData
      });

      if (!uploadResponse.ok) {
        throw new Error(`Upload failed: ${uploadResponse.status}`);
      }

      const uploadData = await uploadResponse.json();
      const fileId = uploadData.data._id;
      
      console.log('✅ File uploaded successfully');
      console.log('📊 Metadata Summary from Upload:');
      if (uploadData.data.metadataSummary) {
        console.log(JSON.stringify(uploadData.data.metadataSummary, null, 2));
      } else {
        console.log('   No metadata summary available');
      }

      // Get detailed metadata
      console.log('\n3. Retrieving detailed metadata...');
      const metadataResponse = await fetch(`${API_BASE_URL}/files/${fileId}/metadata/detailed`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (!metadataResponse.ok) {
        throw new Error(`Metadata retrieval failed: ${metadataResponse.status}`);
      }

      const metadataData = await metadataResponse.json();
      
      console.log('✅ Detailed metadata retrieved');
      console.log('📋 Full Extracted Metadata:');
      
      if (metadataData.data.extractedMetadata) {
        const metadata = metadataData.data.extractedMetadata;
        
        // Display different types of metadata
        if (metadata.fileType) {
          console.log(`\n🔍 File Type: ${metadata.fileType.ext} (${metadata.fileType.mime})`);
        }
        
        if (metadata.dimensions) {
          console.log(`\n📐 Dimensions: ${metadata.dimensions.width}x${metadata.dimensions.height}`);
          console.log(`   Channels: ${metadata.dimensions.channels}, Density: ${metadata.dimensions.density}`);
        }
        
        if (metadata.exif) {
          console.log('\n📷 EXIF Data:');
          if (metadata.exif.make) console.log(`   Camera: ${metadata.exif.make} ${metadata.exif.model || ''}`);
          if (metadata.exif.dateTimeOriginal) console.log(`   Taken: ${metadata.exif.dateTimeOriginal}`);
          if (metadata.exif.iso) console.log(`   ISO: ${metadata.exif.iso}`);
          if (metadata.exif.fNumber) console.log(`   Aperture: f/${metadata.exif.fNumber}`);
          if (metadata.exif.exposureTime) console.log(`   Exposure: ${metadata.exif.exposureTime}s`);
          if (metadata.exif.focalLength) console.log(`   Focal Length: ${metadata.exif.focalLength}mm`);
        }
        
        if (metadata.gps) {
          console.log('\n🌍 GPS Location:');
          console.log(`   Latitude: ${metadata.gps.latitude}°`);
          console.log(`   Longitude: ${metadata.gps.longitude}°`);
          if (metadata.gps.altitude) console.log(`   Altitude: ${metadata.gps.altitude}m`);
        }
        
        if (metadata.audio) {
          console.log('\n🎵 Audio Metadata:');
          if (metadata.audio.title) console.log(`   Title: ${metadata.audio.title}`);
          if (metadata.audio.artist) console.log(`   Artist: ${metadata.audio.artist}`);
          if (metadata.audio.album) console.log(`   Album: ${metadata.audio.album}`);
          if (metadata.audio.duration) console.log(`   Duration: ${Math.round(metadata.audio.duration)}s`);
          if (metadata.audio.bitRate) console.log(`   Bitrate: ${metadata.audio.bitRate} kbps`);
        }
        
        if (metadata.document) {
          console.log('\n📄 Document Metadata:');
          if (metadata.document.title) console.log(`   Title: ${metadata.document.title}`);
          if (metadata.document.author) console.log(`   Author: ${metadata.document.author}`);
          if (metadata.document.pageCount) console.log(`   Pages: ${metadata.document.pageCount}`);
          if (metadata.document.creationDate) console.log(`   Created: ${metadata.document.creationDate}`);
        }
        
        if (metadata.technical) {
          console.log('\n🔧 Technical Metadata:');
          if (metadata.technical.artist) console.log(`   Artist: ${metadata.technical.artist}`);
          if (metadata.technical.copyright) console.log(`   Copyright: ${metadata.technical.copyright}`);
          if (metadata.technical.imageDescription) console.log(`   Description: ${metadata.technical.imageDescription}`);
        }
      } else {
        console.log('   No extracted metadata available');
      }
      
      console.log('\n' + '='.repeat(60) + '\n');
    }

  } catch (error) {
    console.error('❌ Test failed:', error.message);
  }
}

// Run the test
testMetadataExtraction();
