const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const morgan = require('morgan');
const multer = require('multer');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Set up multer for file uploads
const upload = multer({ 
  dest: 'uploads/',
  limits: { fileSize: 10 * 1024 * 1024 } // 10MB file size limit
});

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.text());
app.use(morgan('dev'));

// Encryption algorithms
const algorithms = {
  aes: {
    encrypt: (data, key) => {
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key.padEnd(32).slice(0, 32)), iv);
      let encrypted = cipher.update(data, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      return { iv: iv.toString('hex'), encrypted };
    },
    decrypt: (encryptedData, key, iv) => {
      const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key.padEnd(32).slice(0, 32)), Buffer.from(iv, 'hex'));
      let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      return decrypted;
    }
  },
  des: {
    encrypt: (data, key) => {
      const iv = crypto.randomBytes(8);
      const cipher = crypto.createCipheriv('des-cbc', Buffer.from(key.padEnd(8).slice(0, 8)), iv);
      let encrypted = cipher.update(data, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      return { iv: iv.toString('hex'), encrypted };
    },
    decrypt: (encryptedData, key, iv) => {
      const decipher = crypto.createDecipheriv('des-cbc', Buffer.from(key.padEnd(8).slice(0, 8)), Buffer.from(iv, 'hex'));
      let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      return decrypted;
    }
  },
  tripledes: {
    encrypt: (data, key) => {
      const iv = crypto.randomBytes(8);
      const cipher = crypto.createCipheriv('des-ede3-cbc', Buffer.from(key.padEnd(24).slice(0, 24)), iv);
      let encrypted = cipher.update(data, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      return { iv: iv.toString('hex'), encrypted };
    },
    decrypt: (encryptedData, key, iv) => {
      const decipher = crypto.createDecipheriv('des-ede3-cbc', Buffer.from(key.padEnd(24).slice(0, 24)), Buffer.from(iv, 'hex'));
      let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      return decrypted;
    }
  },
  blowfish: {
    encrypt: (data, key) => {
      const iv = crypto.randomBytes(8);
      const cipher = crypto.createCipheriv('bf-cbc', Buffer.from(key.padEnd(16).slice(0, 16)), iv);
      let encrypted = cipher.update(data, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      return { iv: iv.toString('hex'), encrypted };
    },
    decrypt: (encryptedData, key, iv) => {
      const decipher = crypto.createDecipheriv('bf-cbc', Buffer.from(key.padEnd(16).slice(0, 16)), Buffer.from(iv, 'hex'));
      let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      return decrypted;
    }
  }
};

// Generate test data of a specific size (in KB)
function generateTestData(sizeInKB, dataType) {
  const byteSize = sizeInKB * 1024;
  let data;
  
  switch(dataType) {
    case 'text':
      // Generate random text
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 ';
      data = '';
      for (let i = 0; i < byteSize; i++) {
        data += chars.charAt(Math.floor(Math.random() * chars.length));
      }
      break;
    case 'json':
      // Generate structured JSON data
      const entries = Math.ceil(byteSize / 100); // Approximate size per entry
      const json = { data: [] };
      for (let i = 0; i < entries; i++) {
        json.data.push({
          id: i,
          value: Math.random().toString(36).substring(2, 15),
          timestamp: Date.now()
        });
      }
      data = JSON.stringify(json);
      break;
    case 'binary':
      // Generate random binary data
      data = crypto.randomBytes(byteSize).toString('hex');
      break;
    default:
      data = crypto.randomBytes(byteSize).toString('hex');
  }
  
  return data;
}

// Endpoint to run encryption benchmark
app.post('/api/benchmark', async (req, res) => {
  try {
    const { algorithm, dataSize, dataType, key = "mysecretkey123" } = req.body;
    
    if (!algorithms[algorithm]) {
      return res.status(400).json({ error: `Algorithm '${algorithm}' not supported` });
    }
    
    // Generate test data
    const testData = generateTestData(dataSize, dataType);
    
    // Benchmark encryption
    const encryptStart = process.hrtime();
    const encryptResult = algorithms[algorithm].encrypt(testData, key);
    const encryptDiff = process.hrtime(encryptStart);
    const encryptTime = (encryptDiff[0] * 1e9 + encryptDiff[1]) / 1e6; // Convert to milliseconds
    
    // Benchmark decryption
    const decryptStart = process.hrtime();
    algorithms[algorithm].decrypt(encryptResult.encrypted, key, encryptResult.iv);
    const decryptDiff = process.hrtime(decryptStart);
    const decryptTime = (decryptDiff[0] * 1e9 + decryptDiff[1]) / 1e6; // Convert to milliseconds
    
    // Calculate throughput (KB/s)
    const totalTime = (encryptTime + decryptTime) / 1000; // Convert to seconds
    const throughput = dataSize / totalTime;
    
    // Calculate efficiency score (simplified)
    // Lower is better - combines time and data size
    const efficiency = 100 - Math.min(100, (encryptTime + decryptTime) / dataSize);
    
    res.json({
      algorithm,
      dataSize,
      dataType,
      encryptTime,
      decryptTime,
      totalTime: encryptTime + decryptTime,
      throughput,
      efficiency,
      originalSize: testData.length,
      encryptedSize: encryptResult.encrypted.length
    });
  } catch (error) {
    console.error('Benchmark error:', error);
    res.status(500).json({ error: error.message });
  }
});

// File upload and benchmark endpoint
app.post('/api/file-benchmark', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const { algorithm, key = "mysecretkey123" } = req.body;
    
    if (!algorithms[algorithm]) {
      return res.status(400).json({ error: `Algorithm '${algorithm}' not supported` });
    }
    
    // Read file data
    const filePath = req.file.path;
    const fileData = fs.readFileSync(filePath, 'utf8');
    const fileName = req.file.originalname;
    const fileSize = req.file.size / 1024; // Convert to KB
    
    // Benchmark encryption
    const encryptStart = process.hrtime();
    const encryptResult = algorithms[algorithm].encrypt(fileData, key);
    const encryptDiff = process.hrtime(encryptStart);
    const encryptTime = (encryptDiff[0] * 1e9 + encryptDiff[1]) / 1e6; // Convert to milliseconds
    
    // Benchmark decryption
    const decryptStart = process.hrtime();
    algorithms[algorithm].decrypt(encryptResult.encrypted, key, encryptResult.iv);
    const decryptDiff = process.hrtime(decryptStart);
    const decryptTime = (decryptDiff[0] * 1e9 + decryptDiff[1]) / 1e6; // Convert to milliseconds
    
    // Calculate throughput (KB/s)
    const totalTime = (encryptTime + decryptTime) / 1000; // Convert to seconds
    const throughput = fileSize / totalTime;
    
    // Calculate efficiency score (simplified)
    const efficiency = 100 - Math.min(100, (encryptTime + decryptTime) / fileSize);
    
    // Clean up - delete the uploaded file
    fs.unlinkSync(filePath);
    
    res.json({
      algorithm,
      fileName,
      fileSize,
      encryptTime,
      decryptTime,
      totalTime: encryptTime + decryptTime,
      throughput,
      efficiency,
      originalSize: fileData.length,
      encryptedSize: encryptResult.encrypted.length
    });
  } catch (error) {
    console.error('File benchmark error:', error);
    
    // Clean up on error
    if (req.file && req.file.path) {
      try {
        fs.unlinkSync(req.file.path);
      } catch (unlinkError) {
        console.error('Error deleting file:', unlinkError);
      }
    }
    
    res.status(500).json({ error: error.message });
  }
});

// Recommendation endpoint (simplified)
app.post('/api/recommend', (req, res) => {
  const { dataSize, dataType } = req.body;
  
  // Simple recommendation logic (to be replaced with ML model later)
  let recommendedAlgo;
  
  if (dataSize <= 10) {
    recommendedAlgo = 'aes'; // AES is good for small data
  } else if (dataSize <= 50) {
    recommendedAlgo = dataType === 'text' ? 'blowfish' : 'aes';
  } else {
    recommendedAlgo = 'aes'; // AES is generally a good all-around choice
  }
  
  res.json({
    recommendedAlgorithm: recommendedAlgo,
    reason: `Based on your ${dataSize}KB ${dataType} data, ${recommendedAlgo.toUpperCase()} provides the best balance of security and performance.`
  });
});

// Create uploads directory if it doesn't exist
if (!fs.existsSync('./uploads')) {
  fs.mkdirSync('./uploads');
}

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});