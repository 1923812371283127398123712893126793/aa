const express = require('express');
const multer = require('multer');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const app = express();  // Initialize the express app
const port = 3000;

// Set up file upload destination
const upload = multer({ dest: 'uploads/' });

// Cloudflare Turnstile Secret Key
const TURNSTILE_SECRET_KEY = '1x0000000000000000000000000000000AA';

// IP Whitelist and storage paths
const whitelistFile = 'whitelist/whitelisted_ips.txt';
const generatedFolder = 'generated/';
const accessLogFile = 'access_logs.txt';
const whitelistExpiryTime = 30 * 1000; // 30 seconds in milliseconds

// Serve static files (like the generated HTML files) from the 'generated' folder
app.use('/generated', express.static(path.join(__dirname, 'generated')));

// Middleware to log the IP of every request
const logIP = (req, res, next) => {
  const clientIP = req.ip.replace('::ffff:', ''); // Handle IPv4-mapped IPv6 addresses
  const timestamp = new Date().toISOString();
  
  const logMessage = `IP: ${clientIP} - Time: ${timestamp} - URL: ${req.originalUrl}\n`;
  fs.appendFile(accessLogFile, logMessage, (err) => {
    if (err) {
      console.error('Error logging IP:', err);
    }
  });
  
  next();
};

// Middleware to add IP to whitelist with expiration
const addIPToWhitelist = (ipAddress) => {
  const currentTime = Date.now();
  fs.readFile(whitelistFile, 'utf8', (err, data) => {
    if (err) {
      return console.error('Error reading whitelist');
    }

    let whitelistedIps = data.split('\n').map(line => line.trim()).filter(line => line);

    // Remove expired IPs
    whitelistedIps = whitelistedIps.filter(ipEntry => {
      const [ip, timestamp] = ipEntry.split('|');
      return currentTime - parseInt(timestamp) < whitelistExpiryTime;
    });

    // Add the new IP with current timestamp
    if (!whitelistedIps.some(ipEntry => ipEntry.startsWith(ipAddress))) {
      whitelistedIps.push(`${ipAddress}|${currentTime}`);
      fs.writeFile(whitelistFile, whitelistedIps.join('\n'), (err) => {
        if (err) {
          console.error('Error adding IP to whitelist');
        } else {
          console.log(`Added ${ipAddress} to whitelist`);
        }
      });
    }
  });
};

// Serve the file upload page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Upload handler with Turnstile verification
app.post('/upload', upload.single('file'), async (req, res) => {
  const { file } = req;
  const { 'cf-turnstile-response': turnstileResponse } = req.body;

  if (!turnstileResponse) {
    return res.status(400).send('Turnstile verification failed. Please complete the CAPTCHA.');
  }

  try {
    // Verify Turnstile response with Cloudflare's API
    const verificationResponse = await axios.post('https://challenges.cloudflare.com/turnstile/v0/siteverify', null, {
      params: {
        secret: TURNSTILE_SECRET_KEY,
        response: turnstileResponse,
      },
    });

    if (verificationResponse.data.success) {
      const { filename, originalname } = file;
      res.send(`File uploaded! <a href="/download/${filename}">Download the file</a>`);
    } else {
      res.status(400).send('Turnstile verification failed. Please try again.');
    }
  } catch (error) {
    console.error('Error verifying Turnstile:', error);
    res.status(500).send('Internal server error. Please try again later.');
  }
});

// Generate the HTML for file download after IP validation
app.get('/download/:filename', (req, res) => {
  const { filename } = req.params;
  const filePath = path.join(__dirname, 'uploads', filename);

  fs.access(filePath, fs.constants.F_OK, (err) => {
    if (err) {
      return res.status(404).send('File not found');
    }

    const clientIP = req.ip.replace('::ffff:', ''); // Handle IPv4-mapped IPv6 addresses
    addIPToWhitelist(clientIP); // Add the downloader's IP to the whitelist

    // Generate a random HTML filename for the download page
    const randomName = crypto.randomBytes(16).toString('hex');
    const countdownTime = 30; // Countdown time in seconds

    const downloadPage = `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Download File</title>
        <style>
          body { font-family: Arial, sans-serif; text-align: center; margin-top: 20px; }
          h1 { color: #333; }
          #countdown { font-size: 40px; margin: 20px; }
          #download-btn { padding: 10px 20px; font-size: 16px; cursor: pointer; background-color: #4CAF50; color: white; border: none; border-radius: 5px; display: none; }
          .noscript-warning { color: red; font-weight: bold; }
        </style>
      </head>
      <body>
        <h1>Download Your File</h1>

        <!-- Warning for when JavaScript is disabled -->
        <noscript>
          <div class="noscript-warning">
            JavaScript is disabled in your browser. Please enable JavaScript for the upload and download functionality to work properly.
          </div>
        </noscript>

        <div id="countdown">${countdownTime}</div>
        <button id="download-btn" onclick="window.location.href='/file/${filename}'">Download the file</button>

        <script>
          let countdownTime = ${countdownTime};
          const countdownElement = document.getElementById('countdown');
          const downloadButton = document.getElementById('download-btn');

          // Start the countdown timer
          const countdownInterval = setInterval(() => {
            countdownTime--;
            countdownElement.textContent = countdownTime;

            if (countdownTime <= 0) {
              clearInterval(countdownInterval);
              downloadButton.style.display = 'inline-block'; // Show download button
            }
          }, 1000);

          // Detect when the user switches to another tab
          document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
              // Stop the countdown if the tab is hidden
              clearInterval(countdownInterval);
            } else {
              // Restart the countdown if the tab is active
              countdownInterval = setInterval(() => {
                countdownTime--;
                countdownElement.textContent = countdownTime;

                if (countdownTime <= 0) {
                  clearInterval(countdownInterval);
                  downloadButton.style.display = 'inline-block'; // Show download button
                }
              }, 1000);
            }
          });
        </script>
      </body>
      </html>
    `;

    const generatedPath = path.join(__dirname, 'generated', `${randomName}.html`);
    fs.writeFile(generatedPath, downloadPage, (err) => {
      if (err) {
        return res.status(500).send('Error generating download page');
      }
      res.send(`Download page created! <a href="/generated/${randomName}.html">Go to download page</a>`);
    });
  });
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
