
const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const path = require('path');

const app = express();

// Middleware
app.use(cors());
app.use(morgan('dev'));
app.use(express.json());
app.use(express.static('static'));

// Views
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'templates'));

// Routes
app.get('/', (req, res) => {
  res.render('simple_index');
});

app.get('/docs', (req, res) => {
  res.json({
    api_documentation: {
      obfuscate_endpoint: {
        url: "/api/obfuscate",
        method: "POST",
        body: { url: "https://example.com" }
      },
      proxy_endpoint: {
        url: "/api/proxy/{obfuscated_url}",
        methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
      }
    }
  });
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});
