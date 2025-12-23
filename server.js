const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const path = require('path');
const fs = require('fs');
const { exec } = require('child_process');

const app = express();
const PORT = 3000;

// Initialize in-memory SQLite database
const db = new sqlite3.Database(':memory:');

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static('public'));
app.set('view engine', 'ejs');

// Initialize database with tables and dummy data
db.serialize(() => {
  // Create users table
  db.run(`CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    email TEXT NOT NULL
  )`);

  // Create tasks table
  db.run(`CREATE TABLE tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // [VULNERABILITY] Passwords stored in plain text - no hashing
  db.run(`INSERT INTO users (username, password, email) VALUES ('admin', 'admin123', 'admin@vulnerable.com')`);
  db.run(`INSERT INTO users (username, password, email) VALUES ('user', 'user123', 'user@vulnerable.com')`);
  db.run(`INSERT INTO users (username, password, email) VALUES ('alice', 'password', 'alice@vulnerable.com')`);

  // Insert some sample tasks
  db.run(`INSERT INTO tasks (user_id, content) VALUES (1, 'Review security audit')`);
  db.run(`INSERT INTO tasks (user_id, content) VALUES (2, 'Complete project documentation')`);
  db.run(`INSERT INTO tasks (user_id, content) VALUES (1, 'Update server configuration')`);
});

// Create a dummy log file for path traversal testing
fs.writeFileSync('app.log', 'Application started\nServer running on port 3000\nAll systems operational\n');

// Home page - redirect to login
app.get('/', (req, res) => {
  if (req.cookies.userId) {
    res.redirect('/dashboard');
  } else {
    res.redirect('/login');
  }
});

// Login page
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

// [VULNERABILITY] SQL Injection in login
app.post('/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  const redirectUrl = req.query.redirectUrl || '/dashboard';

  // [VULNERABILITY] SQL Injection - using string concatenation to build SQL query
  // This allows attacks like: username = ' OR '1'='1 to bypass authentication
  const query = `SELECT * FROM users WHERE username = ? AND password = ?`;
  
  console.log('Executing query:', query); // For debugging

  db.get(query,[username,password], (err, user) => {
    if (err) {
      console.error('Database error:', err);
      res.render('login', { error: 'Database error occurred' });
      return;
    }

    if (user) {
      // Set cookie with user ID
      res.cookie('userId', user.id);
      res.cookie('username', user.username);
      
      // [VULNERABILITY] Open Redirect - redirects to any URL without validation
      // An attacker can redirect users to malicious sites via ?redirectUrl=http://evil.com
      res.redirect(redirectUrl);
    } else {
      res.render('login', { error: 'Invalid credentials' });
    }
  });
});

// Logout
app.get('/logout', (req, res) => {
  res.clearCookie('userId');
  res.clearCookie('username');
  res.redirect('/login');
});

// Dashboard - Display tasks
app.get('/dashboard', (req, res) => {
  if (!req.cookies.userId) {
    res.redirect('/login');
    return;
  }

  const userId = req.cookies.userId;
  const username = req.cookies.username;

  db.all(`SELECT * FROM tasks WHERE user_id = ${userId} ORDER BY created_at DESC`, (err, tasks) => {
    if (err) {
      console.error('Database error:', err);
      res.send('Error loading tasks');
      return;
    }

    res.render('dashboard', { username, tasks });
  });
});

// [FIXEDD] Stored XSS - Add task without sanitization
app.post('/add-task', (req, res) => {
  if (!req.cookies.userId) {
    res.redirect('/login');
    return;
  }

  const userId = req.cookies.userId;
  let content = req.body.content;

  // Fix: Basic HTML escaping to prevent XSS
  content = content.replace(/</g, '&lt;').replace(/>/g, '&gt;');
  
  db.run(`INSERT INTO tasks (user_id, content) VALUES (?, ?)`, [userId, content], (err) => {
    if (err) {
      console.error('Error adding task:', err);
    }
    res.redirect('/dashboard');
  });
});

// Admin page - Server health check
app.get('/admin', (req, res) => {
  if (!req.cookies.userId) {
    res.redirect('/login');
    return;
  }

  res.render('admin', { username: req.cookies.username, result: null });
});

// [VULNERABILITY] OS Command Injection
app.post('/ping', (req, res) => {
  if (!req.cookies.userId) {
    res.redirect('/login');
    return;
  }

  const website = req.body.website;

  // Fix: Basic validation to prevent command injection
  if (!/^[a-zA-Z0-9.-]+$/.test(website)) {
    res.render('admin', { username: req.cookies.username, result: 'Invalid website format' });
    return;
  }

  // Fix: Use spawn instead of exec to avoid shell injection
  const { spawn } = require('child_process');
  const ping = spawn('ping', ['-n', '2', website]);

  let result = '';
  ping.stdout.on('data', (data) => {
    result += data.toString();
  });

  ping.stderr.on('data', (data) => {
    result += data.toString();
  });

  ping.on('close', (code) => {
    if (code !== 0) {
      result = `Error: Ping failed with code ${code}\n${result}`;
    }
    res.render('admin', { username: req.cookies.username, result });
  });
});

// [FIXEDD] Path Traversal - File viewer
app.get('/view-log', (req, res) => {
  if (!req.cookies.userId) {
    res.redirect('/login');
    return;
  }

  const filename = req.query.file || 'app.log';

  // Fix: Prevent path traversal by validating filename
  if (filename.includes('..') || filename.includes('/') || filename.includes('\\') || !filename.endsWith('.log')) {
    res.render('file-viewer', { 
      username: req.cookies.username, 
      filename, 
      content: 'Access denied: Invalid filename' 
    });
    return;
  }

  try {
    const content = fs.readFileSync(filename, 'utf8');
    res.render('file-viewer', { 
      username: req.cookies.username, 
      filename, 
      content 
    });
  } catch (error) {
    res.render('file-viewer', { 
      username: req.cookies.username, 
      filename, 
      content: `Error reading file: ${error.message}` 
    });
  }
});

// [VULNERABILITY] IDOR - Insecure Direct Object Reference
app.get('/profile', (req, res) => {
  if (!req.cookies.userId) {
    res.redirect('/login');
    return;
  }

  const profileId = req.query.id || req.cookies.userId;

  // [VULNERABILITY] IDOR - no authorization check to verify if the logged-in user
  // should be allowed to view this profile. Any user can view any profile by changing the ID.
  db.get(`SELECT * FROM users WHERE id = ?`, [profileId], (err, user) => {
    if (err || !user) {
      res.send('User not found');
      return;
    }

    res.render('profile', { 
      username: req.cookies.username, 
      currentUserId: req.cookies.userId,
      profile: user 
    });
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║         VULNERABLE TASK MANAGER - EDUCATIONAL VERSION            ║
║                                                                   ║
║  WARNING: This application contains intentional vulnerabilities  ║
║  for educational purposes only. DO NOT deploy to production!     ║
║                                                                   ║
║  Server running on: http://localhost:${PORT}                          ║
║                                                                   ║
║  Test Accounts:                                                   ║
║    - admin / admin123                                             ║
║    - user / user123                                               ║
║    - alice / password                                             ║
║                                                                   ║
║  Vulnerabilities Included:                                        ║
║    1. SQL Injection (Login)                                       ║
║    2. Stored XSS (Task Dashboard)                                 ║
║    3. OS Command Injection (Admin Ping)                           ║
║    4. Path Traversal (File Viewer)                                ║
║    5. IDOR (User Profile)                                         ║
║    6. Open Redirect (Login Redirect)                              ║
║    7. Plain Text Password Storage                                 ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
  `);
});
