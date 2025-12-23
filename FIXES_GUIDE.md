# 🔒 Security Fixes Guide

This guide shows how to properly fix each vulnerability in the application. Use this as a reference when implementing your own fixes.

---

## Fix 1: SQL Injection

### The Problem
```javascript
// VULNERABLE CODE
const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
db.get(query, (err, user) => { ... });
```

### The Solution
Use **parameterized queries** (also called prepared statements):

```javascript
// SECURE CODE
db.get(
  'SELECT * FROM users WHERE username = ? AND password = ?',
  [username, password],
  (err, user) => {
    // Handle result
  }
);
```

### Why It Works
- The database treats `?` placeholders as data, not executable SQL
- No matter what the user inputs, it cannot break out of the string context
- The database driver automatically escapes special characters

### Additional Best Practices
```javascript
// Also add input validation
const username = req.body.username.trim();
if (username.length > 50) {
  return res.render('login', { error: 'Invalid username length' });
}

// Use an ORM for even more safety (though not required for this exercise)
// Example with Sequelize:
// User.findOne({ where: { username, password } })
```

---

## Fix 2: Stored XSS

### The Problem
```ejs
<!-- VULNERABLE CODE in views/dashboard.ejs -->
<%- task.content %>
```

### The Solution
Use **escaped output** in EJS:

```ejs
<!-- SECURE CODE -->
<%= task.content %>
```

### Why It Works
- `<%= %>` automatically HTML-escapes the content
- `<script>` becomes `&lt;script&gt;` which displays as text, not executed
- `<%- %>` renders raw HTML and should only be used for trusted content

### Character Escaping Examples
| Input | Escaped Output |
|-------|---------------|
| `<script>` | `&lt;script&gt;` |
| `"hello"` | `&quot;hello&quot;` |
| `'hello'` | `&#x27;hello&#x27;` |
| `&` | `&amp;` |

### Additional Best Practices
```javascript
// Server-side: Sanitize input before storing (optional, defense in depth)
const createDOMPurify = require('isomorphic-dompurify');
const clean = createDOMPurify.sanitize(req.body.content);

// Or use a simple validator
const validator = require('validator');
if (!validator.isLength(content, { max: 1000 })) {
  return res.status(400).send('Content too long');
}
```

---

## Fix 3: OS Command Injection

### The Problem
```javascript
// VULNERABLE CODE
const command = `ping -n 2 ${website}`;
exec(command, (error, stdout, stderr) => { ... });
```

### The Solution - Option 1: Input Validation
```javascript
// SECURE CODE - Whitelist validation
const website = req.body.website.trim();

// Only allow valid domain names/IPs
const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$|^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;

if (!domainRegex.test(website)) {
  return res.render('admin', {
    username: req.cookies.username,
    result: 'Invalid domain or IP address'
  });
}

// Use execFile instead of exec (doesn't spawn a shell)
const { execFile } = require('child_process');
execFile('ping', ['-n', '2', website], (error, stdout, stderr) => {
  // Handle result
});
```

### The Solution - Option 2: Use a Library
```javascript
// SECURE CODE - Use a dedicated library
const ping = require('ping');

ping.promise.probe(website, {
  timeout: 10,
  extra: ['-i', '2'],
}).then((res) => {
  const result = `Host: ${res.host}\nAlive: ${res.alive}\nTime: ${res.time}ms`;
  // Render result
});
```

### Why It Works
- **Input validation** prevents special characters like `;`, `&`, `|`
- **execFile** doesn't spawn a shell, preventing command chaining
- **Dedicated libraries** provide safe, purpose-built functionality

### What to Never Do
```javascript
// NEVER DO THIS
exec(`ping ${userInput}`);
exec(`rm ${userInput}`);
exec(`cat ${userInput}`);
// Any exec() with user input is dangerous!
```

---

## Fix 4: Path Traversal

### The Problem
```javascript
// VULNERABLE CODE
const filename = req.query.file || 'app.log';
const content = fs.readFileSync(filename, 'utf8');
```

### The Solution
```javascript
// SECURE CODE
const path = require('path');

const filename = req.query.file || 'app.log';

// Define safe directory
const safeDir = path.join(__dirname, 'logs');

// Resolve the full path
const requestedPath = path.resolve(safeDir, filename);

// Check if path is within safe directory
if (!requestedPath.startsWith(safeDir)) {
  return res.render('file-viewer', {
    username: req.cookies.username,
    filename,
    content: 'Access denied: Invalid file path'
  });
}

// Check if file exists and is a file (not directory)
if (!fs.existsSync(requestedPath) || !fs.statSync(requestedPath).isFile()) {
  return res.render('file-viewer', {
    username: req.cookies.username,
    filename,
    content: 'File not found'
  });
}

// Safe to read
try {
  const content = fs.readFileSync(requestedPath, 'utf8');
  res.render('file-viewer', { username: req.cookies.username, filename, content });
} catch (error) {
  res.render('file-viewer', {
    username: req.cookies.username,
    filename,
    content: 'Error reading file'
  });
}
```

### Why It Works
- `path.resolve()` resolves `../` sequences
- `startsWith()` check ensures the resolved path is within safe directory
- Additional checks prevent directory listing and non-existent files

### Additional Security
```javascript
// Create a whitelist of allowed files
const allowedFiles = ['app.log', 'error.log', 'access.log'];

if (!allowedFiles.includes(filename)) {
  return res.status(403).send('Access denied');
}
```

---

## Fix 5: IDOR (Insecure Direct Object Reference)

### The Problem
```javascript
// VULNERABLE CODE
const profileId = req.query.id || req.cookies.userId;
db.get(`SELECT * FROM users WHERE id = ?`, [profileId], (err, user) => {
  // Shows any user's profile without authorization check
  res.render('profile', { profile: user });
});
```

### The Solution
```javascript
// SECURE CODE - Add authorization check
const profileId = req.query.id || req.cookies.userId;
const currentUserId = req.cookies.userId;

db.get(`SELECT * FROM users WHERE id = ?`, [profileId], (err, user) => {
  if (err || !user) {
    return res.status(404).send('User not found');
  }

  // AUTHORIZATION CHECK: Users can only view their own profile
  if (user.id !== parseInt(currentUserId)) {
    return res.status(403).send('Access denied: You can only view your own profile');
  }

  res.render('profile', {
    username: req.cookies.username,
    currentUserId,
    profile: user
  });
});
```

### Advanced Solution: Role-Based Access
```javascript
// For admin-only access
db.get(`SELECT * FROM users WHERE id = ?`, [currentUserId], (err, currentUser) => {
  if (currentUser.role !== 'admin' && profileId !== currentUserId) {
    return res.status(403).send('Access denied');
  }
  
  // Proceed to show profile
});
```

### Best Practices
1. **Always verify authorization** before returning data
2. **Use the authenticated user's ID** from the session, not from request parameters
3. **Implement role-based access control** (RBAC) for complex applications
4. **Log access attempts** for security monitoring

---

## Fix 6: Open Redirect

### The Problem
```javascript
// VULNERABLE CODE
const redirectUrl = req.query.redirectUrl || '/dashboard';
res.redirect(redirectUrl); // Redirects to ANY URL!
```

### The Solution - Option 1: Whitelist
```javascript
// SECURE CODE - Whitelist allowed redirects
const redirectUrl = req.query.redirectUrl || '/dashboard';

const allowedRedirects = ['/dashboard', '/profile', '/admin', '/view-log'];

if (!allowedRedirects.includes(redirectUrl)) {
  return res.redirect('/dashboard');
}

res.redirect(redirectUrl);
```

### The Solution - Option 2: Validate Relative URLs
```javascript
// SECURE CODE - Only allow relative URLs
const redirectUrl = req.query.redirectUrl || '/dashboard';

// Check if URL is relative (starts with /)
if (!redirectUrl.startsWith('/') || redirectUrl.startsWith('//')) {
  return res.redirect('/dashboard');
}

// Additional check for dangerous protocols
if (redirectUrl.toLowerCase().startsWith('javascript:') || 
    redirectUrl.toLowerCase().startsWith('data:')) {
  return res.redirect('/dashboard');
}

res.redirect(redirectUrl);
```

### The Solution - Option 3: Use URL Parser
```javascript
// SECURE CODE - Parse and validate URL
const url = require('url');

const redirectUrl = req.query.redirectUrl || '/dashboard';

try {
  const parsed = new URL(redirectUrl, `http://${req.headers.host}`);
  
  // Only allow same-host redirects
  if (parsed.host !== req.headers.host) {
    return res.redirect('/dashboard');
  }
  
  res.redirect(redirectUrl);
} catch (error) {
  res.redirect('/dashboard');
}
```

### Why Open Redirects are Dangerous
- **Phishing attacks**: Victims trust your domain but are redirected to fake sites
- **OAuth/SAML attacks**: Can bypass authentication flows
- **Bypassing security filters**: Some scanners only check the initial URL

---

## Fix 7: Plain Text Password Storage

### The Problem
```javascript
// VULNERABLE CODE
db.run(`INSERT INTO users (username, password, email) 
        VALUES ('admin', 'admin123', 'admin@vulnerable.com')`);

// Later, comparing passwords
if (user.password === inputPassword) { ... }
```

### The Solution
```javascript
// SECURE CODE - Install bcrypt first: npm install bcrypt
const bcrypt = require('bcrypt');
const SALT_ROUNDS = 10;

// When creating users (registration/initialization)
const hashedPassword = await bcrypt.hash('admin123', SALT_ROUNDS);
db.run(`INSERT INTO users (username, password, email) 
        VALUES (?, ?, ?)`, 
       ['admin', hashedPassword, 'admin@vulnerable.com']);

// When logging in
db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
  if (err || !user) {
    return res.render('login', { error: 'Invalid credentials' });
  }

  // Compare hashed password
  const passwordMatch = await bcrypt.compare(password, user.password);
  
  if (passwordMatch) {
    // Login successful
    res.cookie('userId', user.id);
    res.redirect('/dashboard');
  } else {
    res.render('login', { error: 'Invalid credentials' });
  }
});
```

### Complete Secure Initialization
```javascript
// In server.js, update initialization
db.serialize(async () => {
  db.run(`CREATE TABLE users ...`);
  
  // Hash all passwords
  const adminPass = await bcrypt.hash('admin123', SALT_ROUNDS);
  const userPass = await bcrypt.hash('user123', SALT_ROUNDS);
  const alicePass = await bcrypt.hash('password', SALT_ROUNDS);
  
  db.run(`INSERT INTO users (username, password, email) VALUES (?, ?, ?)`,
         ['admin', adminPass, 'admin@vulnerable.com']);
  db.run(`INSERT INTO users (username, password, email) VALUES (?, ?, ?)`,
         ['user', userPass, 'user@vulnerable.com']);
  db.run(`INSERT INTO users (username, password, email) VALUES (?, ?, ?)`,
         ['alice', alicePass, 'alice@vulnerable.com']);
});
```

### Update Profile View
```ejs
<!-- views/profile.ejs - Don't display password -->
<div class="profile-field">
  <strong>Password:</strong> ********** 
  <a href="/change-password">Change Password</a>
</div>
```

### Why Hashing is Essential
- **Database breach protection**: Even if DB is stolen, passwords are not exposed
- **Bcrypt is slow**: Makes brute-force attacks impractical
- **Automatic salting**: Bcrypt includes random salt in each hash
- **Industry standard**: Required by compliance standards (PCI-DSS, etc.)

---

## Additional Security Improvements

### 1. Session Management
```javascript
// Replace cookies with sessions
const session = require('express-session');

app.use(session({
  secret: 'your-secret-key-here-use-env-variable',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true, // Use HTTPS in production
    httpOnly: true, // Prevent XSS from reading cookies
    maxAge: 1800000 // 30 minutes
  }
}));

// Set session
req.session.userId = user.id;

// Check session
if (!req.session.userId) {
  return res.redirect('/login');
}
```

### 2. CSRF Protection
```javascript
const csrf = require('csurf');
const csrfProtection = csrf({ cookie: true });

app.get('/dashboard', csrfProtection, (req, res) => {
  res.render('dashboard', { csrfToken: req.csrfToken() });
});

// In form
// <input type="hidden" name="_csrf" value="<%= csrfToken %>">
```

### 3. Security Headers (Helmet)
```javascript
const helmet = require('helmet');
app.use(helmet());

// Or manually:
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000');
  next();
});
```

### 4. Rate Limiting
```javascript
const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts
  message: 'Too many login attempts, please try again later'
});

app.post('/login', loginLimiter, (req, res) => { ... });
```

### 5. Input Validation
```javascript
const { body, validationResult } = require('express-validator');

app.post('/login',
  body('username').trim().isLength({ min: 3, max: 50 }).isAlphanumeric(),
  body('password').isLength({ min: 8 }),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.render('login', { error: 'Invalid input' });
    }
    // Continue with login
  }
);
```

---

## Testing Your Fixes

After implementing fixes, verify they work:

1. **SQL Injection**: Try `' OR '1'='1` - should NOT bypass login
2. **XSS**: Add `<script>alert('XSS')</script>` - should display as text
3. **Command Injection**: Try `google.com; ls` - should only ping
4. **Path Traversal**: Try `../../package.json` - should be blocked
5. **IDOR**: Try `/profile?id=1` as different user - should be denied
6. **Open Redirect**: Try `?redirectUrl=http://evil.com` - should redirect to dashboard
7. **Passwords**: Check profile - password should be hidden/hashed

---

## Summary Checklist

- [ ] All SQL queries use parameterized statements
- [ ] All user output is escaped (use `<%= %>` not `<%- %>`)
- [ ] Command execution uses `execFile` or libraries, with input validation
- [ ] File access validates paths and restricts to safe directories
- [ ] Authorization checks verify user permissions before showing data
- [ ] Redirects only allow relative URLs or whitelisted destinations
- [ ] Passwords are hashed with bcrypt (or similar)
- [ ] Sessions used instead of cookies for authentication
- [ ] CSRF protection implemented
- [ ] Security headers configured
- [ ] Rate limiting on sensitive endpoints
- [ ] Input validation on all user inputs

---

## Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)
- [Express Security Best Practices](https://expressjs.com/en/advanced/best-practice-security.html)

Happy securing! 🔒
