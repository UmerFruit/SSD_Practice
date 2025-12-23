# 🔓 Vulnerable Task Manager - Educational Security Workshop

⚠️ **WARNING**: This application contains intentional security vulnerabilities for educational purposes only. **DO NOT deploy to production or any public environment!**

## 📋 Overview

This is a deliberately vulnerable Node.js web application designed to teach secure coding practices. It demonstrates common web application vulnerabilities that developers should learn to identify and fix.

## 🛠️ Tech Stack

- **Backend**: Node.js with Express
- **Database**: SQLite3 (in-memory, raw SQL queries)
- **Frontend**: EJS (Embedded JavaScript templating)
- **Styling**: Vanilla CSS

## 🚀 Installation & Setup

```bash
# Install dependencies
npm install

# Start the server
npm start
```

The application will run on: **http://localhost:3000**

## 👥 Test Accounts

| Username | Password   | Role  |
|----------|-----------|-------|
| admin    | admin123  | Admin |
| user     | user123   | User  |
| alice    | password  | User  |

## 🐛 Vulnerabilities Included

### 1. SQL Injection (Login System)

**Location**: `POST /login` route in [server.js](server.js)

**Vulnerability**: The login query uses string concatenation to build SQL queries, making it vulnerable to SQL injection attacks.

**How to Test**:
1. Go to the login page
2. Enter as username: `' OR '1'='1`
3. Enter any password (or use the same: `' OR '1'='1`)
4. You'll be logged in without valid credentials!

**Why it's vulnerable**:
```javascript
// BAD - String concatenation
const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
```

**Fix**: Use parameterized queries:
```javascript
// GOOD - Parameterized query
db.get(`SELECT * FROM users WHERE username = ? AND password = ?`, [username, password], ...);
```

---

### 2. Stored XSS (Task Dashboard)

**Location**: `/dashboard` route and [views/dashboard.ejs](views/dashboard.ejs)

**Vulnerability**: User input is stored in the database and rendered without escaping, allowing JavaScript execution.

**How to Test**:
1. Login with any account
2. Add a new task with content: `<script>alert('XSS')</script>`
3. Submit the task
4. The alert will execute when the page loads!

**Other XSS payloads to try**:
- `<img src=x onerror=alert('XSS')>`
- `<svg onload=alert('XSS')>`
- `<iframe src="javascript:alert('XSS')">`

**Why it's vulnerable**:
```ejs
<!-- BAD - Unescaped output -->
<%- task.content %>
```

**Fix**: Use escaped output:
```ejs
<!-- GOOD - Escaped output -->
<%= task.content %>
```

---

### 3. OS Command Injection (Admin Panel)

**Location**: `POST /ping` route in [server.js](server.js)

**Vulnerability**: User input is directly concatenated into shell commands without validation.

**How to Test**:
1. Login and navigate to **Admin** page
2. In the "Ping a Website" field, try these payloads:

**Windows**:
- `google.com & dir` - Lists directory contents
- `google.com & whoami` - Shows current user
- `google.com & type server.js` - Reads server.js file
- `127.0.0.1 & net user` - Lists system users

**Linux/Mac**:
- `google.com; ls` - Lists directory contents
- `google.com; whoami` - Shows current user
- `google.com; cat server.js` - Reads server.js file

**Why it's vulnerable**:
```javascript
// BAD - Direct concatenation into shell command
const command = `ping -n 2 ${website}`;
exec(command, ...);
```

**Fix**: Validate input and use safer alternatives or parameterized commands.

---

### 4. Path Traversal (File Viewer)

**Location**: `GET /view-log` route in [server.js](server.js)

**Vulnerability**: The file parameter is directly passed to `fs.readFileSync()` without validation, allowing access to any file on the system.

**How to Test**:
1. Login and navigate to **Logs** page
2. Try these URLs:
   - `/view-log?file=package.json` - Read package.json
   - `/view-log?file=server.js` - Read server source code
   - `/view-log?file=..\..\..\..\Windows\System32\drivers\etc\hosts` - Read system files (Windows)
   - `/view-log?file=../../../../etc/passwd` - Read system files (Linux/Mac)

**Why it's vulnerable**:
```javascript
// BAD - No path validation
const filename = req.query.file || 'app.log';
const content = fs.readFileSync(filename, 'utf8');
```

**Fix**: Validate the file path and restrict access to a specific directory:
```javascript
// GOOD - Path validation
const safeBasePath = path.join(__dirname, 'logs');
const safePath = path.normalize(path.join(safeBasePath, filename));
if (!safePath.startsWith(safeBasePath)) {
  throw new Error('Invalid path');
}
```

---

### 5. IDOR - Insecure Direct Object Reference (User Profile)

**Location**: `GET /profile` route in [server.js](server.js)

**Vulnerability**: Users can view any user's profile by changing the ID parameter without authorization checks.

**How to Test**:
1. Login as `user` (ID: 2)
2. Navigate to **Profile** page
3. Change the URL to `/profile?id=1`
4. You can now see admin's profile including their plain text password!
5. Try other IDs: `/profile?id=3` (alice's profile)

**Why it's vulnerable**:
```javascript
// BAD - No authorization check
const profileId = req.query.id || req.cookies.userId;
db.get(`SELECT * FROM users WHERE id = ?`, [profileId], ...);
// Displays profile without checking if current user should have access
```

**Fix**: Add authorization checks:
```javascript
// GOOD - Check authorization
if (profileId !== req.cookies.userId) {
  return res.status(403).send('Access denied');
}
```

---

### 6. Open Redirect (Login Redirect)

**Location**: `POST /login` route in [server.js](server.js)

**Vulnerability**: After successful login, the application redirects to a URL specified in the query parameter without validation.

**How to Test**:
1. Logout if logged in
2. Visit: `http://localhost:3000/login?redirectUrl=http://evil.com`
3. Login with valid credentials
4. You'll be redirected to the external site!

**Why it's vulnerable**:
```javascript
// BAD - Unvalidated redirect
const redirectUrl = req.query.redirectUrl || '/dashboard';
res.redirect(redirectUrl);
```

**Fix**: Validate the redirect URL:
```javascript
// GOOD - Validate redirect URL
const redirectUrl = req.query.redirectUrl || '/dashboard';
if (!redirectUrl.startsWith('/')) {
  return res.redirect('/dashboard');
}
res.redirect(redirectUrl);
```

---

### 7. Plain Text Password Storage

**Location**: Database initialization in [server.js](server.js)

**Vulnerability**: Passwords are stored in plain text in the database.

**How to Test**:
1. Login and go to any user's profile
2. You can see the password in plain text!

**Why it's vulnerable**:
```javascript
// BAD - Plain text passwords
db.run(`INSERT INTO users (username, password, email) VALUES ('admin', 'admin123', ...)`);
```

**Fix**: Hash passwords before storing:
```javascript
// GOOD - Hashed passwords
const bcrypt = require('bcrypt');
const hashedPassword = await bcrypt.hash('admin123', 10);
db.run(`INSERT INTO users (username, password, email) VALUES ('admin', ?, ...)`, [hashedPassword]);
```

---

## 📚 Learning Objectives

By working with this vulnerable application, you will:

1. **Identify** common web application vulnerabilities
2. **Understand** how attackers exploit these vulnerabilities
3. **Practice** fixing security issues in real code
4. **Learn** secure coding best practices

## 🔧 Exercise: Fix the Vulnerabilities!

Your task is to fix all 7 vulnerabilities in this application:

1. **SQL Injection**: Implement parameterized queries
2. **Stored XSS**: Escape user input when rendering
3. **Command Injection**: Validate input and use safer alternatives
4. **Path Traversal**: Validate and restrict file access
5. **IDOR**: Implement proper authorization checks
6. **Open Redirect**: Validate redirect URLs
7. **Password Storage**: Implement password hashing with bcrypt

## 🎯 Additional Security Improvements

After fixing the main vulnerabilities, consider implementing:

- **Session Management**: Use express-session instead of cookies
- **CSRF Protection**: Implement CSRF tokens
- **Security Headers**: Use Helmet.js
- **Rate Limiting**: Prevent brute force attacks
- **Input Validation**: Validate all user inputs
- **HTTPS**: Use HTTPS in production
- **Error Handling**: Don't expose sensitive error details
- **Logging**: Implement security event logging

## 📖 Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)

## ⚖️ License

This project is for educational purposes only. Use responsibly.

## 🙏 Acknowledgments

Created for security awareness and training purposes. Always practice secure coding!

---

**Remember**: Security is not a feature, it's a requirement! 🔒
