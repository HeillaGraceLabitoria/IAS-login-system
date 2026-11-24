/*
 * Student: Labitoria, Heilla Grace A. | BSIT 3A
 * Subject: Information Assurance and Security (IAS) — Final Project
 */
import express from 'express';
import cors from 'cors';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

const app = express();
const PORT = 5000;

app.use(cors());
app.use(express.json());

// Track IP-level failed attempts so wrong usernames also trigger the 3-strike lockout
const ipAttempts = new Map();

// 1. Initialize Local SQLite Database
const db = new DatabaseSync('./ias_security.sqlite');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT DEFAULT 'Administrator',
    failed_attempts INTEGER DEFAULT 0,
    locked_until INTEGER DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS login_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username_attempted TEXT NOT NULL,
    status TEXT NOT NULL,
    security_note TEXT,
    ip_address TEXT,
    attempt_time TEXT DEFAULT CURRENT_TIMESTAMP
  );
`);

// Salted Password Hashing (Confidentiality)
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}

function verifyPassword(password, salt, storedHash) {
  const { hash } = hashPassword(password, salt);
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(storedHash, 'hex'));
}

// Seed 'admin' with password 'admin123' (stored strictly as salted hash)
const checkAdmin = db.prepare('SELECT id FROM users WHERE username = ?').get('admin');
if (!checkAdmin) {
  const { salt, hash } = hashPassword('admin123');
  db.prepare('INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)')
    .run('admin', hash, salt, 'Administrator');
}

const insertLog = db.prepare(`
  INSERT INTO login_logs (username_attempted, status, security_note, ip_address)
  VALUES (?, ?, ?, ?)
`);

// 2. Secure Login Endpoint
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const clientIp = req.ip || '127.0.0.1';
  const now = Date.now();

  if (!username || !password || typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ success: false, message: 'Invalid input format.' });
  }

  // Check IP-level lockout first (covers 3 wrong username attempts)
  const ipState = ipAttempts.get(clientIp) || { count: 0, lockedUntil: 0 };
  if (ipState.lockedUntil > now) {
    const secondsLeft = Math.ceil((ipState.lockedUntil - now) / 1000);
    insertLog.run(username, 'LOCKED', `Blocked during ${secondsLeft}s IP lockout window`, clientIp);
    return res.status(429).json({
      success: false,
      locked: true,
      secondsLeft,
      message: `Warning! System locked due to wrong credentials. Try again in ${secondsLeft}s.`
    });
  }

  const isAttackPayload = /('|--|;|<script>|OR\s+1=1)/i.test(username);

  // Parameterized query prevents SQL Injection
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username.trim());

  // CASE A: Wrong Username
  if (!user) {
    const newIpCount = ipState.count + 1;
    const note = isAttackPayload
      ? 'SQLi/XSS payload neutralized by parameterized query'
      : `Wrong username rejected (Attempt ${newIpCount}/3)`;

    if (newIpCount >= 3) {
      ipAttempts.set(clientIp, { count: 0, lockedUntil: now + 30 * 1000 });
      insertLog.run(username, 'LOCKED', '3 wrong username attempts — Locked for 30s', clientIp);
      return res.status(429).json({
        success: false,
        locked: true,
        secondsLeft: 30,
        message: 'Wrong username (Attempt 3 of 3). Locked for 30s.'
      });
    }

    ipAttempts.set(clientIp, { count: newIpCount, lockedUntil: 0 });
    insertLog.run(username, 'FAILED', note, clientIp);
    return res.status(401).json({
      success: false,
      message: `Wrong username: "${username.trim()}" is not registered. (Attempt ${newIpCount} of 3)`
    });
  }

  // Account-level Brute-Force Lockout Check (covers 3 wrong password attempts)
  if (user.locked_until && user.locked_until > now) {
    const secondsLeft = Math.ceil((user.locked_until - now) / 1000);
    insertLog.run(username, 'LOCKED', `Blocked during ${secondsLeft}s lockout window`, clientIp);
    return res.status(429).json({
      success: false,
      locked: true,
      secondsLeft,
      message: `Account locked due to wrong passwords. Try again in ${secondsLeft}s.`
    });
  }

  // Clear any expired lockout state from SQLite before counting a new cycle
  let currentFailedAttempts = user.failed_attempts;
  if (user.locked_until && user.locked_until <= now) {
    currentFailedAttempts = 0;
    db.prepare('UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE id = ?').run(user.id);
  }

  const isValid = verifyPassword(password, user.salt, user.password_hash);

  // CASE B: Valid Username, Wrong Password
  if (!isValid) {
    const newAttempts = currentFailedAttempts + 1;
    if (newAttempts >= 3) {
      const lockUntil = now + 30 * 1000;
      db.prepare('UPDATE users SET failed_attempts = 0, locked_until = ? WHERE id = ?')
        .run(lockUntil, user.id);
      insertLog.run(username, 'LOCKED', '3 wrong password attempts — Account locked for 30s', clientIp);

      return res.status(429).json({
        success: false,
        locked: true,
        secondsLeft: 30,
        message: 'Wrong password (Attempt 3 of 3). Account locked for 30s.'
      });
    } else {
      db.prepare('UPDATE users SET failed_attempts = ? WHERE id = ?').run(newAttempts, user.id);
      insertLog.run(username, 'FAILED', `Wrong password (Attempt ${newAttempts}/3)`, clientIp);

      return res.status(401).json({
        success: false,
        message: `Wrong password for "${user.username}". (Attempt ${newAttempts} of 3)`
      });
    }
  }

  // Password Strength Audit Check (IAS Password Policy demonstration)
  const isWeakPassword = password.length < 10 || !/[!@#$%^&*]/.test(password);
  const loginNote = isWeakPassword
    ? 'Authenticated (IAS Policy Notice: Default/Weak password detected — recommend rotation)'
    : 'Authenticated via scrypt salted hash';

  // Clear both IP and account failed counters on valid login
  ipAttempts.delete(clientIp);
  db.prepare('UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE id = ?').run(user.id);

  const sessionToken = crypto.randomBytes(24).toString('hex');
  insertLog.run(username, 'SUCCESS', loginNote, clientIp);

  return res.json({
    success: true,
    result: 'logged in',
    passwordPolicyWarning: isWeakPassword
      ? 'IAS Password Policy Alert: "admin123" lacks uppercase/special characters, but is protected at rest via salted scrypt hashing.'
      : null,
    user: {
      id: user.id,
      username: user.username,
      role: user.role,
      sessionToken
    }
  });
});

// 3. Fetch Audit Logs & Users
app.get('/api/security-data', (req, res) => {
  const logs = db.prepare('SELECT * FROM login_logs ORDER BY id DESC LIMIT 8').all();
  const users = db.prepare('SELECT id, username, role, password_hash, salt, failed_attempts FROM users').all();
  res.json({ logs, users });
});

app.listen(PORT, () => {
  console.log(`IAS Security Server running at http://localhost:${PORT}`);
});