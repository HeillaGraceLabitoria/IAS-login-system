/*
 * Student: Labitoria, Heilla Grace A. | BSIT 3A
 * Subject: Information Assurance and Security (IAS) — Final Project
 */
import React, { useState, useEffect } from 'react';
import './index.css';

interface UserSession {
  id: number;
  username: string;
  role: string;
  sessionToken: string;
  passwordPolicyWarning?: string | null;
}

interface LoginLog {
  id: number;
  username_attempted: string;
  status: string;
  security_note: string;
  attempt_time: string;
}

interface DbUserRow {
  id: number;
  username: string;
  role: string;
  password_hash: string;
  salt: string;
  failed_attempts: number;
}

export default function App() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPw, setShowPw] = useState(false);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const [lockSeconds, setLockSeconds] = useState(0);

  const [session, setSession] = useState<UserSession | null>(null);
  const [logs, setLogs] = useState<LoginLog[]>([]);
  const [dbUsers, setDbUsers] = useState<DbUserRow[]>([]);

  useEffect(() => {
    if (lockSeconds <= 0) return;
    const timer = setInterval(() => {
      setLockSeconds((prev) => {
        if (prev <= 1) {
          setErrorMsg('');
          return 0;
        }
        return prev - 1;
      });
    }, 1000);
    return () => clearInterval(timer);
  }, [lockSeconds]);

  const fetchSecurityData = async () => {
    try {
      const res = await fetch('/api/security-data');
      const data = await res.json();
      setLogs(data.logs || []);
      setDbUsers(data.users || []);
    } catch (err) {
      console.error('Failed to load SQLite security tables', err);
    }
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setErrorMsg('');

    try {
      const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });

      const data = await res.json();

      if (!res.ok || !data.success) {
        if (data.locked && data.secondsLeft) {
          setLockSeconds(data.secondsLeft);
        }
        setErrorMsg(data.message || 'Authentication failed.');
      } else {
        setSession({
          ...data.user,
          passwordPolicyWarning: data.passwordPolicyWarning,
        });
        await fetchSecurityData();
      }
    } catch {
      setErrorMsg('Cannot connect to local SQLite backend (port 5000).');
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    setSession(null);
    setUsername('');
    setPassword('');
    setErrorMsg('');
  };

  return (
    <div className="app-shell">
      <nav className="navbar">
        <div className="brand">
          <span>IAS Gatekeeper</span>
          <span className="brand-badge">SQLite + Node Auth</span>
        </div>
        <div className="nav-links">
          <span className={!session ? 'active' : ''}>Login Portal</span>
          <span className={session ? 'active' : ''}>Security Audit</span>
        </div>
      </nav>

      <main className="main-wrapper">
        {!session ? (
          <section className="auth-card">
            <div className="card-header">
              <div className="eyebrow">Information Assurance & Security</div>
              <h1>System Log In</h1>
              <p>Local SQLite authentication protected by salted scrypt hashing.</p>
            </div>

            <div className="card-body">
              <form onSubmit={handleLogin}>
                <div className="form-group">
                  <label htmlFor="username">Username</label>
                  <input
                    id="username"
                    type="text"
                    placeholder="admin"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    disabled={lockSeconds > 0}
                    required
                  />
                </div>

                <div className="form-group">
                  <label htmlFor="password">Password</label>
                  <div className="password-wrapper">
                    <input
                      id="password"
                      type={showPw ? 'text' : 'password'}
                      placeholder="••••••••••••"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      disabled={lockSeconds > 0}
                      required
                    />
                    <button
                      type="button"
                      className="toggle-pw"
                      onClick={() => setShowPw(!showPw)}
                    >
                      {showPw ? 'Hide' : 'Show'}
                    </button>
                  </div>
                </div>

                <button
                  type="submit"
                  className="btn-primary"
                  disabled={loading || lockSeconds > 0}
                >
                  {lockSeconds > 0
                    ? `Locked (${lockSeconds}s)`
                    : loading
                    ? 'Verifying...'
                    : 'Log In'}
                </button>

                {errorMsg && (
                  <div className="alert-danger">
                    {lockSeconds > 0
                      ? `Brute-Force Protection: Account locked. Try again in ${lockSeconds}s.`
                      : errorMsg}
                  </div>
                )}
              </form>
            </div>

      
          </section>
        ) : (
          <section className="dashboard-card">
            <div className="dash-header">
              <div>
                <span className="status-pill">● Result: Logged In</span>
                <h2 style={{ color: 'var(--text-white)', marginTop: '0.5rem' }}>
                  Welcome, {session.username}
                </h2>
                <p style={{ color: 'var(--text-caption)', fontSize: '0.85rem' }}>
                  Role: {session.role} • Session Token: <code>{session.sessionToken}</code>
                </p>
              </div>
              <button className="btn-logout" onClick={handleLogout}>
                Log Out
              </button>
            </div>

            <div className="dash-body">
              {session.passwordPolicyWarning && (
                <div
                  style={{
                    backgroundColor: 'rgba(149, 184, 162, 0.14)',
                    border: '1px solid var(--border-mint)',
                    color: 'var(--text-mist)',
                    padding: '0.85rem 1rem',
                    borderRadius: '8px',
                    marginBottom: '1.25rem',
                    fontSize: '0.85rem',
                  }}
                >
                  <strong>🛡️ {session.passwordPolicyWarning}</strong>
                </div>
              )}

              <div className="ias-grid">
                <div className="ias-widget">
                  <h4>Confidentiality (Hashing)</h4>
                  <p>
                    Passwords are never saved in plaintext—salted & hashed using{' '}
                    <strong>crypto.scryptSync</strong> + timing-safe verification.
                  </p>
                </div>
                <div className="ias-widget">
                  <h4>Integrity (SQLi & XSS)</h4>
                  <p>
                    All SQLite queries use <strong>db.prepare()</strong> parameterized bindings;
                    React auto-escapes DOM outputs against XSS.
                  </p>
                </div>
                <div className="ias-widget">
                  <h4>Availability (Rate Limit)</h4>
                  <p>
                    3 consecutive failed attempts trigger a database-enforced{' '}
                    <strong>30-second lockout</strong> against brute-force attacks.
                  </p>
                </div>
              </div>

              <h3 className="section-title">SQLite `users` Table (Proof of Salted Hashing)</h3>
              <table>
                <thead>
                  <tr>
                    <th>Username</th>
                    <th>Role</th>
                    <th>Salt (Hex)</th>
                    <th>Password Hash (Scrypt)</th>
                  </tr>
                </thead>
                <tbody>
                  {dbUsers.map((u) => (
                    <tr key={u.id}>
                      <td>{u.username}</td>
                      <td>{u.role}</td>
                      <td><code>{u.salt.slice(0, 14)}...</code></td>
                      <td><code>{u.password_hash.slice(0, 24)}...</code></td>
                    </tr>
                  ))}
                </tbody>
              </table>

              <h3 className="section-title">SQLite `login_logs` Table (Non-Repudiation Audit Trail)</h3>
              <table>
                <thead>
                  <tr>
                    <th>Username Attempted</th>
                    <th>Status</th>
                    <th>Security Event</th>
                    <th>Timestamp (UTC)</th>
                  </tr>
                </thead>
                <tbody>
                  {logs.map((log) => (
                    <tr key={log.id}>
                      <td>{log.username_attempted}</td>
                      <td className={log.status === 'SUCCESS' ? 'badge-success' : 'badge-failed'}>
                        {log.status}
                      </td>
                      <td>{log.security_note}</td>
                      <td>{log.attempt_time}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        )}
      </main>
    </div>
  );
}