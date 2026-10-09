/**
 * SCENARIO75 - "Admin Feedback System"
 * Intentionally vulnerable Node.js application for the Cyber Range Engineering
 * practical assessment (Red vs. Blue lab).
 *
 * Author: Asyam Adithakarya Erdi Pribadi
 *
 * WARNING: This application is deliberately insecure. It must never be
 * deployed outside an isolated lab network (see README.md).
 *
 * Vulnerability chain implemented:
 *   1. Pre-auth session cookie (pre_mfa_session) issued with HttpOnly=false.
 *   2. Naive WAF blocks <script> but is bypassable with <svg onload=...>.
 *   3. WAF also string-matches "document.cookie", forcing bracket-notation
 *      obfuscation (window['docu'+'ment']['coo'+'kie']) to exfiltrate cookies.
 *   4. /dashboard trusts the mere PRESENCE of pre_mfa_session as proof of a
 *      completed login and never calls /api/verify-mfa before granting an
 *      authenticated adm_sess cookie (the core logic flaw: MFA bypass via
 *      cookie reuse / session replay).
 */

const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3075;

app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Intentionally expose the backend technology (Phase 1: Reconnaissance)
app.disable('x-powered-by'); // remove Express' default so we can set our own exact value
app.use((req, res, next) => {
  res.setHeader('X-Powered-By', 'Node.js');
  next();
});

// In-memory "database" - last feedback comment, reflected unescaped on /dashboard
// to simulate the stored-XSS execution context for grading purposes.
let lastFeedback = 'No feedback submitted yet.';

// -----------------------------------------------------------------------
// PHASE 1: RECONNAISSANCE
// -----------------------------------------------------------------------

app.get('/robots.txt', (req, res) => {
  res.type('text/plain').send(
    [
      'User-agent: *',
      'Disallow: /api/verify-mfa',
      '',
    ].join('\n')
  );
});

app.get('/', (req, res) => {
  // Pre-authentication session cookie. HttpOnly is explicitly FALSE so that
  // client-side JavaScript (and any injected XSS payload) can read it -
  // this is the root cookie-handling flaw the scenario asks for.
  res.cookie('pre_mfa_session', 'pending_mfa_verification', {
    httpOnly: false,
    path: '/',
    sameSite: 'Lax',
  });

  res.type('html').send(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Admin Feedback System</title>
  <!--
  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
  ░  ___       _          _____         _     ░
  ░ | _ \\___ | |__  ___ |_   _|___ __ _| |__ ░
  ░ |   / _ \\| '_ \\/ _ \\  | | / -_) _\` | '_ \\░
  ░ |_|_\\___/|_.__/\\___/  |_| \\___\\__,_|_.__/░
  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
       Lost? Robots usually know where not
             to look. Check robots.txt.
  -->
</head>
<body>
  <h1>Admin Feedback System</h1>
  <p>Please submit any feedback about our internal tools below. An administrator reviews all submissions.</p>
  <form id="fb" method="POST" action="/api/feedback">
    <textarea name="comment" rows="4" cols="50" placeholder="Your feedback..."></textarea><br>
    <button type="submit">Submit Feedback</button>
  </form>
  <p style="color:#888;font-size:12px;">Admin Feedback System v1.0</p>
</body>
</html>`);
});

// -----------------------------------------------------------------------
// PHASE 2: DEFENSE EVASION (WAF & XSS)
// -----------------------------------------------------------------------

// Reject anything but POST on the feedback endpoint
app.all('/api/feedback', (req, res, next) => {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed. Use POST.' });
  }
  next();
});

function wafBlocks(payload) {
  if (!payload) return false;
  const lowered = payload.toLowerCase();
  // Rule 1: block the obvious <script> vector
  if (lowered.includes('<script')) return true;
  // Rule 2: block direct, literal document.cookie keyword access
  // (bypassable via bracket-notation + string concatenation obfuscation)
  if (lowered.includes('document.cookie')) return true;
  return false;
}

app.post('/api/feedback', (req, res) => {
  const comment = (req.body && req.body.comment) || '';

  if (wafBlocks(comment)) {
    return res.status(403).json({
      error: 'Blocked by WAF',
      rule: 'SIG-XSS-001',
    });
  }

  // Stored, unescaped by design - this is the sink the XSS payload lands in.
  lastFeedback = comment;
  return res.status(200).json({ status: 'Feedback received. Thank you.' });
});

// -----------------------------------------------------------------------
// PHASE 3: INITIAL ACCESS (MFA Bypass & Session Replay)
// -----------------------------------------------------------------------

// The "real" MFA endpoint. It exists and would work if ever called - but the
// /dashboard route below never calls it, which is the vulnerability.
app.get('/api/verify-mfa', (req, res) => {
  res.status(200).json({
    status: 'MFA verification endpoint reached directly (not used by /dashboard).',
  });
});

app.get('/dashboard', (req, res) => {
  const cookies = req.cookies || {};

  // Already holds a fully authenticated administrative session.
  if (cookies.adm_sess) {
    return renderDashboard(res);
  }

  // VULNERABILITY: mere possession/replay of pre_mfa_session is treated as
  // sufficient proof of identity. The backend issues an authenticated
  // adm_sess cookie WITHOUT ever redirecting to or calling /api/verify-mfa.
  if (cookies.pre_mfa_session) {
    const token = crypto.randomBytes(16).toString('hex');
    res.cookie('adm_sess', token, {
      httpOnly: true,
      path: '/',
      sameSite: 'Lax',
    });
    return renderDashboard(res);
  }

  return res.status(401).send('Access denied. Please visit / first.');
});

function renderDashboard(res) {
  res.type('html').send(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Admin Dashboard</title>
</head>
<body>
  <h1>Administrative Dashboard</h1>
  <p>Welcome, administrator. Below is the most recent feedback submission:</p>
  <div class="xss-payload">${lastFeedback}</div>

  <!-- SCENARIO75{RED_C00k13_MFA_Byp4ss_0wn3d} -->
  <div style="display:none" id="victory-flag">SCENARIO75{RED_C00k13_MFA_Byp4ss_0wn3d}</div>

  <hr>
  <p style="color:#888;font-size:12px;">Session established without MFA verification step.</p>
</body>
</html>`);
}

// -----------------------------------------------------------------------

app.use((req, res) => {
  res.status(404).send('Not Found');
});

app.listen(PORT, () => {
  console.log(`Admin Feedback System listening on port ${PORT}`);
});
