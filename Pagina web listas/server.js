const path = require('path');
const crypto = require('crypto');
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.disable('x-powered-by');

const PORT = Number(process.env.PORT || 3000);
const SESSION_DAYS = Number(process.env.SESSION_DAYS || 7);
const MAX_ATTEMPTS = Number(process.env.MAX_LOGIN_ATTEMPTS || 5);
const LOCKOUT_MS = Number(process.env.LOGIN_LOCKOUT_MS || 60 * 1000);
const ATTEMPT_TTL_MS = Number(process.env.ATTEMPT_TTL_MS || 15 * 60 * 1000);
const COOKIE_NAME = 'it_setup_session';

const setupPassword = process.env.SETUP_PASSWORD || '';
const setupPasswordHash = process.env.SETUP_PASSWORD_HASH || '';
const setupPasswordSalt = process.env.SETUP_PASSWORD_SALT || '';
const jwtSecret = process.env.JWT_SECRET || '';
const appOrigin = process.env.APP_ORIGIN || '';

if (!jwtSecret) {
  console.error('Missing JWT_SECRET in environment.');
  process.exit(1);
}

if (!setupPassword && !(setupPasswordHash && setupPasswordSalt)) {
  console.error('Missing password config. Use SETUP_PASSWORD or SETUP_PASSWORD_HASH + SETUP_PASSWORD_SALT.');
  process.exit(1);
}

const attemptsByIp = new Map();

setInterval(() => {
  const now = Date.now();
  for (const [ip, state] of attemptsByIp.entries()) {
    if (state.lockUntil > now) continue;
    if (now - state.updatedAt > ATTEMPT_TTL_MS) {
      attemptsByIp.delete(ip);
    }
  }
}, 60 * 1000).unref();

app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
}));

app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());

function audit(event, details) {
  const entry = {
    ts: new Date().toISOString(),
    event,
    ...details,
  };
  console.log(JSON.stringify(entry));
}

function getIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || 'unknown';
}

function verifyPasswordPlain(provided, expected) {
  const a = Buffer.from(provided, 'utf8');
  const b = Buffer.from(expected, 'utf8');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function verifyPasswordHash(provided, hashHex, saltHex) {
  try {
    const derived = crypto.scryptSync(provided, Buffer.from(saltHex, 'hex'), 64);
    const expected = Buffer.from(hashHex, 'hex');
    if (derived.length !== expected.length) return false;
    return crypto.timingSafeEqual(derived, expected);
  } catch {
    return false;
  }
}

function verifyPassword(provided) {
  if (setupPasswordHash && setupPasswordSalt) {
    return verifyPasswordHash(provided, setupPasswordHash, setupPasswordSalt);
  }
  return verifyPasswordPlain(provided, setupPassword);
}

function getAttemptState(ip) {
  const current = attemptsByIp.get(ip);
  if (!current) {
    const init = { count: 0, lockUntil: 0, updatedAt: Date.now() };
    attemptsByIp.set(ip, init);
    return init;
  }

  if (current.lockUntil && current.lockUntil <= Date.now()) {
    current.lockUntil = 0;
    current.count = 0;
  }

  current.updatedAt = Date.now();
  return current;
}

function authRequired(req, res, next) {
  const token = req.cookies[COOKIE_NAME];
  if (!token) {
    return res.status(401).json({ ok: false, message: 'Unauthorized' });
  }

  try {
    const payload = jwt.verify(token, jwtSecret);
    req.user = payload;
    return next();
  } catch {
    return res.status(401).json({ ok: false, message: 'Invalid session' });
  }
}

if (appOrigin) {
  app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (!origin || origin === appOrigin) {
      return next();
    }
    return res.status(403).json({ ok: false, message: 'Forbidden origin' });
  });
}

app.get('/api/health', (req, res) => {
  return res.json({ ok: true, status: 'healthy' });
});

app.post('/api/login', (req, res) => {
  const ip = getIp(req);
  const state = getAttemptState(ip);

  if (state.lockUntil && state.lockUntil > Date.now()) {
    const retryAfterSec = Math.ceil((state.lockUntil - Date.now()) / 1000);
    audit('login_blocked', { ip, retryAfterSec });
    return res.status(429).json({
      ok: false,
      message: 'Too many attempts',
      retryAfterSec,
    });
  }

  const password = (req.body?.password || '').toString();
  if (!password || password.length > 256) {
    audit('login_invalid_payload', { ip });
    return res.status(400).json({ ok: false, message: 'Invalid payload' });
  }

  if (!verifyPassword(password)) {
    state.count += 1;
    state.updatedAt = Date.now();

    if (state.count >= MAX_ATTEMPTS) {
      state.count = 0;
      state.lockUntil = Date.now() + LOCKOUT_MS;
      audit('login_lockout', { ip, lockoutMs: LOCKOUT_MS });
      return res.status(429).json({
        ok: false,
        message: 'Too many attempts',
        retryAfterSec: Math.ceil(LOCKOUT_MS / 1000),
      });
    }

    audit('login_failed', { ip, attemptsLeft: MAX_ATTEMPTS - state.count });
    return res.status(401).json({
      ok: false,
      message: 'Invalid credentials',
      attemptsLeft: MAX_ATTEMPTS - state.count,
    });
  }

  state.count = 0;
  state.lockUntil = 0;
  state.updatedAt = Date.now();

  const token = jwt.sign({ role: 'operator' }, jwtSecret, {
    expiresIn: `${SESSION_DAYS}d`,
    issuer: 'it-setup-backend',
  });

  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: SESSION_DAYS * 24 * 60 * 60 * 1000,
    path: '/',
  });

  audit('login_success', { ip });
  return res.json({ ok: true });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME, { path: '/' });
  audit('logout', { ip: getIp(req) });
  return res.json({ ok: true });
});

app.get('/api/session', authRequired, (req, res) => {
  return res.json({ ok: true, authenticated: true });
});

app.get('/api/secrets', authRequired, (req, res) => {
  return res.json({
    ok: true,
    data: {
      dropbox_email: process.env.DROPBOX_EMAIL || '',
      dropbox_pass: process.env.DROPBOX_PASS || '',
      admin_pass: process.env.ADMIN_PASS || '',
    },
  });
});

app.use(express.static(path.join(__dirname)));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'lista.html'));
});

app.listen(PORT, () => {
  console.log(`IT Setup secure server running on http://localhost:${PORT}`);
});