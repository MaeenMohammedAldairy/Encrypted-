// server.js
'use strict';
/**
 * Advanced POC server:
 * - HTTPS with self-signed cert (auto-generate using 'selfsigned' on first run)
 * - Strong Argon2id with pepper (server-side secret)
 * - JWT (RS256) signed with server RSA keypair (spki/pkcs8)
 * - Server signs users' public keys when registering (signature stored)
 * - SQLite storage via better-sqlite3 with simple backup endpoint
 *
 * Notes:
 * - For production, do NOT use self-signed certs; use real CA certs.
 * - Store server private keys and pepper in secure vault in production.
 */
const fs = require('fs');
const path = require('path');
const https = require('https');
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, param, validationResult } = require('express-validator');
const argon2 = require('argon2');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fse = require('fs-extra');
const selfsigned = require('selfsigned');
const Database = require('better-sqlite3');

const ROOT = __dirname;
const KEYS_DIR = path.join(ROOT, 'keys');
const DATA_DIR = path.join(ROOT, 'data');
const BACKUPS_DIR = path.join(ROOT, 'backups');
fse.ensureDirSync(KEYS_DIR);
fse.ensureDirSync(DATA_DIR);
fse.ensureDirSync(BACKUPS_DIR);

// ------------------ HTTPS cert (self-signed) ------------------
const CERT_PEM = path.join(KEYS_DIR, 'server_cert.pem');
const KEY_PEM = path.join(KEYS_DIR, 'server_key.pem');
if (!fs.existsSync(CERT_PEM) || !fs.existsSync(KEY_PEM)) {
  console.log('Generating self-signed certificate (keys/server_cert.pem, server_key.pem)');
  const attrs = [{ name: 'commonName', value: 'localhost' }];
  const p = selfsigned.generate(attrs, { days: 365, keySize: 2048, algorithm: 'rsa' });
  fs.writeFileSync(CERT_PEM, p.cert);
  fs.writeFileSync(KEY_PEM, p.private);
  fs.chmodSync(KEY_PEM, 0o600);
}

// ------------------ Server RSA keypair for JWT signing & signing public keys ------------------
const JWT_PRIV = path.join(KEYS_DIR, 'jwt_private.pem');
const JWT_PUB = path.join(KEYS_DIR, 'jwt_public.pem');
if (!fs.existsSync(JWT_PRIV) || !fs.existsSync(JWT_PUB)) {
  console.log('Generating server RSA keypair for JWT signing (keys/jwt_*.pem)');
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 4096,
    publicExponent: 0x10001,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  fs.writeFileSync(JWT_PRIV, privateKey, { mode: 0o600 });
  fs.writeFileSync(JWT_PUB, publicKey);
}

// ------------------ Pepper secret ------------------
const PEPPER_FILE = path.join(KEYS_DIR, 'pepper.txt');
if (!fs.existsSync(PEPPER_FILE)) {
  const pepper = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(PEPPER_FILE, pepper, { mode: 0o600 });
}
const PEPPER = fs.readFileSync(PEPPER_FILE, 'utf8').trim();

// ------------------ SQLite DB init ------------------
const DB_FILE = path.join(DATA_DIR, 'poc.db');
const db = new Database(DB_FILE);
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  userId TEXT PRIMARY KEY,
  passwordHash TEXT NOT NULL,
  createdAt INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS public_keys (
  userId TEXT PRIMARY KEY,
  publicKeyJwk TEXT NOT NULL,
  signatureB64 TEXT NOT NULL,
  addedAt INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  recipient TEXT NOT NULL,
  sender TEXT NOT NULL,
  encryptedKeyB64 TEXT NOT NULL,
  ivB64 TEXT NOT NULL,
  ciphertextB64 TEXT NOT NULL,
  ts INTEGER NOT NULL
);
`);

// ------------------ Helpers ------------------
function respondValidationErrors(req, res) {
  const errs = validationResult(req);
  if (!errs.isEmpty()) {
    return res.status(400).json({ errors: errs.array() });
  }
  return null;
}
const JWT_PRIVATE = fs.readFileSync(JWT_PRIV, 'utf8');
const JWT_PUBLIC = fs.readFileSync(JWT_PUB, 'utf8');

function signJwt(payload, expiresIn = '1h') {
  return jwt.sign(payload, JWT_PRIVATE, { algorithm: 'RS256', expiresIn });
}
function verifyJwt(token) {
  try {
    return jwt.verify(token, JWT_PUBLIC, { algorithms: ['RS256'] });
  } catch (e) {
    return null;
  }
}
function requireAuth(req, res, next) {
  const h = req.headers.authorization;
  if (!h || !h.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  const token = h.slice(7);
  const decoded = verifyJwt(token);
  if (!decoded || !decoded.sub) return res.status(401).json({ error: 'Invalid token' });
  req.auth = decoded;
  next();
}
function requireMatchingUserParam(paramName) {
  return (req, res, next) => {
    const target = req.params[paramName] || req.body[paramName];
    if (!target) return res.status(400).json({ error: 'missing user identifier' });
    if (!req.auth || req.auth.sub !== target) return res.status(403).json({ error: 'forbidden: user mismatch' });
    return next();
  };
}

// sign a user's public key (JWK JSON string) using server private key (PKCS#1/PKCS8 PEM)
function signPublicKeyJwk(jwkObject) {
  const payload = JSON.stringify(jwkObject);
  const signer = crypto.createSign('sha256');
  signer.update(payload);
  signer.end();
  const sig = signer.sign(JWT_PRIVATE); // sign with server private key
  return sig.toString('base64');
}

// verify signature of JWK with server public key
function verifySignatureOfJwk(jwkObject, signatureB64) {
  const payload = JSON.stringify(jwkObject);
  const verifier = crypto.createVerify('sha256');
  verifier.update(payload);
  verifier.end();
  const ok = verifier.verify(JWT_PUBLIC, Buffer.from(signatureB64, 'base64'));
  return !!ok;
}

// ------------------ Express setup ------------------
const app = express();
app.use(helmet());
app.use(cors({ origin: true }));
app.use(bodyParser.json({ limit: '5mb' }));

// rate limits
const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  message: { error: 'Too many requests, slow down' }
});
app.use('/auth', authLimiter);

// serve static client
app.use(express.static(path.join(ROOT, 'public')));

// expose server public key PEM for clients to verify signatures
app.get('/server-public.pem', (req, res) => {
  res.type('text').send(JWT_PUBLIC);
});

// ------------------ Auth endpoints ------------------
// Register: Argon2id with stronger params and pepper
app.post('/auth/register',
  body('userId').isAlphanumeric().isLength({ min: 3, max: 32 }),
  body('password').isLength({ min: 12, max: 1024 }),
  async (req, res) => {
    if (respondValidationErrors(req, res)) return;
    const { userId, password } = req.body;
    const row = db.prepare('SELECT userId FROM users WHERE userId = ?').get(userId);
    if (row) return res.status(400).json({ error: 'user exists' });
    try {
      // stronger Argon2id: memoryCost 256MB, timeCost 4, parallelism 2
      const pwdPlusPepper = password + PEPPER;
      const hash = await argon2.hash(pwdPlusPepper, { type: argon2.argon2id, memoryCost: 262144, timeCost: 4, parallelism: 2 });
      const now = Date.now();
      db.prepare('INSERT INTO users (userId, passwordHash, createdAt) VALUES (?,?,?)').run(userId, hash, now);
      return res.json({ ok: true });
    } catch (e) {
      console.error(e);
      return res.status(500).json({ error: 'server error' });
    }
  }
);

// Login: verify Argon2 hash (prepend pepper) then issue JWT
app.post('/auth/login',
  body('userId').isAlphanumeric().isLength({ min: 3, max: 32 }),
  body('password').isLength({ min: 12, max: 1024 }),
  async (req, res) => {
    if (respondValidationErrors(req, res)) return;
    const { userId, password } = req.body;
    const row = db.prepare('SELECT passwordHash FROM users WHERE userId = ?').get(userId);
    if (!row) return res.status(400).json({ error: 'invalid credentials' });
    try {
      const ok = await argon2.verify(row.passwordHash, password + PEPPER);
      if (!ok) return res.status(400).json({ error: 'invalid credentials' });
      const token = signJwt({ sub: userId }, '6h');
      return res.json({ token, expiresIn: 6 * 3600 });
    } catch (e) {
      console.error(e);
      return res.status(500).json({ error: 'server error' });
    }
  }
);

// ------------------ Key registration & retrieval ------------------
// register public key (signed by server)
app.post('/register-key',
  requireAuth,
  body('userId').isAlphanumeric().isLength({ min: 3, max: 32 }),
  body('publicKeyJwk').isObject(),
  requireMatchingUserParam('userId'),
  (req, res) => {
    if (respondValidationErrors(req, res)) return;
    const { userId, publicKeyJwk } = req.body;
    const signatureB64 = signPublicKeyJwk(publicKeyJwk);
    const now = Date.now();
    db.prepare('INSERT OR REPLACE INTO public_keys (userId, publicKeyJwk, signatureB64, addedAt) VALUES (?,?,?,?)')
      .run(userId, JSON.stringify(publicKeyJwk), signatureB64, now);
    return res.json({ ok: true, signatureB64 });
  }
);

// get public key and signature
app.get('/get-key/:userId',
  requireAuth,
  param('userId').isAlphanumeric().isLength({ min: 3, max: 32 }),
  (req, res) => {
    if (respondValidationErrors(req, res)) return;
    const userId = req.params.userId;
    const row = db.prepare('SELECT publicKeyJwk, signatureB64 FROM public_keys WHERE userId = ?').get(userId);
    if (!row) return res.status(404).json({ error: 'not found' });
    return res.json({ userId, publicKeyJwk: JSON.parse(row.publicKeyJwk), signatureB64: row.signatureB64 });
  }
);

// ------------------ Messaging ------------------
app.post('/send-message',
  requireAuth,
  body('from').isAlphanumeric().isLength({ min: 3, max: 32 }),
  body('to').isAlphanumeric().isLength({ min: 3, max: 32 }),
  body('encryptedKeyB64').isString(),
  body('ivB64').isString(),
  body('ciphertextB64').isString(),
  requireMatchingUserParam('from'),
  (req, res) => {
    if (respondValidationErrors(req, res)) return;
    const { from, to, encryptedKeyB64, ivB64, ciphertextB64 } = req.body;
    const now = Date.now();
    db.prepare('INSERT INTO messages (recipient, sender, encryptedKeyB64, ivB64, ciphertextB64, ts) VALUES (?,?,?,?,?,?)')
      .run(to, from, encryptedKeyB64, ivB64, ciphertextB64, now);
    return res.json({ ok: true });
  }
);

app.get('/messages/:userId',
  requireAuth,
  param('userId').isAlphanumeric().isLength({ min: 3, max: 32 }),
  requireMatchingUserParam('userId'),
  (req, res) => {
    if (respondValidationErrors(req, res)) return;
    const userId = req.params.userId;
    const rows = db.prepare('SELECT sender AS from, encryptedKeyB64, ivB64, ciphertextB64, ts FROM messages WHERE recipient = ? ORDER BY ts ASC').all(userId);
    return res.json({ messages: rows });
  }
);

app.get('/users', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT userId FROM public_keys').all();
  return res.json({ users: rows.map(r => r.userId) });
});

// ------------------ Backup endpoint ------------------
// create a timestamped copy of DB in backups/
app.post('/backup', requireAuth, (req, res) => {
  // Allow only a designated admin user to trigger backups
  try {
    const ADMIN = process.env.ADMIN_USER || 'admin';
    if (!req.auth || req.auth.sub !== ADMIN) {
      return res.status(403).json({ error: 'forbidden: backup requires admin' });
    }
    const ts = Date.now();
    const dest = path.join(BACKUPS_DIR, `poc-db-backup-${ts}.db`);
    fs.copyFileSync(DB_FILE, dest);
    return res.json({ ok: true, backup: dest });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'backup failed' });
  }
});

// ------------------ Start HTTPS server ------------------
const cert = fs.readFileSync(CERT_PEM);
const key = fs.readFileSync(KEY_PEM);
const httpsServer = https.createServer({ key: key, cert: cert }, app);

const PORT = process.env.PORT || 3443;
httpsServer.listen(PORT, () => console.log(`Secure HTTPS POC Server running on https://localhost:${PORT}`));
