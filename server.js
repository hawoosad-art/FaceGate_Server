/**
 * facedocs.bond — FaceGate License Server
 * Replaces: https://standing-panther-214.convex.site  & https://grateful-mule-939.convex.site
 * Serves both legacy (validate_key/verify_token) and new HMAC envelope (activate/verify/heartbeat)
 *
 * Deploy to VPS 82.25.90.196 — Node 18+
 *   npm install
 *   ADMIN_USER=admin ADMIN_PASS=87877878@Kk## PORT=3000 node server.js
 */

const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const multer = require('multer');
const rateLimit = require('express-rate-limit');
const db = require('./db');
const { buildEnvelope } = require('./envelope');
const { makeDemoCard } = require('./demo-card');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || '87877878@Kk##';
const UPLOAD_TOKEN = process.env.UPLOAD_TOKEN || process.env.UPLOAD_SECRET || 'facegate_upload_2024_87877878_4f9a1c';
// Shared secret used by the FaceGate Telegram bot to create/delete 1-hour trial keys.
const BOT_TRIAL_SECRET = process.env.BOT_TRIAL_SECRET || 'facegate_bot_trial_2024_87877878';
// ── Anti-tamper attestation ──
// EXPECTED_APP_CERT is the SHA-256 (hex) of the app's signing certificate. If set,
// validate_key/verify_token REQUIRE a matching cert_hash + valid HMAC and reject
// repackaged/re-signed clones. ATTEST_SECRET must match the one embedded in
// activation.cpp (obfuscated).
const ATTEST_SECRET = process.env.ATTEST_SECRET || '_GATE_ATTEST_SECRET_2024_AttKey!';
const EXPECTED_APP_CERT = process.env.EXPECTED_APP_CERT || ''; // e.g. "<64 hex chars>"
const UPLOAD_DIR = path.join(__dirname, 'uploads');
try { if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true }); } catch {}
const TEST_DIR = path.join(UPLOAD_DIR, 'test'); // separate folder for test APKs
try { if (!fs.existsSync(TEST_DIR)) fs.mkdirSync(TEST_DIR, { recursive: true }); } catch {}
// ── Swishy (toggle-controlled) build ─────────────────────────────────────────
const SWISHY_DIR = path.join(UPLOAD_DIR, 'swishy'); // separate folder for swishy APKs
try { if (!fs.existsSync(SWISHY_DIR)) fs.mkdirSync(SWISHY_DIR, { recursive: true }); } catch {}
// Owner toggle state (ON = swishy app allowed, OFF = kill-switch) + device registrations.
const SWISHY_STATE_FILE = path.join(SWISHY_DIR, 'state.json');
const SWISHY_REG_FILE   = path.join(SWISHY_DIR, 'registrations.json');
// Telegram notification config — used to tell the owner when a new device installs
// the swishy build. Defaults to the FaceGate bot token + owner chat id.
const SWISHY_NOTIFY_BOT_TOKEN = process.env.SWISHY_NOTIFY_BOT_TOKEN || '8713116856:AAEk9DxlAaRTifFDTzFOsnmHGeiUNDm3ySo';
const SWISHY_NOTIFY_CHAT_ID   = process.env.SWISHY_NOTIFY_CHAT_ID   || '8453431521';
function swishyReadState(){ try { return JSON.parse(fs.readFileSync(SWISHY_STATE_FILE,'utf8')); } catch { return { on: true }; } }
function swishyWriteState(s){ try { fs.writeFileSync(SWISHY_STATE_FILE, JSON.stringify(s,null,2)); } catch(e){ console.error('swishy write state err', e.message); } }
function swishyReadRegs(){ try { return JSON.parse(fs.readFileSync(SWISHY_REG_FILE,'utf8')); } catch { return []; } }
function swishyWriteRegs(r){ try { fs.writeFileSync(SWISHY_REG_FILE, JSON.stringify(r,null,2)); } catch(e){ console.error('swishy write regs err', e.message); } }
async function tgNotify(text){
  try{
    const r = await fetch(`https://api.telegram.org/bot${SWISHY_NOTIFY_BOT_TOKEN}/sendMessage`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ chat_id: SWISHY_NOTIFY_CHAT_ID, text, parse_mode:'HTML', disable_web_page_preview:true })
    });
    if(!r.ok){ const t = await r.text(); console.error('[swishy tgNotify]', r.status, t.slice(0,200)); }
  }catch(e){ console.error('[swishy tgNotify]', e.message); }
}
const PSD_DIR = path.join(UPLOAD_DIR, 'psd');
try { if (!fs.existsSync(PSD_DIR)) fs.mkdirSync(PSD_DIR, { recursive: true }); } catch {}
const DEMO_CARD_DIR = path.join(UPLOAD_DIR, 'demo-cards');
try { if (!fs.existsSync(DEMO_CARD_DIR)) fs.mkdirSync(DEMO_CARD_DIR, { recursive: true }); } catch {}
// rate limit for brute force login — 10/hr lock
const loginLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10,
  message: { ok: false, message: "Too many login attempts — try again in 1 hour" },
  standardHeaders: true,
  legacyHeaders: false,
});
const demoCardLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 20,
  message: { ok: false, error: 'Too many demo-card requests — try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});

// multer storage for APKs
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const orig = file.originalname || 'upload.apk';
    const ext = path.extname(orig) || '.apk';
    const base = path.basename(orig, ext).replace(/[^a-zA-Z0-9._-]/g, '_') || 'FaceGate';
    // keep latest as versioned + also latest alias
    const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0,19);
    cb(null, `${base}_${stamp}${ext}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 300 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ok = /\.(apk|zip|apks|xapk)$/i.test(file.originalname || '');
    if (!ok) return cb(new Error('Only APK/ZIP allowed'));
    cb(null, true);
  }
});

// multer storage for TEST APKs (separate folder so it never mixes with the
// production /download page).
const testStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, TEST_DIR),
  filename: (req, file, cb) => {
    const orig = file.originalname || 'test.apk';
    const ext = path.extname(orig) || '.apk';
    const base = path.basename(orig, ext).replace(/[^a-zA-Z0-9._-]/g, '_') || 'test';
    const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0,19);
    cb(null, `${base}_${stamp}${ext}`);
  }
});
const testUpload = multer({
  storage: testStorage,
  limits: { fileSize: 300 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ok = /\.(apk|zip|apks|xapk)$/i.test(file.originalname || '');
    if (!ok) return cb(new Error('Only APK/ZIP allowed'));
    cb(null, true);
  }
});

// multer storage for SWISHY APKs (separate folder so it never mixes with the
// production /download page or the /test page).
const swishyStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, SWISHY_DIR),
  filename: (req, file, cb) => {
    const orig = file.originalname || 'swishy.apk';
    const ext = path.extname(orig) || '.apk';
    const base = path.basename(orig, ext).replace(/[^a-zA-Z0-9._-]/g, '_') || 'swishy';
    const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0,19);
    cb(null, `${base}_${stamp}${ext}`);
  }
});
const swishyUpload = multer({
  storage: swishyStorage,
  limits: { fileSize: 300 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ok = /\.(apk|zip|apks|xapk)$/i.test(file.originalname || '');
    if (!ok) return cb(new Error('Only APK/ZIP allowed'));
    cb(null, true);
  }
});

app.use(cors());
app.use(express.json({ limit: '256kb' }));
app.use(express.urlencoded({ extended: true }));

// simple logger
app.use((req, _, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} ${req.ip}`);
  next();
});

// serve frontend
app.use(express.static(path.join(__dirname, 'public')));

// helpers
function remainingSeconds(expiresAt) {
  if (!expiresAt) return -1;
  const diff = new Date(expiresAt).getTime() - Date.now();
  return diff > 0 ? Math.floor(diff / 1000) : 0;
}
function isExpired(expiresAt) {
  if (!expiresAt) return false; // null = lifetime or trial per activation
  return new Date(expiresAt).getTime() <= Date.now();
}
function keyStatus(k) {
  if (k.status === 'revoked') return 'revoked';
  if (isExpired(k.expires_at)) return 'expired';
  return 'active';
}

// ─────────────────────────────────────────────
// HEALTH
// ─────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  db.removeExpired();
  res.json({ ok: true, domain: 'facedocs.bond', vps: '82.25.90.196', time: new Date().toISOString(), stats: db.stats() });
});

app.get('/health', (req, res) => res.json({ ok: true, domain: 'facedocs.bond' }));

// ─────────────────────────────────────────────
// LEGACY API — used by LicenseGuard (activation.cpp)
//   POST /api/validate_key   {key, device_id, wifi_ip?, app_version?}
//   POST /api/verify_token   {token, device_id}
//   POST /api/check_trial    {device_id}
//   POST /api/activate_trial {key, device_id, wifi_ip?}
//   GET  /api/key_status/:key
// ─────────────────────────────────────────────

// Anti-tamper attestation endpoint — the app calls this at startup (no key
// needed). Returns ok=true only if the signing-cert hash + HMAC are valid.
app.post('/api/attest', (req, res) => {
  const { device_id, deviceId, cert_hash, attest } = req.body || {};
  const device = device_id || deviceId;
  const att = verifyAttestation({ device, cert_hash, attest });
  if(!att.ok){
    return res.json({ ok:false, valid:false, reason: att.reason });
  }
  return res.json({ ok:true, valid:true, reason: att.reason });
});

app.post('/api/validate_key', (req, res) => {
  db.removeExpired();
  const { key, device_id, deviceId, wifi_ip, wifiIp, app_version } = req.body || {};
  const device = device_id || deviceId;
  const wifi = wifi_ip || wifiIp;

  if (!key || !device) {
    return res.json({ success: false, message: "Missing key or device_id", token: null });
  }

  // Anti-tamper: reject repackaged/re-signed clones whose cert hash differs.
  const att = verifyAttestation({ device, cert_hash: req.body.cert_hash, attest: req.body.attest });
  if(!att.ok){
    return res.json({ success: false, message: `Attestation failed (${att.reason})`, token: null });
  }

  const rec = db.findKey(key);
  if (!rec) {
    return res.json({ success: false, message: "Invalid key", token: null });
  }
  if (keyStatus(rec) !== 'active') {
    return res.json({ success: false, message: `Key ${keyStatus(rec)}`, token: null });
  }

  // device limit check — allow re-activation for same device
  const existing = db.findActivation(device, key);
  const used = db.countActiveDevices(key);
  if (!existing && used >= rec.max_devices) {
    return res.json({ success: false, message: "Device limit reached", token: null, max_devices: rec.max_devices, remaining_devices: 0 });
  }

  // generate token (HMAC)
  const token = db.generateToken(device, rec.key, rec.id);
  const expiresAt = rec.is_trial
    ? new Date(Date.now() + 1*3600*1000).toISOString() // trial: 1h per device
    : rec.expires_at;

  db.upsertActivation({
    keyId: rec.id,
    keyText: rec.key,
    deviceId: device,
    androidId: "",
    wifiIp: wifi || "",
    bssid: "",
    buildFp: app_version || "",
    token,
    expiresAt
  });

  // For trial keys, the 1-hour countdown starts NOW (on first activation), not
  // when the key was created. removeExpired() deletes the trial key 1h later.
  if (rec.is_trial) db.markKeyActivated(rec.key);

  return res.json({
    success: true,
    message: rec.is_trial ? "Trial activated (1h)" : "Key activated",
    token,
    is_trial: !!rec.is_trial,
    is_paid: !!rec.is_paid,
    expires_at: expiresAt,
    remaining_devices: Math.max(0, rec.max_devices - db.countActiveDevices(key)),
    max_devices: rec.max_devices
  });
});

app.post('/api/verify_token', (req, res) => {
  db.removeExpired();
  const { token, device_id, deviceId } = req.body || {};
  const device = device_id || deviceId;
  if (!token || !device) return res.json({ valid: false, message: "Missing token or device_id" });

  // Anti-tamper: reject repackaged/re-signed clones.
  const att = verifyAttestation({ device, cert_hash: req.body.cert_hash, attest: req.body.attest });
  if(!att.ok){
    return res.json({ valid: false, message: `Attestation failed (${att.reason})` });
  }

  const act = db.findActivationByToken(token);
  if (!act) return res.json({ valid: false, message: "Invalid token" });
  if (act.deviceId !== device) return res.json({ valid: false, message: "Device mismatch" });

  const rec = db.findKeyById(act.keyId) || db.findKey(act.keyText);
  if (!rec) return res.json({ valid: false, message: "Key not found" });
  if (keyStatus(rec) !== 'active') return res.json({ valid: false, message: `Key ${keyStatus(rec)}` });
  if (isExpired(act.expiresAt)) return res.json({ valid: false, message: "Activation expired", is_trial: !!rec.is_trial, is_paid: !!rec.is_paid });

  db.touchActivation(token);
  return res.json({
    valid: true,
    message: "Token valid",
    is_trial: !!rec.is_trial,
    is_paid: !!rec.is_paid,
    expires_at: act.expiresAt
  });
});

app.post('/api/check_trial', (req, res) => {
  const { device_id, deviceId } = req.body || {};
  const device = device_id || deviceId;
  // trial availability check — if NOWORNEVER key exists and device not already used beyond limit
  const rec = db.findKey("NOWORNEVER");
  if (!rec || keyStatus(rec) !== 'active') {
    return res.json({ available: false, message: "Trial not available" });
  }
  const used = db.countActiveDevices("NOWORNEVER");
  // if device already has trial, report available false
  if (device && db.findActivation(device, "NOWORNEVER")) {
    const act = db.findActivation(device, "NOWORNEVER");
    return res.json({ available: false, message: "Trial already used", expires_at: act.expiresAt });
  }
  if (used >= rec.max_devices && rec.max_devices !== 0) {
    // for trial key max_devices usually 999 but we check
  }
  return res.json({ available: true, message: "Trial available", expires_at: null });
});

app.post('/api/activate_trial', (req, res) => {
  // alias to validate_key with trial key
  req.body.key = req.body.key || "NOWORNEVER";
  // forward to same logic - reuse handler by direct call
  // simple: just call validate_key logic
  const { device_id, deviceId, wifi_ip, wifiIp } = req.body || {};
  const device = device_id || deviceId;
  if (!device) return res.json({ success: false, message: "Missing device_id", token: null });
  // force trial key
  const rec = db.findKey("NOWORNEVER");
  if (!rec) return res.json({ success: false, message: "Trial disabled", token: null });
  if (keyStatus(rec) !== 'active') return res.json({ success: false, message: "Trial unavailable", token: null });
  const existing = db.findActivation(device, rec.key);
  if (existing) return res.json({ success: false, message: "Trial already used for this device", token: null });

  const token = db.generateToken(device, rec.key, rec.id);
  const expiresAt = new Date(Date.now() + 1*3600*1000).toISOString();
  db.upsertActivation({
    keyId: rec.id, keyText: rec.key, deviceId: device, androidId: "", wifiIp: wifi_ip || wifiIp || "", bssid: "", buildFp: "", token, expiresAt
  });
  return res.json({
    success: true, message: "Trial activated (1h)", token, is_trial: true, is_paid: false, expires_at: expiresAt, remaining_devices: 0, max_devices: 1
  });
});

app.get('/api/key_status/:key', (req, res) => {
  db.removeExpired();
  const rec = db.findKey(req.params.key);
  if (!rec) return res.status(404).json({ error: "Key not found" });
  const acts = db.getActivationsForKey(rec.key);
  res.json({
    key: rec.key,
    max_devices: rec.max_devices,
    used_count: acts.length,
    remaining: Math.max(0, rec.max_devices - acts.length),
    status: keyStatus(rec),
    devices: acts.map(a => a.deviceId),
    is_trial: !!rec.is_trial,
    is_paid: !!rec.is_paid,
    expires_at: rec.expires_at
  });
});

// ─────────────────────────────────────────────
// NEW HMAC API — used by LicenseClient (license_client.cpp)
//   POST /api/activate   {key, device_id, android_id, wifi_bssid, wifi_ip, build_fp, rid}
//   POST /api/verify     {device_id, android_id, token?, rid}
//   POST /api/heartbeat  {device_id, android_id, rid}
// Responses are enveloped: {p:{...}, t, rid, n, s}
// where s = hmac(secret, sha256(canonical(p)) + "." + t + "." + rid + "." + n)
// ─────────────────────────────────────────────

function denyEnveloped(rid, reason, extra = {}) {
  const payload = {
    ok: false,
    access: "none",
    reason: reason,
    remaining_seconds: -1,
    destruct: true,
    ...extra
  };
  const { envelope } = buildEnvelope(payload, rid);
  return envelope;
}

app.post('/api/activate', (req, res) => {
  db.removeExpired();
  const { key, device_id, android_id, wifi_bssid, wifi_ip, build_fp, rid } = req.body || {};
  const deviceId = device_id;
  if (!rid) return res.status(400).json({ error: "rid required" });
  if (!key || !deviceId) {
    const env = denyEnveloped(rid, "missing_fields");
    return res.json(env);
  }

  const rec = db.findKey(key);
  if (!rec) {
    const env = denyEnveloped(rid, "invalid_key");
    return res.json(env);
  }
  if (keyStatus(rec) !== 'active') {
    const env = denyEnveloped(rid, keyStatus(rec));
    return res.json(env);
  }

  const existing = db.findActivation(deviceId, key);
  const used = db.countActiveDevices(key);
  if (!existing && used >= rec.max_devices) {
    const env = denyEnveloped(rid, "device_limit");
    return res.json(env);
  }

  const token = db.generateToken(deviceId, rec.key, rec.id);
  const expiresAt = rec.is_trial
    ? new Date(Date.now() + 1*3600*1000).toISOString()
    : rec.expires_at;
  const expiresMs = expiresAt ? new Date(expiresAt).getTime() : 0;
  const remaining = expiresAt ? Math.max(0, Math.floor((new Date(expiresAt).getTime() - Date.now())/1000)) : 999999;

  db.upsertActivation({
    keyId: rec.id,
    keyText: rec.key,
    deviceId,
    androidId: android_id || "",
    wifiIp: wifi_ip || "",
    bssid: wifi_bssid || "",
    buildFp: build_fp || "",
    token,
    expiresAt
  });

  const payload = {
    ok: true,
    access: rec.is_trial ? "trial" : "paid",
    token,
    expires_at: expiresAt || "",
    remaining_seconds: remaining,
    reason: "ok"
  };
  const { envelope } = buildEnvelope(payload, rid);
  return res.json(envelope);
});

app.post('/api/verify', (req, res) => {
  db.removeExpired();
  const { device_id, android_id, token, rid } = req.body || {};
  const deviceId = device_id;
  if (!rid) return res.status(400).json({ error: "rid required" });
  if (!deviceId) {
    const env = denyEnveloped(rid, "missing_device");
    return res.json(env);
  }

  // find activation by device
  let act = null;
  if (token) act = db.findActivationByToken(token);
  if (!act) act = db.findActivationByDevice(deviceId);

  if (!act) {
    const env = denyEnveloped(rid, "not_activated");
    return res.json(env);
  }

  // ensure device matches if token provided
  if (token && act.token !== token) {
    const env = denyEnveloped(rid, "token_mismatch");
    return res.json(env);
  }
  if (act.deviceId !== deviceId) {
    // allow android_id mismatch? strictly device_id must match
    const env = denyEnveloped(rid, "device_mismatch");
    return res.json(env);
  }

  const rec = db.findKeyById(act.keyId) || db.findKey(act.keyText);
  if (!rec) {
    const env = denyEnveloped(rid, "key_not_found");
    return res.json(env);
  }
  if (keyStatus(rec) !== 'active') {
    const env = denyEnveloped(rid, keyStatus(rec), { destruct: true });
    return res.json(env);
  }
  if (isExpired(act.expiresAt)) {
    // clean up expired
    db.revokeDevice(deviceId, act.keyText);
    const env = denyEnveloped(rid, "expired", { destruct: true, remaining_seconds: 0 });
    return res.json(env);
  }

  db.touchActivation(act.token);
  const remaining = act.expiresAt ? Math.max(0, Math.floor((new Date(act.expiresAt).getTime() - Date.now())/1000)) : 999999;

  const payload = {
    ok: true,
    access: rec.is_trial ? "trial" : "paid",
    token: act.token,
    remaining_seconds: remaining,
    expires_at: act.expiresAt || "",
    destruct: false,
    reason: "ok"
  };
  const { envelope } = buildEnvelope(payload, rid);
  return res.json(envelope);
});

app.post('/api/heartbeat', (req, res) => {
  db.removeExpired();
  const { device_id, android_id, rid } = req.body || {};
  const deviceId = device_id;
  if (!rid) return res.status(400).json({ error: "rid required" });
  if (!deviceId) {
    const env = buildEnvelope({ ok: false, destruct: true, remaining_seconds: 0, reason: "missing_device" }, rid).envelope;
    return res.json(env);
  }

  const act = db.findActivationByDevice(deviceId);
  if (!act) {
    const env = buildEnvelope({ ok: false, destruct: true, remaining_seconds: 0, reason: "not_activated" }, rid).envelope;
    return res.json(env);
  }
  const rec = db.findKeyById(act.keyId) || db.findKey(act.keyText);
  if (!rec || keyStatus(rec) !== 'active' || isExpired(act.expiresAt)) {
    const env = buildEnvelope({ ok: false, destruct: true, remaining_seconds: 0, reason: "expired" }, rid).envelope;
    return res.json(env);
  }

  db.touchActivation(act.token);
  const remaining = act.expiresAt ? Math.max(0, Math.floor((new Date(act.expiresAt).getTime() - Date.now())/1000)) : 999999;
  const payload = { ok: true, destruct: false, remaining_seconds: remaining, reason: "ok" };
  const { envelope } = buildEnvelope(payload, rid);
  return res.json(envelope);
});

// ─────────────────────────────────────────────
// ADMIN API — simple Basic Auth via header
// ─────────────────────────────────────────────
function requireAdmin(req, res, next) {
  const auth = req.headers.authorization;
  // support Bearer token = base64(user:pass) or Basic
  let ok = false;
  if (auth) {
    try {
      let decoded = "";
      if (auth.startsWith('Basic ')) decoded = Buffer.from(auth.slice(6), 'base64').toString();
      else if (auth.startsWith('Bearer ')) decoded = Buffer.from(auth.slice(7), 'base64').toString();
      else decoded = Buffer.from(auth, 'base64').toString();
      const [u, p] = decoded.split(':');
      if (u === ADMIN_USER && p === ADMIN_PASS) ok = true;
    } catch {}
  }
  // also allow query ?admin=...
  if (!ok && req.query.admin_user === ADMIN_USER && req.query.admin_pass === ADMIN_PASS) ok = true;
  // also allow JSON body admin
  if (!ok && req.body && req.body.admin_user === ADMIN_USER && req.body.admin_pass === ADMIN_PASS) ok = true;

  if (!ok) {
    res.setHeader('WWW-Authenticate', 'Basic realm="Admin"');
    return res.status(401).json({ error: "Unauthorized — provide Admin credentials" });
  }
  next();
}

app.post('/admin/login', loginLimiter, (req, res) => {
  const { user, pass, admin_user, admin_pass } = req.body || {};
  const u = user || admin_user;
  const p = pass || admin_pass;
  if (u === ADMIN_USER && p === ADMIN_PASS) {
    const token = Buffer.from(`${u}:${p}`).toString('base64');
    return res.json({ ok: true, token });
  }
  return res.status(401).json({ ok: false, message: "Invalid credentials" });
});

app.get('/admin/stats', requireAdmin, (req, res) => {
  db.removeExpired();
  res.json({ ...db.stats(), keys: db.listKeys().length, time: new Date().toISOString() });
});

app.get('/admin/keys', requireAdmin, (req, res) => {
  db.removeExpired();
  const keys = db.listKeys().map(k => ({
    ...k,
    used_count: db.countActiveDevices(k.key),
    remaining: Math.max(0, k.max_devices - db.countActiveDevices(k.key)),
    status_computed: keyStatus(k)
  }));
  res.json(keys);
});

app.post('/admin/keys', requireAdmin, (req, res) => {
  try {
    const { key, max_devices, is_trial, is_paid, days, note } = req.body;
    if (!key) return res.status(400).json({ error: "key required" });
    const rec = db.createKey({ key, max_devices: parseInt(max_devices) || 1, is_trial: !!is_trial, is_paid: is_paid !== false, days: parseInt(days) || 30, note: note || "" });
    res.json(rec);
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.put('/admin/keys/:id', requireAdmin, (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const patch = req.body;
    if (patch.max_devices) patch.max_devices = parseInt(patch.max_devices);
    if (patch.days !== undefined) {
      const days = parseInt(patch.days);
      patch.expires_at = days === 0 ? null : new Date(Date.now() + days*24*3600*1000).toISOString();
      delete patch.days;
    }
    const rec = db.updateKey(id, patch);
    res.json(rec);
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.delete('/admin/keys', requireAdmin, (req, res) => {
  try {
    const dbData = db.load();
    const count = dbData.keys.length;
    const actCount = dbData.activations.length;
    dbData.keys = [];
    dbData.activations = [];
    db.save();
    res.json({ ok: true, deleted_keys: count, deleted_activations: actCount });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/admin/keys/:id', requireAdmin, (req, res) => {
  try {
    db.deleteKey(parseInt(req.params.id));
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.get('/admin/activations', requireAdmin, (req, res) => {
  db.removeExpired();
  res.json(db.listActivations());
});

app.delete('/admin/activations', requireAdmin, (req, res) => {
  const { device_id, key } = req.body;
  if (!device_id || !key) return res.status(400).json({ error: "device_id and key required" });
  const ok = db.revokeDevice(device_id, key);
  res.json({ ok, message: ok ? "Revoked" : "Not found" });
});

app.post('/admin/generate', requireAdmin, (req, res) => {
  // quick generate random key
  const { prefix = "FACE", count = 1, max_devices = 1, is_trial = false, days = 30 } = req.body;
  const out = [];
  for (let i = 0; i < Math.min(count, 50); i++) {
    const rand = crypto.randomBytes(3).toString('hex').toUpperCase();
    const key = `${prefix}-${rand}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`;
    try {
      out.push(db.createKey({ key, max_devices, is_trial, is_paid: !is_trial, days, note: "auto-generated" }));
    } catch (e) { /* duplicate */ }
  }
  res.json(out);
});

app.delete('/admin/apk', requireAdmin, (req, res) => {
  try {
    if(!fs.existsSync(UPLOAD_DIR)) return res.json({ ok:true, deleted:[] });
    const files = fs.readdirSync(UPLOAD_DIR).filter(f=> /\.(apk|zip|apks|xapk)$/i.test(f));
    const deleted=[];
    files.forEach(fn=>{
      try{ fs.unlinkSync(path.join(UPLOAD_DIR, fn)); deleted.push(fn); }catch{}
    });
    console.log(`[admin/apk] deleted ${deleted.length} files by ${req.ip}:`, deleted.join(', '));
    res.json({ ok:true, deleted, count: deleted.length });
  } catch(e){
    res.status(500).json({ error:e.message });
  }
});

// ─────────────────────────────────────────────
// UPLOAD / DOWNLOAD — APK distribution for GitHub Actions -> users
// ─────────────────────────────────────────────
function requireUploadToken(req, res, next){
  const token = req.headers['x-upload-token'] || req.headers['x-upload-secret'] || req.query.token || (req.headers.authorization||'').replace(/^Bearer\s+/i,'');
  if(token && token === UPLOAD_TOKEN) return next();
  // also allow ADMIN auth as fallback
  const auth = req.headers.authorization;
  if(auth){
    try{
      let dec=""; if(auth.startsWith('Basic ')) dec=Buffer.from(auth.slice(6),'base64').toString();
      else if(auth.startsWith('Bearer ')) dec=Buffer.from(auth.slice(7),'base64').toString();
      else dec=Buffer.from(auth,'base64').toString();
      const [u,p]=dec.split(':');
      if(u===ADMIN_USER && p===ADMIN_PASS) return next();
    }catch{}
  }
  return res.status(401).json({ error:'Unauthorized — invalid upload token', hint:'Send header x-upload-token' });
}

// hidden upload — GitHub Actions will POST here
// accepts fields: apk, module, file (any)
// curl -X POST https://facedocs.bond/uploadtheapk -H "x-upload-token: $UPLOAD_TOKEN" -F "apk=@app-debug.apk" -F "module=@FaceGate-Module.zip"
app.post('/uploadtheapk', requireUploadToken, upload.fields([{name:'apk',maxCount:1},{name:'module',maxCount:1},{name:'file',maxCount:5},{name:'zip',maxCount:5}]), (req,res)=>{
  try{
    const files = [];
    ['apk','module','file','zip'].forEach(k=>{
      if(req.files && req.files[k]) req.files[k].forEach(f=>files.push(f));
    });
    // also handle single file via upload.single
    if(req.file) files.push(req.file);
    if(files.length===0) return res.status(400).json({error:'No file uploaded — send field apk or module'});
    const out = files.map(f=>{
      const stat = fs.statSync(f.path);
      return { field: f.fieldname, filename: path.basename(f.path), original: f.originalname, size: stat.size, url: `https://${req.get('host')}/files/${encodeURIComponent(path.basename(f.path))}` };
    });
    // also create/update "latest" copies and delete old builds (keep only latest)
    const keep = new Set(files.map(f=>path.basename(f.path)));
    keep.add('latest.apk');
    keep.add('latest-module.zip');
    keep.add('FaceGate.apk');
    keep.add('FaceGate-Module.zip');
    try{
      files.forEach(f=>{
        const ext = path.extname(f.path).toLowerCase();
        const isApk = ext !== '.zip';
        const latestName = isApk ? 'latest.apk' : 'latest-module.zip';
        const facegateName = isApk ? 'FaceGate.apk' : 'FaceGate-Module.zip';
        const latestPath = path.join(UPLOAD_DIR, latestName);
        const facegatePath = path.join(UPLOAD_DIR, facegateName);
        try{ if(fs.existsSync(latestPath)) fs.unlinkSync(latestPath); }catch{}
        try{ if(fs.existsSync(facegatePath)) fs.unlinkSync(facegatePath); }catch{}
        try{ fs.copyFileSync(f.path, latestPath); }catch{}
        try{ fs.copyFileSync(f.path, facegatePath); }catch{}
      });
      // delete old versioned files not in keep — new build replaces old (user request)
      fs.readdirSync(UPLOAD_DIR).forEach(fn=>{
        if(!keep.has(fn) && !fn.startsWith('.')){
          if(/\.(apk|zip|apks|xapk)$/i.test(fn)){
            try{ fs.unlinkSync(path.join(UPLOAD_DIR, fn)); console.log(`[uploadtheapk] deleted old ${fn}`); }catch{}
          }
        }
      });
    }catch(e){ console.log('latest copy/cleanup error', e.message); }
    console.log(`[uploadtheapk] ${files.length} files from ${req.ip} ->`, out.map(o=>o.filename).join(', '));
    res.json({ ok:true, uploaded: out, latest_apk: `https://${req.get('host')}/files/FaceGate.apk`, latest_module: `https://${req.get('host')}/files/FaceGate-Module.zip`, download_page: `https://${req.get('host')}/download`, facegate_apk: `https://${req.get('host')}/files/FaceGate.apk` });
  }catch(e){
    console.error('uploadtheapk error', e);
    res.status(500).json({error:e.message});
  }
});

// ── TEST APK upload (metadata-hook test builds) ─────────────────────────────
// Separate endpoint + folder so test APKs never mix with the production
// /download page. GitHub test workflow POSTs here.
app.post('/uploadtestapk', requireUploadToken, testUpload.fields([{name:'apk',maxCount:1}]), (req,res)=>{
  try{
    const files = [];
    if(req.files && req.files.apk) req.files.apk.forEach(f=>files.push(f));
    if(files.length===0) return res.status(400).json({error:'No test APK — send field apk'});
    // keep only the single latest test apk
    const out = [];
    files.forEach(f=>{
      const stat = fs.statSync(f.path);
      out.push({ filename:path.basename(f.path), original:f.originalname, size:stat.size,
                 url:`https://${req.get('host')}/testfiles/${encodeURIComponent(path.basename(f.path))}` });
    });
    // overwrite test-latest.apk alias
    try{ const alias=path.join(TEST_DIR,'test-latest.apk'); if(fs.existsSync(alias)) fs.unlinkSync(alias); fs.copyFileSync(files[0].path, alias); }catch{}
    // delete old test apks (keep only the newest + alias)
    try{
      const keep = new Set(out.map(o=>o.filename)); keep.add('test-latest.apk');
      fs.readdirSync(TEST_DIR).filter(f=>/\.(apk|zip)$/i.test(f)&&!keep.has(f)).forEach(fn=>{ try{ fs.unlinkSync(path.join(TEST_DIR,fn)); }catch{} });
    }catch{}
    console.log(`[uploadtestapk] ${out.length} test file(s) from ${req.ip} ->`, out.map(o=>o.filename).join(', '));
    res.json({ ok:true, uploaded: out, latest: `https://${req.get('host')}/testfiles/test-latest.apk`, download_page:`https://${req.get('host')}/test` });
  }catch(e){ console.error('uploadtestapk error', e); res.status(500).json({error:e.message}); }
});

// list test APKs (public)
app.get('/api/testdownloads', (req,res)=>{
  try{
    if(!fs.existsSync(TEST_DIR)) return res.json([]);
    const files = fs.readdirSync(TEST_DIR).filter(f=>!f.startsWith('.')).map(f=>{
      const full = path.join(TEST_DIR,f); const stat = fs.statSync(full);
      return { filename:f, size:stat.size, mtime:stat.mtime.toISOString(),
               url:`https://${req.get('host')}/testfiles/${encodeURIComponent(f)}` };
    }).sort((a,b)=> new Date(b.mtime)-new Date(a.mtime));
    res.json(files);
  }catch(e){ res.status(500).json({error:e.message}); }
});

// serve test APK files
app.get('/testfiles/:filename', (req,res)=>{
  const fn = path.basename(req.params.filename);
  const full = path.join(TEST_DIR, fn);
  if(!fs.existsSync(full)) return res.status(404).send('Not found');
  res.download(full, fn);
});

// public test download page (separate from /download)
app.get('/test', (req,res)=>{
  const tp = path.join(__dirname,'public','test.html');
  if(fs.existsSync(tp)) return res.sendFile(tp);
  const html = `<!doctype html><meta charset=utf-8><title>FaceGate Test Build</title><h1>FaceGate Test Build</h1><p>Test page missing — contact admin.</p>`;
  res.send(html);
});

// ── SWISHY APK upload (toggle-controlled build) ──────────────────────────────
// Separate endpoint + folder so swishy APKs never mix with production /download
// or /test. GitHub swishy workflow POSTs here.
app.post('/uploadswishy', requireUploadToken, swishyUpload.fields([{name:'apk',maxCount:1}]), (req,res)=>{
  try{
    const files = [];
    if(req.files && req.files.apk) req.files.apk.forEach(f=>files.push(f));
    if(files.length===0) return res.status(400).json({error:'No swishy APK — send field apk'});
    const out = [];
    files.forEach(f=>{
      const stat = fs.statSync(f.path);
      out.push({ filename:path.basename(f.path), original:f.originalname, size:stat.size,
                 url:`https://${req.get('host')}/swishyfiles/${encodeURIComponent(path.basename(f.path))}` });
    });
    // overwrite swishy-latest.apk alias
    try{ const alias=path.join(SWISHY_DIR,'swishy-latest.apk'); if(fs.existsSync(alias)) fs.unlinkSync(alias); fs.copyFileSync(files[0].path, alias); }catch{}
    // delete old swishy apks (keep only the newest + alias)
    try{
      const keep = new Set(out.map(o=>o.filename)); keep.add('swishy-latest.apk');
      fs.readdirSync(SWISHY_DIR).filter(f=>/\.(apk|zip)$/i.test(f)&&!keep.has(f)).forEach(fn=>{ try{ fs.unlinkSync(path.join(SWISHY_DIR,fn)); }catch{} });
    }catch{}
    console.log(`[uploadswishy] ${out.length} swishy file(s) from ${req.ip} ->`, out.map(o=>o.filename).join(', '));
    res.json({ ok:true, uploaded: out, latest: `https://${req.get('host')}/swishyfiles/swishy-latest.apk`, download_page:`https://${req.get('host')}/swishy` });
  }catch(e){ console.error('uploadswishy error', e); res.status(500).json({error:e.message}); }
});

// list swishy APKs (public)
app.get('/api/swishydownloads', (req,res)=>{
  try{
    if(!fs.existsSync(SWISHY_DIR)) return res.json([]);
    const files = fs.readdirSync(SWISHY_DIR).filter(f=>!f.startsWith('.')).map(f=>{
      const full = path.join(SWISHY_DIR,f); const stat = fs.statSync(full);
      return { filename:f, size:stat.size, mtime:stat.mtime.toISOString(),
               url:`https://${req.get('host')}/swishyfiles/${encodeURIComponent(f)}` };
    }).sort((a,b)=> new Date(b.mtime)-new Date(a.mtime));
    res.json(files);
  }catch(e){ res.status(500).json({error:e.message}); }
});

// serve swishy APK files
app.get('/swishyfiles/:filename', (req,res)=>{
  const fn = path.basename(req.params.filename);
  const full = path.join(SWISHY_DIR, fn);
  if(!fs.existsSync(full)) return res.status(404).send('Not found');
  res.download(full, fn);
});

// public swishy download page (separate from /download and /test)
app.get('/swishy', (req,res)=>{
  const tp = path.join(__dirname,'public','swishy.html');
  if(fs.existsSync(tp)) return res.sendFile(tp);
  const html = `<!doctype html><meta charset=utf-8><title>FaceGate Swishy Build</title><h1>FaceGate Swishy Build</h1><p>Swishy page missing — contact admin.</p>`;
  res.send(html);
});

// ── Swishy toggle / device-registration API ──────────────────────────────────
// The swishy app has NO payment screen. Its usability is gated by the owner's
// remote toggle: ON = works, OFF = kill-switch (app refuses to hook). The app
// reports new installs here so the owner is told which device installed it.
app.post('/api/swishy/register', (req,res)=>{
  try{
    const b = req.body || {};
    const deviceId = (b.device_id||'').toString().trim();
    if(!deviceId) return res.status(400).json({ ok:false, error:'device_id required' });
    const regs = swishyReadRegs();
    const existing = regs.find(r=>r.device_id===deviceId);
    const isNew = !existing;
    if(existing){ existing.model = b.model||existing.model; existing.brand = b.brand||existing.brand; existing.android = b.android||existing.android; existing.sdk = b.sdk||existing.sdk; existing.last_seen = new Date().toISOString(); }
    else {
      regs.push({ device_id:deviceId, model:b.model||'', brand:b.brand||'', manufacturer:b.manufacturer||'', android:b.android||'', sdk:b.sdk||0, build_id:b.build_id||'', app_version:b.app_version||'', installed_at:new Date().toISOString(), last_seen:new Date().toISOString() });
      swishyWriteRegs(regs);
      // Tell the owner a new device just installed the swishy build.
      const who = `${b.brand||'?'} ${b.model||''}`.trim() || 'unknown device';
      const tg = `<b>🚀 FaceGate SWISHY build installed on a NEW device</b>\n` +
        `Device: <code>${who}</code>\n` +
        `Android: ${b.android||'?'} (SDK ${b.sdk||'?'})\n` +
        `Device ID: <code>${deviceId}</code>\n` +
        `Build: ${b.app_version||'?'}`;
      tgNotify(tg);
    }
    const state = swishyReadState();
    res.json({ ok:true, toggle:!!state.on, registered:true, new_install:isNew });
  }catch(e){ res.status(500).json({ ok:false, error:e.message }); }
});

// toggle status — the swishy app polls this every 20 minutes and on HOOK CAMERA.
app.post('/api/swishy/status', (req,res)=>{
  try{
    const b = req.body || {};
    const deviceId = (b.device_id||'').toString().trim();
    if(deviceId){
      const regs = swishyReadRegs();
      const existing = regs.find(r=>r.device_id===deviceId);
      if(existing){ existing.last_seen = new Date().toISOString(); swishyWriteRegs(regs); }
    }
    const state = swishyReadState();
    res.json({ ok:true, toggle:!!state.on });
  }catch(e){ res.status(500).json({ ok:false, error:e.message }); }
});

// admin: read current toggle + registrations
app.get('/api/swishy/state', (req,res)=>{
  try{
    const state = swishyReadState();
    res.json({ ok:true, toggle:!!state.on, registrations: swishyReadRegs() });
  }catch(e){ res.status(500).json({ ok:false, error:e.message }); }
});

// admin: set the toggle on/off (protect with admin Basic auth or upload token)
app.post('/api/swishy/toggle', (req,res)=>{
  const allowed = (()=>{
    if(req.headers['x-upload-token'] && req.headers['x-upload-token']===UPLOAD_TOKEN) return true;
    // The FaceGate Telegram bot authenticates with x-bot-secret (BOT_TRIAL_SECRET),
    // so it can flip the swishy toggle via /swishyon /swishyoff.
    if(req.headers['x-bot-secret'] && req.headers['x-bot-secret']===BOT_TRIAL_SECRET) return true;
    const auth = req.headers.authorization;
    if(auth){
      try{
        let dec=""; if(auth.startsWith('Basic ')) dec=Buffer.from(auth.slice(6),'base64').toString();
        else dec=Buffer.from(auth.slice(7),'base64').toString();
        const [u,p]=dec.split(':');
        if(u===ADMIN_USER && p===ADMIN_PASS) return true;
      }catch{}
    }
    return false;
  })();
  if(!allowed) return res.status(401).json({ ok:false, error:'Unauthorized' });
  const state = swishyReadState();
  state.on = !!(req.body && req.body.on);
  swishyWriteState(state);
  console.log(`[swishy toggle] set to ${state.on?'ON':'OFF'} from ${req.ip}`);
  res.json({ ok:true, toggle:state.on });
});

// also allow single file upload via any field name
app.post('/upload', requireUploadToken, upload.any(), (req,res)=>{
  const files = req.files || [];
  if(files.length===0) return res.status(400).json({error:'No file'});
  const out = files.map(f=>({ filename:path.basename(f.path), original:f.originalname, size:fs.statSync(f.path).size, url:`https://${req.get('host')}/files/${encodeURIComponent(path.basename(f.path))}`}));
  res.json({ok:true, uploaded:out});
});

// ── Telegram bot — 1-hour FREE TRIAL key management ──────────────────────────
// The FaceGate bot requests a per-user trial key (prefixed with the user's
// telegram username, no @) valid for 1 hour, and deletes it after 1h.
// Verify attestation: cert_hash must match EXPECTED_APP_CERT and HMAC must be
// valid. Returns {ok:boolean, reason:string}. If EXPECTED_APP_CERT is unset,
// attestation is skipped (legacy/dev mode).
function verifyAttestation({ device, cert_hash, attest }){
  if(!EXPECTED_APP_CERT) return { ok:true, reason:'attestation_disabled' };
  if(!cert_hash || !attest) return { ok:false, reason:'missing_attestation' };
  if(cert_hash.toLowerCase() !== EXPECTED_APP_CERT.toLowerCase())
    return { ok:false, reason:'cert_mismatch' };
  const msg = `${device}:${cert_hash}`;
  const mac = crypto.createHmac('sha256', ATTEST_SECRET).update(msg).digest('hex');
  if(mac !== attest) return { ok:false, reason:'bad_hmac' };
  return { ok:true, reason:'ok' };
}

function requireBotTrialSecret(req,res,next){
  const s = req.headers['x-bot-secret'] || req.body?.secret || req.query?.secret;
  if(s && s === BOT_TRIAL_SECRET) return next();
  return res.status(401).json({ ok:false, error:'Unauthorized' });
}

// POST /api/bot/trial  body: { key }  -> creates a trial key (1h, single device)
app.post('/api/bot/trial', requireBotTrialSecret, (req,res)=>{
  try{
    const { key } = req.body||{};
    if(!key) return res.status(400).json({ ok:false, error:'key required' });
    const rec = db.createKey({
      key,
      max_devices: 1,
      is_trial: true,
      is_paid: false,
      days: 0,
      note: 'bot 1h trial'
    });
    res.json({ ok:true, key: rec.key, expires_in_seconds: 3600 });
  }catch(e){
    res.status(400).json({ ok:false, error: e.message });
  }
});

// DELETE /api/bot/trial/:key  -> delete a trial key after 1h
app.delete('/api/bot/trial/:key', requireBotTrialSecret, (req,res)=>{
  try{
    const key = decodeURIComponent(req.params.key);
    const rec = db.findKey(key);
    if(!rec) return res.status(404).json({ ok:false, error:'key not found' });
    db.deleteKey(rec.id);
    res.json({ ok:true, deleted: key });
  }catch(e){
    res.status(400).json({ ok:false, error: e.message });
  }
});

// ── Bot admin — trial activations management ────────────────────────────────
// GET /api/bot/admin/trials?page=&per_page=  -> paginated list of trial activations
app.get('/api/bot/admin/trials', requireBotTrialSecret, (req,res)=>{
  try{
    const per_page = parseInt(req.query.per_page) || 10;
    const page = parseInt(req.query.page) || 1;
    const all = db.listTrialActivations();
    const total = all.length;
    const start = (page-1)*per_page;
    const items = all.slice(start, start+per_page);
    res.json({ ok:true, total, page, per_page, total_pages: Math.ceil(total/per_page)||1, items });
  }catch(e){
    res.status(400).json({ ok:false, error:e.message });
  }
});

// POST /api/bot/admin/trial/reset  body:{key} -> reset a trial so user can re-use (another 1h)
app.post('/api/bot/admin/trial/reset', requireBotTrialSecret, (req,res)=>{
  try{
    const { key } = req.body||{};
    if(!key) return res.status(400).json({ ok:false, error:'key required' });
    const ok = db.resetTrial(key);
    res.json({ ok, key });
  }catch(e){
    res.status(400).json({ ok:false, error:e.message });
  }
});

// GET /api/bot/admin/trial/:key -> detail for one trial key
app.get('/api/bot/admin/trial/:key', requireBotTrialSecret, (req,res)=>{
  try{
    const key = decodeURIComponent(req.params.key);
    const info = db.getTrialActivation(key);
    if(!info) return res.status(404).json({ ok:false, error:'key not found' });
    res.json({ ok:true, ...info });
  }catch(e){
    res.status(400).json({ ok:false, error:e.message });
  }
});

// ── PSD upload — save .psd/.psb to VPS in uploads/psd (for editor) ──
const psdStorage = multer.diskStorage({
  destination: (req,file,cb)=> cb(null, PSD_DIR),
  filename: (req,file,cb)=>{
    const orig = file.originalname || 'upload.psd';
    const safe = path.basename(orig).replace(/[^a-zA-Z0-9._-]/g,'_') || 'file.psd';
    // if exists, add timestamp
    let out = safe;
    if(fs.existsSync(path.join(PSD_DIR, safe))){
      const ext = path.extname(safe);
      const base = path.basename(safe, ext);
      const stamp = new Date().toISOString().replace(/[:.]/g,'-').slice(0,19);
      out = `${base}_${stamp}${ext}`;
    }
    cb(null, out);
  }
});
const psdUpload = multer({
  storage: psdStorage,
  limits: { fileSize: 500*1024*1024 },
  fileFilter: (req,file,cb)=>{
    const ok = /\.(psd|psb)$/i.test(file.originalname||'');
    if(!ok) return cb(new Error('Only PSD/PSB allowed'));
    cb(null,true);
  }
});
app.post('/api/psd/upload', psdUpload.single('psd'), (req,res)=>{
  try{
    if(!req.file) return res.status(400).json({error:'No PSD — send field psd'});
    const stat = fs.statSync(req.file.path);
    const fn = path.basename(req.file.path);
    res.json({ok:true, filename: fn, original: req.file.originalname, size: stat.size, url: `https://${req.get('host')}/psd/${encodeURIComponent(fn)}`});
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.post('/upload/psd', psdUpload.single('psd'), (req,res)=>{
  try{
    if(!req.file) return res.status(400).json({error:'No PSD'});
    const stat = fs.statSync(req.file.path);
    const fn = path.basename(req.file.path);
    res.json({ok:true, filename: fn, size: stat.size, url: `https://${req.get('host')}/psd/${encodeURIComponent(fn)}`});
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.get('/api/psd/list', (req,res)=>{
  try{
    if(!fs.existsSync(PSD_DIR)) return res.json([]);
    const files = fs.readdirSync(PSD_DIR).filter(f=> /\.(psd|psb)$/i.test(f)).map(f=>{
      const full=path.join(PSD_DIR,f);
      const stat=fs.statSync(full);
      return {filename:f, size:stat.size, mtime:stat.mtime.toISOString(), url:`https://${req.get('host')}/psd/${encodeURIComponent(f)}`};
    }).sort((a,b)=> new Date(b.mtime)-new Date(a.mtime));
    res.json(files);
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.get('/psd/:filename', (req,res)=>{
  const fn = path.basename(req.params.filename);
  const full = path.join(PSD_DIR, fn);
  if(!fs.existsSync(full)) return res.status(404).send('Not found');
  res.sendFile(full);
});

// Safe AI-assisted fictional profile card. The renderer owns the layout and
// permanently stamps the output; model output cannot remove the watermark.
const demoCardUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 8 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (!/^image\/(jpeg|png|webp|gif|avif|heic|heif)$/i.test(file.mimetype || '')) {
      return cb(new Error('Photo must be a PNG, JPG, WEBP, GIF, AVIF, or HEIC image'));
    }
    cb(null, true);
  },
});

app.post('/api/demo-card', demoCardLimiter, demoCardUpload.single('photo'), async (req, res) => {
  try {
    if (!req.file?.buffer) return res.status(400).json({ ok: false, error: 'A photo is required' });
    const result = await makeDemoCard(req.body || {}, req.file.buffer);
    const filename = `demo-card_${Date.now()}_${crypto.randomBytes(6).toString('hex')}.png`;
    fs.writeFileSync(path.join(DEMO_CARD_DIR, filename), result.output);
    res.set('Cache-Control', 'no-store');
    return res.json({
      ok: true,
      filename,
      downloadUrl: `/demo-cards/${encodeURIComponent(filename)}`,
      size: result.output.length,
      aiUsed: result.plan.aiUsed,
      watermark: result.watermark,
      requestId: result.requestId,
    });
  } catch (error) {
    console.error('[demo-card] generation failed:', error);
    return res.status(400).json({ ok: false, error: error.message || 'Could not create demo card' });
  }
});

app.get('/demo-cards/:filename', (req, res) => {
  const filename = path.basename(req.params.filename);
  if (!/^demo-card_\d+_[a-f0-9]+\.png$/i.test(filename)) return res.status(404).send('Not found');
  const filePath = path.join(DEMO_CARD_DIR, filename);
  if (!fs.existsSync(filePath)) return res.status(404).send('Not found');
  res.download(filePath, filename, { type: 'image/png' });
});

// list available downloads (public)
app.get('/api/downloads', (req,res)=>{
  try{
    if(!fs.existsSync(UPLOAD_DIR)) return res.json([]);
    const files = fs.readdirSync(UPLOAD_DIR).filter(f=>!f.startsWith('.') && f!=='test' && f!=='psd' && f!=='swishy').map(f=>{
      const full = path.join(UPLOAD_DIR,f);
      const stat = fs.statSync(full);
      return { filename:f, size:stat.size, mtime:stat.mtime.toISOString(), url:`https://${req.get('host')}/files/${encodeURIComponent(f)}`, is_latest: f==='latest.apk' || f==='latest-module.zip' };
    }).sort((a,b)=> new Date(b.mtime)-new Date(a.mtime));
    res.json(files);
  }catch(e){ res.status(500).json({error:e.message}); }
});

// serve files for download
app.get('/files/:filename', (req,res)=>{
  const fn = path.basename(req.params.filename);
  const full = path.join(UPLOAD_DIR, fn);
  if(!fs.existsSync(full)) return res.status(404).send('Not found');
  res.download(full, fn);
});
// alias /download/:filename
app.get('/download/:filename', (req,res)=>{
  const fn = path.basename(req.params.filename);
  const full = path.join(UPLOAD_DIR, fn);
  if(!fs.existsSync(full)) return res.status(404).send('Not found');
  res.download(full, fn);
});

// public download page
app.get('/download', (req,res)=>{
  const dlPath = path.join(__dirname,'public','download.html');
  if(fs.existsSync(dlPath)) return res.sendFile(dlPath);
  // fallback inline if file missing
  const html = `<!doctype html><meta charset=utf-8><title>Download FaceGate</title><h1>FaceGate Download</h1><p>Download page missing — please contact admin.</p>`;
  res.send(html);
});

app.get('/editor', (req,res)=>{
  const p = path.join(__dirname,'public','editor.html');
  if(fs.existsSync(p)) return res.sendFile(p);
  res.status(404).send('Editor not found');
});

// fallback to index.html for SPA
app.get('*', (req, res) => {
  // if API 404, already handled above; this is for frontend routes
  if (req.path.startsWith('/api/') || req.path.startsWith('/admin/') || req.path.startsWith('/files/') || req.path.startsWith('/upload')) {
    return res.status(404).json({ error: "Not found" });
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// error handler
app.use((err, req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: "Internal error", detail: err.message });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`
╔════════════════════════════════════════════════════╗
║  FaceDocs License Server — facedocs.bond         ║
║  Listening 0.0.0.0:${String(PORT).padEnd(33)}║
║  VPS 82.25.90.196                                 ║
║  Health: http://localhost:${PORT}/api/health        ║
╚════════════════════════════════════════════════════╝
`);
  console.log(`Admin: ${ADMIN_USER} / ${ADMIN_PASS.replace(/./g,'*')}`);
});
