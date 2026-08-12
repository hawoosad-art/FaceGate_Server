// db.js — simple JSON file DB, no native deps. Atomic write + in-memory cache.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DB_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DB_DIR, 'db.json');

function ensureDb() {
  if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });
  if (!fs.existsSync(DB_FILE)) {
    const init = {
      keys: [],
      activations: [], // { keyId, keyText, deviceId, androidId, wifiIp, bssid, buildFp, token, createdAt, expiresAt, lastSeen }
      meta: { createdAt: new Date().toISOString() }
    };
    // seed with demo keys so admin can test immediately
    const now = Date.now();
    init.keys.push(
      {
        id: 1,
        key: "DEMO-TRIAL-9999",
        max_devices: 1,
        status: "active",
        is_trial: true,
        is_paid: false,
        expires_at: null, // trial expiry is per-activation (1h)
        created_at: new Date().toISOString(),
        note: "Demo trial key"
      },
      {
        id: 2,
        key: "FACE-DEMO-PAID-001",
        max_devices: 3,
        status: "active",
        is_trial: false,
        is_paid: true,
        expires_at: new Date(now + 30*24*3600*1000).toISOString(),
        created_at: new Date().toISOString(),
        note: "Demo paid key 30 days, 3 devices"
      },
      {
        id: 999,
        key: "NOWORNEVER",
        max_devices: 1,
        status: "active",
        is_trial: true,
        is_paid: false,
        expires_at: null,
        created_at: new Date().toISOString(),
        note: "Hardcoded trial key FACEGATE_TRIAL_KEY"
      }
    );
    fs.writeFileSync(DB_FILE, JSON.stringify(init, null, 2));
  }
}

let cache = null;
function load() {
  ensureDb();
  if (cache) return cache;
  cache = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  return cache;
}
function save() {
  if (!cache) return;
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(cache, null, 2));
  fs.renameSync(tmp, DB_FILE);
}

// helpers
function findKey(keyText) {
  const db = load();
  return db.keys.find(k => k.key === keyText);
}
function findKeyById(id) {
  const db = load();
  return db.keys.find(k => k.id === id);
}
function listKeys() {
  return load().keys;
}
function createKey({ key, max_devices = 1, is_trial = false, is_paid = true, days = 30, status = 'active', note = '' }) {
  const db = load();
  if (db.keys.some(k => k.key === key)) throw new Error('Key already exists');
  const id = db.keys.length ? Math.max(...db.keys.map(k => k.id)) + 1 : 1;
  const expires_at = is_trial ? null : (days === 0 ? null : new Date(Date.now() + days*24*3600*1000).toISOString());
  const rec = { id, key, max_devices, status, is_trial, is_paid, expires_at, created_at: new Date().toISOString(), note };
  db.keys.push(rec);
  save();
  return rec;
}
function updateKey(id, patch) {
  const db = load();
  const k = db.keys.find(x => x.id === id);
  if (!k) throw new Error('Key not found');
  Object.assign(k, patch);
  save();
  return k;
}
function deleteKey(id) {
  const db = load();
  const idx = db.keys.findIndex(x => x.id === id);
  if (idx === -1) throw new Error('Key not found');
  db.keys.splice(idx, 1);
  // also remove activations for that key
  const keyText = db.keys[idx]?.key;
  db.activations = db.activations.filter(a => a.keyId !== id);
  save();
}

function getActivationsForKey(keyText) {
  const db = load();
  return db.activations.filter(a => a.keyText === keyText);
}
function countActiveDevices(keyText) {
  return getActivationsForKey(keyText).length;
}
function findActivation(deviceId, keyText) {
  const db = load();
  return db.activations.find(a => a.deviceId === deviceId && a.keyText === keyText);
}
function findActivationByToken(token) {
  const db = load();
  return db.activations.find(a => a.token === token);
}
function findActivationByDevice(deviceId) {
  const db = load();
  const acts = db.activations.filter(a => a.deviceId === deviceId);
  if (!acts.length) return undefined;
  acts.sort((a, b) => {
    const tb = new Date(b.lastSeen || b.createdAt || 0).getTime();
    const ta = new Date(a.lastSeen || a.createdAt || 0).getTime();
    return tb - ta;
  });
  return acts[0];
}
function upsertActivation({ keyId, keyText, deviceId, androidId, wifiIp, bssid, buildFp, token, expiresAt }) {
  const db = load();
  let act = db.activations.find(a => a.deviceId === deviceId && a.keyText === keyText);
  const now = new Date().toISOString();
  if (act) {
    act.androidId = androidId || act.androidId;
    act.wifiIp = wifiIp || act.wifiIp;
    act.bssid = bssid || act.bssid;
    act.buildFp = buildFp || act.buildFp;
    act.token = token || act.token;
    act.expiresAt = expiresAt || act.expiresAt;
    act.lastSeen = now;
  } else {
    act = { keyId, keyText, deviceId, androidId, wifiIp, bssid, buildFp, token, createdAt: now, expiresAt, lastSeen: now };
    db.activations.push(act);
  }
  save();
  return act;
}
function touchActivation(token) {
  const db = load();
  const act = db.activations.find(a => a.token === token);
  if (act) { act.lastSeen = new Date().toISOString(); save(); }
  return act;
}
function removeExpired() {
  const db = load();
  const now = Date.now();
  const before = db.activations.length;
  db.activations = db.activations.filter(a => {
    if (!a.expiresAt) return true;
    return new Date(a.expiresAt).getTime() > now;
  });
  if (db.activations.length !== before) save();
}
function revokeDevice(deviceId, keyText) {
  const db = load();
  const idx = db.activations.findIndex(a => a.deviceId === deviceId && a.keyText === keyText);
  if (idx !== -1) { db.activations.splice(idx, 1); save(); return true; }
  return false;
}

function generateToken(deviceId, keyText, keyId) {
  // replicate native: hmac(secret, "facegate:paid:deviceId:keyId:keyText")
  // but for simplicity also support trial tokens; we use same logic for all
  const { hmacSha256Hex, FACEGATE_HMAC_SECRET } = require('./envelope');
  const raw = `facegate:paid:${deviceId}:${keyId}:${keyText}`;
  return hmacSha256Hex(FACEGATE_HMAC_SECRET, raw);
}

function listActivations() {
  return load().activations;
}

function stats() {
  const db = load();
  return {
    totalKeys: db.keys.length,
    activeKeys: db.keys.filter(k => k.status === 'active').length,
    totalActivations: db.activations.length,
    trialKeys: db.keys.filter(k => k.is_trial).length
  };
}

module.exports = {
  load, save,
  findKey, findKeyById, listKeys, createKey, updateKey, deleteKey,
  getActivationsForKey, countActiveDevices, findActivation, findActivationByToken, findActivationByDevice,
  upsertActivation, touchActivation, removeExpired, revokeDevice,
  generateToken, listActivations, stats
};
