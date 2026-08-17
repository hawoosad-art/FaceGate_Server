const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const path = require('node:path');
const sharp = require('sharp');

const ROOT = path.resolve(__dirname, '..');
const PORT = 33871;
const BASE = `http://127.0.0.1:${PORT}`;

function waitForServer(child) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('server did not start')), 15000);
    let output = '';
    const onData = chunk => {
      output += chunk.toString();
      if (output.includes(`Listening 0.0.0.0:${PORT}`)) { clearTimeout(timer); resolve(); }
    };
    child.stdout.on('data', onData); child.stderr.on('data', onData);
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('exit', code => { if (code !== null && !output.includes(`Listening 0.0.0.0:${PORT}`)) { clearTimeout(timer); reject(new Error(`server exited before starting (${code})`)); } });
  });
}

test('demo-card endpoint creates and serves a PNG download', async t => {
  const child = spawn(process.execPath, ['server.js'], { cwd: ROOT, env: { ...process.env, PORT: String(PORT), OPENAI_API_KEY: '', DEMO_CARD_DISABLE_AI: '1' }, stdio: ['ignore', 'pipe', 'pipe'] });
  t.after(() => child.kill('SIGTERM'));
  await waitForServer(child);
  const photo = await sharp({ create: { width: 180, height: 220, channels: 4, background: { r: 55, g: 120, b: 220, alpha: 1 } } }).png().toBuffer();
  const form = new FormData();
  form.set('name', 'Test Person'); form.set('role', 'Demo role'); form.set('organization', 'Fictional Studio'); form.set('photo', new Blob([photo], { type: 'image/png' }), 'photo.png');
  const created = await fetch(`${BASE}/api/demo-card`, { method: 'POST', body: form });
  const payload = await created.json();
  assert.equal(created.status, 200); assert.equal(payload.ok, true); assert.equal(payload.aiUsed, false); assert.equal(payload.watermark, 'SAMPLE — NOT A REAL ID');
  const download = await fetch(`${BASE}${payload.downloadUrl}`);
  assert.equal(download.status, 200); assert.match(download.headers.get('content-type') || '', /^image\/png/); assert.match(download.headers.get('content-disposition') || '', /attachment/);
  const metadata = await sharp(Buffer.from(await download.arrayBuffer())).metadata();
  assert.equal(metadata.format, 'png'); assert.equal(metadata.width, 1400); assert.equal(metadata.height, 880);
});