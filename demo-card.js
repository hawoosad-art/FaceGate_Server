const crypto = require('crypto');
const OpenAI = require('openai');
const sharp = require('sharp');

const CARD_WIDTH = 1400;
const CARD_HEIGHT = 880;
const WATERMARK = 'SAMPLE — NOT A REAL ID';

function clampText(value, maxLength, fallback = '') {
  return String(value || fallback)
    .replace(/[\u0000-\u001f\u007f]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, maxLength);
}

function escapeXml(value) {
  return String(value)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&apos;');
}

function safeColor(value, fallback) {
  const color = String(value || '').trim();
  return /^#[0-9a-f]{6}$/i.test(color) ? color : fallback;
}

function fallbackPlan(input) {
  return {
    headline: clampText(input.label, 28, 'PROFILE CARD'),
    subtitle: clampText(input.tagline, 54, 'A fictional demo profile'),
    accent: '#39d0b4',
    aiUsed: false,
  };
}

async function createSafeDemoPlan(input) {
  const fallback = fallbackPlan(input);
  if (!process.env.OPENAI_API_KEY || process.env.DEMO_CARD_DISABLE_AI === '1') return fallback;
  try {
    const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
    const response = await client.chat.completions.create({
      model: process.env.OPENAI_TEXT_MODEL || 'gpt-5-mini',
      max_completion_tokens: 220,
      response_format: { type: 'json_object' },
      messages: [
        { role: 'system', content:
          'You create copy and a color suggestion for a fictional profile-card demo. ' +
          'Never create or imitate government IDs, driver licenses, passports, visas, permits, ' +
          'school IDs, employee badges, official seals, barcodes, QR codes, document numbers, or ' +
          'security features. Return JSON only with headline, subtitle, and accent. Keep headline ' +
          'under 28 characters, subtitle under 54 characters, and accent as a six-digit hex color. ' +
          'The final renderer permanently adds SAMPLE — NOT A REAL ID.' },
        { role: 'user', content: JSON.stringify({
          label: clampText(input.label, 40, 'PROFILE CARD'),
          tagline: clampText(input.tagline, 80, 'A fictional demo profile'),
          role: clampText(input.role, 60),
          organization: clampText(input.organization, 80),
        }) },
      ],
    });
    const parsed = JSON.parse(response.choices?.[0]?.message?.content || '{}');
    return {
      headline: clampText(parsed.headline, 28, fallback.headline),
      subtitle: clampText(parsed.subtitle, 54, fallback.subtitle),
      accent: safeColor(parsed.accent, fallback.accent),
      aiUsed: true,
    };
  } catch (error) {
    console.warn('[demo-card] AI plan unavailable; using safe fallback:', error.message);
    return fallback;
  }
}

function renderBackgroundSvg({ plan, name, role, organization, tagline }) {
  const accent = escapeXml(plan.accent);
  const headline = escapeXml(plan.headline);
  const subtitle = escapeXml(plan.subtitle);
  const safeName = escapeXml(name || 'Demo Person');
  const safeRole = escapeXml(role || 'Creative profile');
  const safeOrganization = escapeXml(organization || 'Fictional Studio');
  const safeTagline = escapeXml(tagline || subtitle);
  const watermark = Array.from({ length: 5 }, (_, row) => {
    const y = 130 + row * 170;
    return `<text x="680" y="${y}" transform="rotate(-20 680 ${y})" class="watermark">${WATERMARK}</text>`;
  }).join('');
  return `
    <svg xmlns="http://www.w3.org/2000/svg" width="${CARD_WIDTH}" height="${CARD_HEIGHT}">
      <defs>
        <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#0b1730"/><stop offset="55%" stop-color="#13253d"/><stop offset="100%" stop-color="#0d3c4d"/></linearGradient>
        <linearGradient id="glow" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="${accent}" stop-opacity=".32"/><stop offset="100%" stop-color="${accent}" stop-opacity="0"/></linearGradient>
        <pattern id="grid" width="32" height="32" patternUnits="userSpaceOnUse"><path d="M32 0H0V32" fill="none" stroke="#ffffff" stroke-opacity=".045"/></pattern>
        <style>.sans{font-family:Arial,Helvetica,sans-serif}.small{font-size:20px;letter-spacing:3px}.watermark{font-family:Arial,Helvetica,sans-serif;font-size:70px;font-weight:800;letter-spacing:5px;fill:#fff;fill-opacity:.22}</style>
      </defs>
      <rect width="1400" height="880" rx="42" fill="url(#bg)"/><rect width="1400" height="880" rx="42" fill="url(#grid)"/>
      <circle cx="1160" cy="120" r="360" fill="url(#glow)"/><path d="M0 680 C260 590 460 820 760 690 S1200 560 1400 670 V880 H0Z" fill="${accent}" fill-opacity=".09"/>
      <rect x="38" y="38" width="1324" height="804" rx="28" fill="none" stroke="#fff" stroke-opacity=".16" stroke-width="2"/>
      <text x="70" y="95" class="sans small" fill="#fff" fill-opacity=".72">FACEGATE DEMO</text>
      <text x="70" y="145" class="sans" font-size="42" font-weight="700" fill="#fff">${headline}</text>
      <text x="70" y="180" class="sans" font-size="22" fill="#dbeafe">${subtitle}</text>
      <rect x="70" y="220" width="340" height="420" rx="22" fill="#09111e" stroke="#fff" stroke-opacity=".32" stroke-width="3"/>
      <rect x="460" y="242" width="840" height="2" fill="${accent}" fill-opacity=".8"/>
      <text x="460" y="315" class="sans small" fill="#fff" fill-opacity=".62">DISPLAY NAME</text>
      <text x="460" y="370" class="sans" font-size="56" font-weight="700" fill="#fff">${safeName}</text>
      <text x="460" y="430" class="sans" font-size="30" fill="${accent}">${safeRole}</text>
      <text x="460" y="535" class="sans small" fill="#fff" fill-opacity=".62">ORGANIZATION</text>
      <text x="460" y="580" class="sans" font-size="34" font-weight="600" fill="#fff">${safeOrganization}</text>
      <text x="460" y="630" class="sans" font-size="24" fill="#dbeafe">${safeTagline}</text>
      <rect x="70" y="690" width="1230" height="74" rx="18" fill="#000" fill-opacity=".23"/>
      <text x="100" y="736" class="sans" font-size="24" fill="#fff" fill-opacity=".84">Fictional design exercise • no official identifiers • no legal use</text>
      ${watermark}
    </svg>`;
}

async function makeDemoCard(input, photoBuffer) {
  const values = {
    name: clampText(input.name, 48, 'Demo Person'),
    role: clampText(input.role, 48, 'Creative profile'),
    organization: clampText(input.organization, 62, 'Fictional Studio'),
    label: clampText(input.label, 40, 'PROFILE CARD'),
    tagline: clampText(input.tagline, 80, 'A fictional demo profile'),
  };
  const plan = await createSafeDemoPlan(values);
  const background = Buffer.from(renderBackgroundSvg({ plan, ...values }));
  const photo = await sharp(photoBuffer).rotate().resize({ width: 340, height: 420, fit: 'cover', position: 'centre' }).png().toBuffer();
  const photoFrame = Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" width="340" height="420"><rect x="2" y="2" width="336" height="416" rx="20" fill="none" stroke="#fff" stroke-opacity=".72" stroke-width="4"/></svg>');
  const output = await sharp(background).composite([
    { input: photo, left: 70, top: 220 },
    { input: photoFrame, left: 70, top: 220 },
  ]).png().toBuffer();
  return { output, plan, watermark: WATERMARK, requestId: crypto.randomUUID() };
}

module.exports = { WATERMARK, makeDemoCard, createSafeDemoPlan, clampText };