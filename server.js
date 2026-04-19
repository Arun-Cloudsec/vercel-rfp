const express  = require('express');
const Anthropic = require('@anthropic-ai/sdk');
const bcrypt   = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const multer   = require('multer');
const AdmZip   = require('adm-zip');
const XLSX     = require('xlsx');
let pdfParse;
try { pdfParse = require('pdf-parse/lib/pdf-parse'); } catch(e) { try { pdfParse = require('pdf-parse'); } catch(e2) { pdfParse = async()=>({text:'',numpages:0}); } }
const path     = require('path');
const fs       = require('fs');

const app    = express();
const PORT   = process.env.PORT || 3000;
const ALLOWED_EXTENSIONS = /\.(docx|doc|pdf|xls|xlsx|txt|csv)$/i;
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 25 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    ALLOWED_EXTENSIONS.test(file.originalname) ? cb(null, true) : cb(new Error('File type not allowed. Only .docx, .doc, .pdf, .xls, .xlsx, .txt files accepted.'));
  }
});

// ── Persistent storage — uses Azure D:\home\data on App Service, local ./data otherwise ──
const PERSIST_DIR = process.env.HOME
  ? path.join(process.env.HOME, 'data')          // Azure: D:\home\data (survives redeploy)
  : path.join(__dirname, 'data');                 // Local fallback
const DATA_DIR = PERSIST_DIR;
const DB_FILE  = path.join(PERSIST_DIR, 'db.json');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
// Also fix pdf-parse import


// ── Database ──────────────────────────────────────────────────────────────────
function loadDB() {
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch { return { users: [], library: [], recent: [] }; }
}
function saveDB(d) { fs.writeFileSync(DB_FILE, JSON.stringify(d, null, 2)); }

const db = {
  getUser:      (email) => loadDB().users.find(u => u.email === email) || null,
  getUserById:  (id)    => loadDB().users.find(u => u.id === id) || null,
  getUserByToken:(token) => loadDB().users.find(u => u.token === token) || null,
  createUser:   (user)  => { const d = loadDB(); d.users.push(user); saveDB(d); },
  updateUser:   (id, f) => {
    const d = loadDB(), i = d.users.findIndex(u => u.id === id);
    if (i >= 0) { d.users[i] = { ...d.users[i], ...f }; saveDB(d); }
  },
  getLibrary:    (uid) => loadDB().library.filter(l => l.user_id === uid).sort((a,b) => b.created_at.localeCompare(a.created_at)),
  addLibrary:    (item) => { const d = loadDB(); d.library.unshift(item); saveDB(d); },
  deleteLibrary: (id, uid) => { const d = loadDB(); d.library = d.library.filter(l => !(l.id === id && l.user_id === uid)); saveDB(d); },
  getRecent:     (uid) => loadDB().recent.filter(r => r.user_id === uid).sort((a,b) => b.created_at.localeCompare(a.created_at)).slice(0, 10),
  addRecent:     (item) => {
    const d = loadDB(); d.recent.unshift(item);
    const ui = d.recent.filter(r => r.user_id === item.user_id);
    if (ui.length > 10) { const rm = ui.slice(10).map(r => r.id); d.recent = d.recent.filter(r => !rm.includes(r.id)); }
    saveDB(d);
  },
  getEstimations: (uid) => { const d = loadDB(); return (d.estimations||[]).filter(e => e.user_id === uid).sort((a,b) => b.created_at.localeCompare(a.created_at)); },
  addEstimation:  (item) => { const d = loadDB(); if(!d.estimations) d.estimations=[]; d.estimations.unshift(item); if(d.estimations.filter(e=>e.user_id===item.user_id).length > 50){ const keep = d.estimations.filter(e=>e.user_id===item.user_id).slice(0,50).map(e=>e.id); d.estimations = d.estimations.filter(e => e.user_id!==item.user_id || keep.includes(e.id)); } saveDB(d); },
  deleteEstimation:(id,uid) => { const d = loadDB(); d.estimations = (d.estimations||[]).filter(e => !(e.id===id && e.user_id===uid)); saveDB(d); }
};

// ── Field encryption for sensitive values ────────────────────────────────────
const crypto = require('crypto');
const ENC_KEY = Buffer.from(require('crypto').createHash('sha256').update(process.env.SECRET||'changeme2026').digest('hex').substring(0,32));
function encrypt(text){ if(!text)return ''; const iv=crypto.randomBytes(16),c=crypto.createCipheriv('aes-256-cbc',ENC_KEY,iv); return iv.toString('hex')+':'+c.update(text,'utf8','hex')+c.final('hex'); }
function decrypt(text){ if(!text||!text.includes(':'))return text||''; try{ const[ivHex,enc]=text.split(':'),d=crypto.createDecipheriv('aes-256-cbc',ENC_KEY,Buffer.from(ivHex,'hex')); return d.update(enc,'hex','utf8')+d.final('utf8'); }catch(e){return '';} }

// ── Auth: simple token stored in DB + sent as plain cookie ───────────────────
// No express-session, no file locking, works on Windows/Linux/Mac.
function parseCookies(req) {
  const list = {};
  const header = req.headers.cookie;
  if (!header) return list;
  header.split(';').forEach(c => {
    const [k, ...v] = c.trim().split('=');
    list[k.trim()] = decodeURIComponent(v.join('='));
  });
  return list;
}

function setAuthCookie(res, token) {
  const maxAge = 7 * 24 * 60 * 60; // 7 days in seconds
  res.setHeader('Set-Cookie', `rfp_token=${token}; Path=/; Max-Age=${maxAge}; HttpOnly; SameSite=Lax`);
}

function clearAuthCookie(res) {
  res.setHeader('Set-Cookie', 'rfp_token=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax');
}

function auth(req, res, next) {
  const token = parseCookies(req).rfp_token;
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  const user = db.getUserByToken(token);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  req.user = user;
  // Resolve effective API key: user's own key → admin key → any user with a key
  const adminUser  = db.getUser('demo@email.com');
  const adminKey   = adminUser ? adminUser.api_key || '' : '';
  // Last fallback: scan all users for anyone who has set a key
  let fallbackKey  = adminKey;
  if (!fallbackKey) {
    const allUsers = loadDB().users || [];
    const anyWithKey = allUsers.find(u => u.api_key && u.api_key.trim());
    fallbackKey = anyWithKey ? anyWithKey.api_key : '';
  }
  req.effectiveApiKey  = user.api_key || fallbackKey || '';
  // Also resolve ElevenLabs key with same pattern
  const adminElevenKey = adminUser ? adminUser.eleven_labs_key || '' : '';
  let fallbackElevenKey = adminElevenKey;
  if (!fallbackElevenKey) {
    const allUsers2 = loadDB().users || [];
    const anyWithEleven = allUsers2.find(u => u.eleven_labs_key && u.eleven_labs_key.trim());
    fallbackElevenKey = anyWithEleven ? anyWithEleven.eleven_labs_key : '';
  }
  req.effectiveElevenKey = user.eleven_labs_key || fallbackElevenKey || '';
  next();
}

function authPage(req, res, next) {
  const token = parseCookies(req).rfp_token;
  if (!token) return res.redirect('/');
  const user = db.getUserByToken(token);
  if (!user) return res.redirect('/');
  req.user = user;
  next();
}

// ── Rate limiting ────────────────────────────────────────────────────────────
const loginAttempts = new Map();
function loginRateLimit(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  const now = Date.now();
  const rec = loginAttempts.get(ip) || { count: 0, resetAt: now + 15 * 60 * 1000 };
  if (now > rec.resetAt) { rec.count = 0; rec.resetAt = now + 15 * 60 * 1000; }
  if (++rec.count > 10) {
    loginAttempts.set(ip, rec);
    return res.status(429).json({ success: false, error: `Too many attempts. Try again in ${Math.ceil((rec.resetAt - now) / 60000)} min.` });
  }
  loginAttempts.set(ip, rec);
  next();
}
setInterval(() => { const now = Date.now(); for (const [k,v] of loginAttempts) if (now > v.resetAt) loginAttempts.delete(k); }, 3600000);

const apiRequests = new Map();
function apiRateLimit(req, res, next) {
  if (req.path === '/health') return next();
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  const now = Date.now();
  const rec = apiRequests.get(ip) || { count: 0, resetAt: now + 60000 };
  if (now > rec.resetAt) { rec.count = 0; rec.resetAt = now + 60000; }
  if (++rec.count > 100) { apiRequests.set(ip, rec); return res.status(429).json({ error: 'Rate limit exceeded.' }); }
  apiRequests.set(ip, rec);
  next();
}
setInterval(() => { const now = Date.now(); for (const [k,v] of apiRequests) if (now > v.resetAt) apiRequests.delete(k); }, 3600000);

// ── Security headers ──────────────────────────────────────────────────────────
function securityHeaders(req, res, next) {
  res.setHeader('X-Content-Type-Options',  'nosniff');
  res.setHeader('X-Frame-Options',         'DENY');
  res.setHeader('X-XSS-Protection',        '1; mode=block');
  res.setHeader('Referrer-Policy',         'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy',      'geolocation=(), microphone=(), camera=()');
  if (req.secure || req.headers['x-forwarded-proto'] === 'https')
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
}

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(securityHeaders);
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/api/', apiRateLimit);

// ── Azure App Service health check ───────────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));

// ── Local library serving with auto-download ──────────────────────────────────
// Libraries are served from /public/libs/ to avoid CDN blocking by Edge/Safari
// They are downloaded on first request if not already present (no manual setup needed)
const LIBS = {
  'mammoth.min.js':    'https://cdnjs.cloudflare.com/ajax/libs/mammoth/1.6.0/mammoth.browser.min.js',
  'xlsx.min.js':       'https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js',
  'pdf.min.js':        'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.min.js',
  'pdf.worker.min.js': 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js',
};
const LIBS_DIR = path.join(__dirname, 'public', 'libs');
if (!fs.existsSync(LIBS_DIR)) fs.mkdirSync(LIBS_DIR, { recursive: true });

async function downloadLib(filename, url) {
  const dest = path.join(LIBS_DIR, filename);
  if (fs.existsSync(dest)) return; // already downloaded
  console.log('  Downloading library:', filename);
  return new Promise((resolve) => {
    const https = require('https');
    const file  = fs.createWriteStream(dest);
    https.get(url, res => {
      res.pipe(file);
      file.on('finish', () => { file.close(); resolve(); });
    }).on('error', err => {
      fs.unlink(dest, () => {});
      console.warn('  Warning: Could not download', filename, '-', err.message);
      resolve();
    });
  });
}

// Download all libs on startup (non-blocking)
Promise.all(Object.entries(LIBS).map(([f, u]) => downloadLib(f, u)))
  .then(() => console.log('  Libraries ready in /public/libs/'))
  .catch(() => {});

// ── Pages ─────────────────────────────────────────────────────────────────────
app.get('/',    (req, res) => {
  const token = parseCookies(req).rfp_token;
  if (token && db.getUserByToken(token)) return res.redirect('/app');
  res.sendFile(path.join(__dirname, 'public', 'auth.html'));
});
app.get('/app', authPage, (req, res) => res.sendFile(path.join(__dirname, 'public', 'app.html')));

// ── Auth routes ───────────────────────────────────────────────────────────────
// ── Public registration ───────────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, org_name } = req.body;
    if (!email || !password) return res.json({ success: false, error: 'Email and password required' });
    if (password.length < 8) return res.json({ success: false, error: 'Password must be at least 8 characters' });
    const existing = db.getUser(email.toLowerCase());
    if (existing) return res.json({ success: false, error: 'An account with this email already exists' });
    const id    = uuidv4();
    const token = uuidv4() + uuidv4();
    db.createUser({
      id, email: email.toLowerCase(),
      password_hash: await bcrypt.hash(password, 10),
      token,
      org_name: org_name || '', org_industry: 'Technology / IT',
      org_years: '', org_bio: '', api_key: '',
      created_at: new Date().toISOString()
    });
    // Auto-login: set session cookie with correct name
    setAuthCookie(res, token);
    res.json({ success: true });
  } catch(err) {
    res.json({ success: false, error: err.message || 'Registration failed' });
  }
});

// ── Admin CLI helper function (used by manage.js) ─────────────────────────────
async function createUser(email, password, orgName) {
  if (!email || !password) throw new Error('Email and password required');
  if (password.length < 8) throw new Error('Password must be at least 8 characters');
  if (db.getUser(email.toLowerCase())) throw new Error('Email already registered: ' + email);
  const id    = uuidv4();
  const token = uuidv4() + uuidv4();
  db.createUser({
    id, email: email.toLowerCase(),
    password_hash: await bcrypt.hash(password, 10),
    token,
    org_name: orgName || '', org_industry: 'Technology / IT',
    org_years: '', org_bio: '', api_key: '',
    created_at: new Date().toISOString()
  });
  console.log('\n✅ User created: ' + email.toLowerCase());
  return { id, email: email.toLowerCase() };
}
module.exports = { createUser, db };

app.post('/api/auth/login', loginRateLimit, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.json({ success: false, error: 'Email and password required' });
  const user = db.getUser(email.toLowerCase());
  if (!user) return res.json({ success: false, error: 'No account found with this email' });
  if (!await bcrypt.compare(password, user.password_hash)) return res.json({ success: false, error: 'Incorrect password' });
  // Rotate token on each login
  const token = uuidv4() + uuidv4();
  db.updateUser(user.id, { token });
  setAuthCookie(res, token);
  res.json({ success: true });
});

app.post('/api/auth/logout', (req, res) => {
  const token = parseCookies(req).rfp_token;
  if (token) {
    const user = db.getUserByToken(token);
    if (user) db.updateUser(user.id, { token: '' });
  }
  clearAuthCookie(res);
  res.json({ success: true });
});

// ── AI Chat ───────────────────────────────────────────────────────────────────
// Handles all chat intents: rate card updates, role adds, response review/edit,
// azure service updates, general Q&A about the current workspace state.
app.post('/api/chat', auth, async (req, res) => {
  const user = db.getUserById(req.user.id);
  const _apiKey = req.effectiveApiKey; if (!_apiKey) return res.status(400).json({ error: "No API key set. Contact your administrator to add one in Settings." });

  const { message, context, briefLoaded, briefFileName: bfName } = req.body;
  if (!message || typeof message !== 'string' || message.length > 2000) return res.status(400).json({ error: 'Invalid message' });

  const client = new Anthropic({ apiKey: req.effectiveApiKey });

  // Build executive brief section — inject full brief data so AI can answer questions
  let briefSection = '';
  if (context && context.briefContext && context.briefContext.length > 20) {
    briefSection = `

EXECUTIVE BRIEF DATA (document already loaded — DO NOT ask user to upload):
${context.briefContext}

Brief file: "${context.briefFileName || bfName || 'uploaded document'}"
INSTRUCTION: Answer ALL questions about this brief directly from the data above. Include requirements, timeline, GO/NO-GO, win factors, risks, compliance, evaluation criteria, contract value, issuer, and any other details. Never tell the user to upload a document.`;
  } else if (briefLoaded) {
    briefSection = `

An executive brief is loaded from "${bfName || 'uploaded document'}" but detailed data is unavailable. Acknowledge the brief is loaded and ask the user what specific information they need.`;
  }

  const systemPrompt = `You are an AI assistant embedded in RFP Agent Platform — an AI-powered tool for responding to RFPs/RFIs, generating executive briefs, and producing effort estimations.

The user is on the "${(context && context.page) || 'unknown'}" page.

CURRENT PLATFORM STATE:
${context && context.rfpFileName ? `- RFP document loaded (Generate page): "${context.rfpFileName}"` : '- No RFP loaded in Generate page'}
${context && context.currentResp ? `- RFP response available: ${context.currentResp.substring(0, 800)}` : '- No RFP response generated yet'}
${context && context.currentEstimate ? `- Effort estimate: ${context.currentEstimate.deploymentType}, ${context.currentEstimate.months} months, ${(context.currentEstimate.costs && context.currentEstimate.costs.grandTotal) ? context.currentEstimate.costs.grandTotal.toLocaleString() + ' AED' : ''}` : ''}
${context && context.rateCard ? `- Rate card: ${context.rateCard}` : ''}
${context && context.libraryCount !== undefined ? `- ${context.libraryCount} saved responses in library` : ''}${briefSection}

CAPABILITIES — you can help with all of these:
1. EXECUTIVE BRIEF: Answer any question about requirements, timeline, GO/NO-GO, win factors, risks, evaluation criteria, issuer, deadlines, contract value, compliance standards, recommended actions
2. RFP RESPONSE: Review, summarise, improve, fix compliance gaps, rewrite sections, change tone
3. EFFORT ESTIMATION: Review estimates, explain costs, suggest changes
4. RATE CARD: Add/remove/change roles and AED daily rates
5. AZURE SERVICES: Update service percentage breakdown (must total 100%)
6. PLATFORM HELP: Explain how to use any feature

For data changes only, include at the END of your reply:
<ACTION>
{ "type": "update_rate_card"|"update_azure_services"|"update_response"|"add_role", "data": {...} }
</ACTION>

Rate card data format: { "rates": [{"role":"...", "rate":0}] }
Azure services format: { "services": [{"icon":"...","name":"...","pct":0}] } — must sum to 100%
Response format: { "response": "full text" }
Add role format: { "role":"...", "phase":"Design|Implement|Support|Test", "daily_rate_aed":0 }

Only use ACTION blocks for explicit change requests. Otherwise answer directly and helpfully.`;

  const messages = [{ role: 'user', content: message }];

  try {
    const msg = await client.messages.create({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 2000,
      system: systemPrompt,
      messages
    });
    const raw = msg.content.map(b => b.text || '').join('');

    // Parse action block if present
    const actionMatch = raw.match(/<ACTION>([\s\S]*?)<\/ACTION>/);
    let action = null;
    let text = raw.replace(/<ACTION>[\s\S]*?<\/ACTION>/, '').trim();

    if (actionMatch) {
      try { action = JSON.parse(actionMatch[1].trim()); } catch(e) {}
    }

    res.json({ text, action });
  } catch(err) {
    res.status(500).json({ error: err.status === 401 ? 'Invalid API key.' : err.message || 'AI error' });
  }
});

// ── Estimations ──────────────────────────────────────────────────────────────
app.get('/api/estimations',      auth, (req, res) => res.json(db.getEstimations(req.user.id)));
app.post('/api/estimations', auth, (req, res) => {
  const { title, summary, deploymentType, months, totalDays, costs, roles, monthCols, projectScope, azureBreakdown } = req.body;
  const item = {
    id: uuidv4(), user_id: req.user.id,
    title: (title||'').substring(0,200), summary: (summary||'').substring(0,1000),
    deploymentType: (deploymentType||'').substring(0,100),
    months: parseInt(months)||0, totalDays: parseInt(totalDays)||0,
    costs: costs||{}, roles: Array.isArray(roles)?roles.slice(0,50):[],
    monthCols: Array.isArray(monthCols)?monthCols.slice(0,24):[],
    projectScope: (projectScope||'').substring(0,2000),
    azureBreakdown: Array.isArray(azureBreakdown)?azureBreakdown.slice(0,20):null,
    created_at: new Date().toISOString()
  };
  db.addEstimation(item); res.json({ success: true, id: item.id });
});
app.delete('/api/estimations/:id', auth, (req, res) => { db.deleteEstimation(req.params.id, req.user.id); res.json({ success: true }); });

// ── User profile ──────────────────────────────────────────────────────────────
const ADMIN_EMAIL = 'demo@email.com';

app.get('/api/me', auth, (req, res) => {
  const { password_hash, token, ...safe } = req.user;
  const adminUser = db.getUser(ADMIN_EMAIL);
  safe.shared_api_key       = adminUser ? adminUser.api_key         || '' : '';
  safe.shared_rate_card     = adminUser ? adminUser.rate_card        || '' : '';
  safe.shared_azure         = adminUser ? adminUser.azure_services   || '' : '';
  safe.shared_eleven_key    = req.effectiveElevenKey || '';  // already resolved in auth middleware
  safe.is_admin             = (req.user.email === ADMIN_EMAIL);
  res.json(safe);
});

app.put('/api/me', auth, (req, res) => {
  const isAdmin = req.user.email === ADMIN_EMAIL;
  const { org_name, org_industry, org_years, org_bio, api_key, rate_card, azure_services, eleven_labs_key } = req.body;

  // ALL users can save their own API keys and profile
  const update = {
    org_name:        org_name        || '',
    org_industry:    org_industry    || '',
    org_years:       org_years       || '',
    org_bio:         org_bio         || '',
  };
  // Every user can set their own Anthropic + ElevenLabs keys
  if (api_key         !== undefined) update.api_key         = api_key         || '';
  if (eleven_labs_key !== undefined) update.eleven_labs_key = eleven_labs_key || '';
  // Only admin can update shared rate card and azure services
  if (isAdmin) {
    if (rate_card      !== undefined) update.rate_card      = rate_card      || '';
    if (azure_services !== undefined) update.azure_services = azure_services || '';
  }

  db.updateUser(req.user.id, update);
  res.json({ success: true, is_admin: isAdmin });
});

// ── ElevenLabs TTS Proxy ───────────────────────────────────────────────────────
// Keeps the API key server-side; returns audio/mpeg stream to the browser
// ── ElevenLabs key test + debug ───────────────────────────────────────────────
app.get('/api/elevenlabs/test', auth, async (req, res) => {
  const elevenKey = req.effectiveElevenKey || '';
  if (!elevenKey) return res.json({ ok: false, error: 'No ElevenLabs key configured in Settings' });
  res.json({ ok: true, keyPrefix: elevenKey.substring(0, 8) + '…' });
});

// Debug: shows exactly what keys are stored for this user (no secrets exposed)
app.get('/api/elevenlabs/debug', auth, (req, res) => {
  const u = req.user;
  const allUsers = loadDB().users || [];
  const anyWithEleven = allUsers.find(uu => uu.eleven_labs_key && uu.eleven_labs_key.trim());
  res.json({
    user_email:          u.email,
    user_has_eleven_key: !!(u.eleven_labs_key && u.eleven_labs_key.trim()),
    user_eleven_prefix:  u.eleven_labs_key ? u.eleven_labs_key.substring(0,8)+'…' : '(empty)',
    user_has_api_key:    !!(u.api_key && u.api_key.trim()),
    effective_eleven_key: req.effectiveElevenKey ? req.effectiveElevenKey.substring(0,8)+'…' : '(none)',
    any_user_with_eleven: anyWithEleven ? anyWithEleven.email : '(none)',
  });
});

// ── ElevenLabs TTS — saves audio as temp static file served by IIS directly ──
// IIS serves static files natively (bypasses IISNode), so no binary corruption.
const TEMP_AUDIO_DIR = path.join(__dirname, 'public', 'temp');
if (!fs.existsSync(TEMP_AUDIO_DIR)) fs.mkdirSync(TEMP_AUDIO_DIR, { recursive: true });

// Clean up temp audio files older than 10 minutes every 5 minutes
setInterval(() => {
  try {
    const files = fs.readdirSync(TEMP_AUDIO_DIR);
    const cutoff = Date.now() - 10 * 60 * 1000;
    files.forEach(f => {
      try {
        const fp = path.join(TEMP_AUDIO_DIR, f);
        if (fs.statSync(fp).mtimeMs < cutoff) fs.unlinkSync(fp);
      } catch(_) {}
    });
  } catch(_) {}
}, 5 * 60 * 1000);

app.post('/api/elevenlabs/speak', auth, async (req, res) => {
  const { text, voice_id, language_code } = req.body;
  if (!text) return res.status(400).json({ error: 'No text provided' });

  const elevenKey = req.effectiveElevenKey || '';
  if (!elevenKey) return res.status(400).json({ error: 'No ElevenLabs API key configured. Add it in Settings.' });

  const voiceId  = voice_id || 'nPczCjzI2devNBz1zQrb';
  const langCode = (language_code || 'en').toLowerCase().trim();

  // Use multilingual model for non-English, turbo for English (faster)
  const isEnglish = langCode === 'en' || langCode === 'af' || langCode === 'auto' || !langCode;
  const modelId   = isEnglish ? 'eleven_turbo_v2_5' : 'eleven_multilingual_v2';

  // Only pass language_code for non-English (ElevenLabs ignores it for English)
  const bodyPayload = {
    text: text.substring(0, 4500),
    model_id: modelId,
    voice_settings: {
      stability: 0.52,
      similarity_boost: 0.85,
      style: 0.30,
      use_speaker_boost: true
    }
  };
  if (!isEnglish && langCode !== 'auto') {
    bodyPayload.language_code = langCode;
  }

  console.log(`[ElevenLabs] lang=${langCode} model=${modelId} voice=${voiceId}`);

  try {
    const upstream = await fetch(`https://api.elevenlabs.io/v1/text-to-speech/\${voiceId}`, {
      method: 'POST',
      headers: { 'xi-api-key': elevenKey, 'Content-Type': 'application/json', 'Accept': 'audio/mpeg' },
      body: JSON.stringify(bodyPayload)
    });

    if (!upstream.ok) {
      const e = await upstream.json().catch(() => ({}));
      return res.status(upstream.status).json({ error: e?.detail?.message || e?.detail || 'ElevenLabs error' });
    }

    const audioBuf = Buffer.from(await upstream.arrayBuffer());
    console.log('[ElevenLabs] audio bytes:', audioBuf.length);

    // Save to public/temp — IIS serves static files directly, bypassing IISNode
    const fileId  = uuidv4();
    const fileName = `audio-${fileId}.mp3`;
    const filePath = path.join(TEMP_AUDIO_DIR, fileName);
    fs.writeFileSync(filePath, audioBuf);

    // Auto-delete after 10 minutes
    setTimeout(() => { try { fs.unlinkSync(filePath); } catch(_) {} }, 10 * 60 * 1000);

    res.json({ ok: true, url: `/temp/${fileName}`, size: audioBuf.length });

  } catch(err) {
    res.status(500).json({ error: err.message || 'TTS error' });
  }
});

// Clean up specific temp audio file on request
app.delete('/api/elevenlabs/temp/:file', auth, (req, res) => {
  const safe = path.basename(req.params.file);
  try { fs.unlinkSync(path.join(TEMP_AUDIO_DIR, safe)); } catch(_) {}
  res.json({ ok: true });
});

app.put('/api/me/password', auth, async (req, res) => {
  const { current, newPassword } = req.body;
  if (!await bcrypt.compare(current, req.user.password_hash)) return res.json({ success: false, error: 'Current password incorrect' });
  if (!newPassword || newPassword.length < 8) return res.json({ success: false, error: 'New password must be 8+ characters' });
  db.updateUser(req.user.id, { password_hash: await bcrypt.hash(newPassword, 10) });
  res.json({ success: true });
});

// ── Library ───────────────────────────────────────────────────────────────────
app.get('/api/library',       auth, (req, res) => res.json(db.getLibrary(req.user.id)));
app.post('/api/library',      auth, (req, res) => {
  const { rfp_name, industry, company, response, rfp_text, score, version } = req.body;
  const item = { id: uuidv4(), user_id: req.user.id, rfp_name: rfp_name||'Untitled', industry: industry||'', company: company||'', response: response||'', rfp_text: (rfp_text||'').substring(0, 3000), score: score||0, version: version||1, created_at: new Date().toISOString() };
  db.addLibrary(item); res.json({ success: true, id: item.id });
});
app.delete('/api/library/:id', auth, (req, res) => { db.deleteLibrary(req.params.id, req.user.id); res.json({ success: true }); });

// ── Recent ────────────────────────────────────────────────────────────────────
app.get('/api/recent',  auth, (req, res) => res.json(db.getRecent(req.user.id)));
app.post('/api/recent', auth, (req, res) => {
  db.addRecent({ id: uuidv4(), user_id: req.user.id, rfp_name: req.body.rfp_name||'Untitled', score: req.body.score||0, created_at: new Date().toISOString() });
  res.json({ success: true });
});

// ── AI: Generate text response (plain text, no docx) ─────────────────────────
// ── AI: Executive Brief — analyze RFP/RFI and return structured insights ──────
app.post('/api/analyze-rfp', auth, upload.single('rfpDoc'), async (req, res) => {
  const rfpFile = req.file;
  if (!rfpFile) return res.status(400).json({ error: 'No document uploaded' });

  const _apiKey = req.effectiveApiKey;
  if (!_apiKey) return res.status(400).json({ error: 'No API key set. Contact your administrator.' });

  try {
    // ── Extract text from document ───────────────────────────────────────────
    let fullText = '';
    const fname  = rfpFile.originalname.toLowerCase();

    if (fname.endsWith('.pdf')) {
      const pdfData = await pdfParse(rfpFile.buffer);
      fullText = pdfData.text || '';
    } else if (fname.endsWith('.docx') || fname.endsWith('.doc')) {
      const zip = new AdmZip(rfpFile.buffer);
      const docEntry = zip.getEntry('word/document.xml');
      if (docEntry) {
        fullText = docEntry.getData().toString('utf8').replace(/<[^>]+>/g,' ').replace(/\s+/g,' ');
      }
    } else if (fname.endsWith('.xlsx') || fname.endsWith('.xls')) {
      const wb = XLSX.read(rfpFile.buffer, { type: 'buffer' });
      wb.SheetNames.forEach(sn => {
        fullText += `\n[Sheet: ${sn}]\n` + XLSX.utils.sheet_to_txt(wb.Sheets[sn]);
      });
    } else if (fname.endsWith('.zip')) {
      const zip = new AdmZip(rfpFile.buffer);
      for (const entry of zip.getEntries()) {
        if (entry.isDirectory) continue;
        const en = entry.entryName.toLowerCase();
        try {
          if (en.endsWith('.pdf')) {
            const pd = await pdfParse(entry.getData());
            fullText += `\n[${entry.entryName}]\n${pd.text}`;
          } else if (en.endsWith('.docx')) {
            const dz = new AdmZip(entry.getData());
            const de = dz.getEntry('word/document.xml');
            if (de) fullText += `\n[${entry.entryName}]\n` + de.getData().toString('utf8').replace(/<[^>]+>/g,' ');
          } else if (en.endsWith('.txt') || en.endsWith('.csv')) {
            fullText += `\n[${entry.entryName}]\n` + entry.getData().toString('utf8');
          } else if (en.endsWith('.xlsx') || en.endsWith('.xls')) {
            const wb2 = XLSX.read(entry.getData(), { type: 'buffer' });
            wb2.SheetNames.forEach(sn => { fullText += `\n[${entry.entryName}/${sn}]\n` + XLSX.utils.sheet_to_txt(wb2.Sheets[sn]); });
          }
        } catch(e) { /* skip unreadable entries */ }
      }
    } else {
      fullText = rfpFile.buffer.toString('utf8');
    }

    if (!fullText.trim()) return res.status(400).json({ error: 'Could not extract readable text from this document.' });

    // Truncate to fit context window
    const snippet  = fullText.substring(0, 14000);
    const language     = (req.body.language || 'English').trim();
    const srcLangName  = (req.body.source_language_name || 'Auto-Detect').trim();
    const srcLangCode  = (req.body.source_language || 'auto').trim();
    const isAutoDetect = srcLangCode === 'auto' || srcLangCode === '';

    // ── Build a strong, unambiguous translation + extraction instruction ──────
    // This works for ANY source→target pair: Arabic→Spanish, French→Korean, etc.
    const langSystem = [
      isAutoDetect
        ? 'The document may be in ANY language. Automatically detect and read it.'
        : `STEP 1 — READ: The document is written in ${srcLangName}. Read and understand every word of the ${srcLangName} document fully before doing anything else.`,
      `STEP 2 — TRANSLATE & WRITE: You MUST produce the entire JSON output in ${language}.`,
      `Every single text value in the JSON — executive_summary, scope, go_nogo_reason, all items in win_factors[], risk_flags[], recommended_actions[], eval_criteria[].criterion, compliance_standards[], timeline[].event, key_requirements[].title, key_requirements[].description, local_content, contact — MUST be written in ${language}.`,
      `This is a translation task: source language is ${isAutoDetect ? 'auto-detected' : srcLangName}, output language is ${language}.`,
      `Do NOT leave any text in the source language. Do NOT mix languages. If you find yourself writing in ${isAutoDetect ? 'the source language' : srcLangName}, STOP and translate to ${language}.`,
      `Only these stay unchanged: JSON key names, numeric values, dates, percentages, reference codes (like "GOV-2025-IT-001"), and the go_nogo value ("GO"/"NO-GO"/"CONDITIONAL GO").`
    ].join(' ');

    // ── Call Claude to extract structured insights ────────────────────────────
    const client = new Anthropic({ apiKey: _apiKey });
    const prompt = `You are an expert multilingual RFP/RFI analyst and translator preparing an executive briefing for senior leadership.

${langSystem}

Analyze the following RFP/RFI document and extract ALL available information. Return ONLY a valid JSON object with this exact structure (no markdown, no extra text):

{
  "title": "Full RFP/RFI title",
  "issuer": "Organization name",
  "ref": "RFP/RFI reference number if any",
  "executive_summary": "2-3 sentence summary of what they need and why it matters",
  "scope": "3-4 sentence high-level scope description",
  "industry": "Industry sector",
  "contract_value": "Budget or contract value range if mentioned, else null",
  "contract_duration": "Contract duration if mentioned, else null",
  "submission_date": "Submission/response deadline date",
  "qa_deadline": "Q&A or clarification deadline if mentioned, else null",
  "award_date": "Expected award date if mentioned, else null",
  "timeline": [
    {"event": "event name", "date": "date string"}
  ],
  "key_requirements": [
    {"id": "req id or number", "title": "requirement title", "priority": "MANDATORY/HIGH/MEDIUM", "description": "brief description"}
  ],
  "eval_criteria": [
    {"criterion": "criterion name", "weight": "weight or percentage if given"}
  ],
  "compliance_standards": ["ISO 27001", "SOC 2", "etc"],
  "go_nogo": "GO or CONDITIONAL GO or NO-GO",
  "go_nogo_reason": "1-2 sentence justification for recommendation",
  "win_probability": 65,
  "win_factors": ["factor 1", "factor 2", "factor 3"],
  "risk_flags": ["risk 1", "risk 2"],
  "recommended_actions": ["action 1", "action 2", "action 3"],
  "local_content": "Local content requirements if any, else null",
  "contact": "Contact details if available, else null"
}

RFP DOCUMENT TEXT:
${snippet}`;

    const msg = await client.messages.create({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 2000,
      messages: [{ role: 'user', content: prompt }]
    });

    const raw = msg.content.map(b => b.text || '').join('').trim();
    // Strip any markdown fences
    const clean = raw.replace(/^```json?\s*/i,'').replace(/\s*```$/,'').trim();
    const data  = JSON.parse(clean);

    res.json({ success: true, brief: data, filename: rfpFile.originalname });

  } catch(err) {
    const msg = err.status === 401 ? 'Invalid API key.'
              : err.status === 400 ? 'API credit balance too low.'
              : err instanceof SyntaxError ? 'AI returned invalid JSON — please retry.'
              : err.message || 'Server error';
    res.status(500).json({ error: msg });
  }
});

app.post('/api/generate', auth, async (req, res) => {
  const user = req.user;
  const _apiKey = req.effectiveApiKey; if (!_apiKey) return res.status(400).json({ error: "No API key set. Contact your administrator to add one in Settings." });
  const { rfpText, histTexts, histNames, config, library } = req.body;
  if (!rfpText || !rfpText.trim()) return res.status(400).json({ error: 'No RFP text provided' });
  const histCtx = histTexts && histTexts.length ? '\n\nHISTORICAL PROPOSALS:\n' + histTexts.map((t,i) => `[Ref ${i+1}: ${(histNames&&histNames[i])||'ref'}]\n${t.substring(0,2000)}`).join('\n\n') : '';
  const libCtx  = library && library.length ? '\n\nLIBRARY RESPONSES:\n' + library.slice(-3).map(l => `[${l.rfp_name} score:${l.score}]\n${(l.response||'').substring(0,800)}`).join('\n\n') : '';
  const prompt = `You are an expert RFP response writer for ${(config&&config.company)||user.org_name||'Our Organization'}.
PROFILE: ${user.org_bio||'A leading technology solutions provider.'}
INDUSTRY: ${(config&&config.industry)||'Technology / IT'} | TONE: ${(config&&config.tone)||'Formal & Professional'} | LENGTH: ${(config&&config.length)||'Comprehensive'}
COMPLIANCE: ${(config&&config.compliance)||'Auto-detect'} | FOCUS: ${(config&&config.focus)||'all sections'}
EXTRA CONTEXT: ${(config&&config.context)||'none'}

RFP DOCUMENT:
${rfpText.substring(0,4000)}${histCtx.substring(0,2000)}${libCtx.substring(0,1500)}

Write a complete structured vendor response with sections: Executive Summary, Company Overview, Technical Solution, Implementation Plan, Compliance & Certifications, Team & Staffing, Pricing Structure, References & Case Studies. Use ## for H2 headers and ### for H3 sub-headers.

End response with exactly this line:
SCORES_JSON:{"requirements":85,"technical":78,"compliance":90,"clarity":88,"win_probability":72}`;
  try {
    const client = new Anthropic({ apiKey: req.effectiveApiKey });
    const msg = await client.messages.create({ model: 'claude-sonnet-4-20250514', max_tokens: 4000, messages: [{ role: 'user', content: prompt }] });
    const raw = msg.content.map(b => b.text||'').join('');
    let scores = { requirements:75, technical:70, compliance:80, clarity:75, win_probability:65 };
    const m = raw.match(/SCORES_JSON:(\{[^}]+\})/);
    if (m) { try { scores = JSON.parse(m[1]); } catch(e) {} }
    res.json({ response: raw.replace(/SCORES_JSON:\{[^}]+\}/, '').trim(), scores });
  } catch(err) {
    res.status(500).json({ error: err.status===401?'Invalid API key.':err.status===400?'Credit balance too low — add credits at console.anthropic.com':err.message||'API error' });
  }
});

// ── AI: Improve text response ─────────────────────────────────────────────────
app.post('/api/improve', auth, async (req, res) => {
  const user = req.user;
  const _apiKey = req.effectiveApiKey; if (!_apiKey) return res.status(400).json({ error: "No API key set. Contact your administrator to add one in Settings." });
  const { instruction, currentResponse, rfpText, scores: prev } = req.body;
  const prompt = `Expert RFP writer. Improve the response per instruction: "${instruction}"
RFP CONTEXT: ${(rfpText||'').substring(0,1500)}
CURRENT RESPONSE:
${currentResponse}
Keep ## / ### structure. End with:
SCORES_JSON:{"requirements":85,"technical":78,"compliance":90,"clarity":88,"win_probability":72}`;
  try {
    const client = new Anthropic({ apiKey: req.effectiveApiKey });
    const msg = await client.messages.create({ model: 'claude-sonnet-4-20250514', max_tokens: 4000, messages: [{ role: 'user', content: prompt }] });
    const raw = msg.content.map(b => b.text||'').join('');
    let scores = prev || { requirements:75, technical:70, compliance:80, clarity:75, win_probability:65 };
    const m = raw.match(/SCORES_JSON:(\{[^}]+\})/);
    if (m) { try { scores = JSON.parse(m[1]); } catch(e) {} }
    res.json({ response: raw.replace(/SCORES_JSON:\{[^}]+\}/, '').trim(), scores });
  } catch(err) { res.status(500).json({ error: err.message||'API error' }); }
});

// ── Extract ALL rows from a historical docx that have vendor responses ─────────
// Returns array of { reqId, reqTitle, reqDesc, response, fileName }
// Works regardless of ID format — captures any row where column 4 has real content
function extractHistoricalRows(xml, fileName) {
  const rows = [];
  const trRe = /<w:tr[ >][\s\S]*?<\/w:tr>/g;
  let tm;
  while ((tm = trRe.exec(xml)) !== null) {
    const tr = tm[0];
    const cells = [];
    const tcRe = /<w:tc>[\s\S]*?<\/w:tc>/g;
    let cm;
    while ((cm = tcRe.exec(tr)) !== null) {
      cells.push(cm[0].replace(/<[^>]+>/g,' ').replace(/\s+/g,' ').trim());
    }
    if (cells.length >= 4) {
      const col1 = cells[0].trim();
      const col2 = cells[1].trim();
      const col3 = cells[2].trim();
      const col4 = cells[3].trim();
      // Skip header rows and rows with no vendor response
      if (!col2 || col4.length < 20) continue;
      if (col4.toLowerCase().includes('[vendor to complete]')) continue;
      if (col4.toLowerCase().includes('[vendor response]')) continue;
      if (col4.toLowerCase().includes('source:') && col4.length < 40) continue;
      // Strip source notes from previous runs (italic grey lines beginning "Source:")
      const cleanedResp = col4.replace(/Source:[^\n]*/gi, '').trim();
      if (cleanedResp.length < 15) continue;
      rows.push({
        reqId:    col1,
        reqTitle: col2,
        reqDesc:  col3,
        response: cleanedResp,
        fileName
      });
    }
  }
  return rows;
}

// ── Semantic matching: for each new requirement find best historical match ─────
// Uses AI to match by meaning, not ID. Runs one batch call for all new reqs.
// Returns { newReqId -> historicalRow } where a good match was found (confidence >= 7/10)
async function semanticMatch(client, newRows, historicalRows) {
  if (!historicalRows.length || !newRows.length) return {};

  // Build compact index of historical rows
  const histIndex = historicalRows.map((h, i) =>
    `H${i}|ID:${h.reqId}|Title:${h.reqTitle}|Desc:${h.reqDesc.substring(0,120)}|Response preview:${h.response.substring(0,80)}`
  ).join('\n');

  // Build new requirements list
  const newList = newRows.map((r, i) =>
    `N${i}|ID:${r.reqId}|Title:${r.reqTitle}|Desc:${r.reqDesc.substring(0,150)}`
  ).join('\n');

  const prompt = `You are a requirements matching expert. Match each NEW requirement to the BEST historical requirement based on semantic meaning — even if the wording, numbering, or phrasing is different. The underlying topic and intent matter, not the exact words.

HISTORICAL REQUIREMENTS (with vendor responses already written):
${histIndex}

NEW REQUIREMENTS (need vendor responses):
${newList}

For each new requirement (N0, N1, N2...), find the best historical match (H0, H1, H2...) if one exists.
A match is valid if the new and historical requirements are about the same topic (e.g. both about firewall, both about identity management, both about compliance reporting).
Only match if confidence is 7 or higher out of 10.

Reply ONLY with a JSON array. No markdown, no explanation.
[{"new":"N0","hist":"H2","confidence":9},{"new":"N1","hist":"H0","confidence":8},{"new":"N2","hist":null,"confidence":0}]`;

  try {
    const msg = await client.messages.create({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 1000,
      messages: [{ role: 'user', content: prompt }]
    });
    const raw     = msg.content.map(b => b.text || '').join('').trim();
    const cleaned = raw.replace(/^```[a-z]*\n?/,'').replace(/\n?```$/,'').trim();
    const matches = JSON.parse(cleaned);

    const result = {};
    for (const m of matches) {
      if (!m.hist || m.confidence < 7) continue;
      const newIdx  = parseInt(m.new.replace('N',''));
      const histIdx = parseInt(m.hist.replace('H',''));
      if (isNaN(newIdx) || isNaN(histIdx)) continue;
      if (newIdx >= newRows.length || histIdx >= historicalRows.length) continue;
      result[newRows[newIdx].reqId] = historicalRows[histIdx];
    }
    return result;
  } catch(e) {
    return {}; // semantic match failed — fall back gracefully
  }
}


// Step 1: Parse rows and inject unique placeholder markers into the 4th cell
function injectPlaceholders(xml) {
  const rows = [];
  let markedXml = xml;
  let offset = 0;

  // ── Helper: extract all cell texts from a <w:tr> ───────────────────────────
  function getCells(trXml) {
    const cells = [];
    const tcRe = /<w:tc>[\s\S]*?<\/w:tc>/g;
    let m;
    while ((m = tcRe.exec(trXml)) !== null) {
      cells.push({ text: m[0].replace(/<[^>]+>/g,' ').replace(/\s+/g,' ').trim(), xml: m[0] });
    }
    return cells;
  }

  // ── Step 1: Collect all rows, find the header row ─────────────────────────
  // Priority tiers — tier 0 wins over tier 3 when multiple columns match
  const VENDOR_RESP_TIERS = [
    // Tier 0: unambiguous vendor/company response columns (highest priority)
    ['vendor response','vendor responses','your response','proposed response',
     'vendor answer','company response','vendor to complete','fill in response'],
    // Tier 1: compliance-specific response columns
    ['compliance response','response to requirement','your answer',
     'vendor comments','supplier response','bidder response'],
    // Tier 2: generic standalone "response" or "answer"
    ['answer','response'],
    // Tier 3: last resort — only if nothing better exists
    ['to be completed','fill in','tbd','comments','remarks','notes'],
  ];

  const allTrs = [];
  const trRe = /<w:tr[ >][\s\S]*?<\/w:tr>/g;
  let tm;
  while ((tm = trRe.exec(xml)) !== null) {
    allTrs.push({ xml: tm[0], index: tm.index });
  }

  if (!allTrs.length) return { rows: [], markedXml };

  // Find the header row and the vendor-response column using priority tiers
  let headerRowIdx   = -1;
  let vendorColIdx   = -1;
  let vendorTier     = 999;
  let reqTextColIdx  = -1;
  let reqIdColIdx    = -1;

  for (let i = 0; i < Math.min(allTrs.length, 8); i++) {
    const cells = getCells(allTrs[i].xml);
    let rowHasVendorCol = false;

    for (let c = 0; c < cells.length; c++) {
      const txt = cells[c].text.toLowerCase().trim();
      if (!txt) continue;

      // Check each tier — lower tier number = higher priority
      for (let tier = 0; tier < VENDOR_RESP_TIERS.length; tier++) {
        if (VENDOR_RESP_TIERS[tier].some(k => txt === k || txt.includes(k))) {
          if (tier < vendorTier) {
            headerRowIdx = i;
            vendorColIdx = c;
            vendorTier   = tier;
            rowHasVendorCol = true;
          }
          break; // don't check lower-priority tiers for this cell
        }
      }
    }

    // Once we've found a Tier 0 or Tier 1 match, commit to this header row
    if (rowHasVendorCol && vendorTier <= 1) break;
    // For Tier 2/3, keep scanning — a later row might have a better match
    if (headerRowIdx >= 0 && vendorTier <= 1) break;
  }

  // Fallback: assume last column is vendor response
  if (headerRowIdx < 0 || vendorColIdx < 0) {
    const hdrCells = getCells(allTrs[0].xml);
    headerRowIdx = 0;
    vendorColIdx = hdrCells.length - 1;
  }

  // Identify the requirement text column from the header row
  const hdrCells = getCells(allTrs[headerRowIdx].xml);
  for (let c = 0; c < hdrCells.length; c++) {
    if (c === vendorColIdx) continue;
    const txt = hdrCells[c].text.toLowerCase().trim();
    // Column that looks like a short ID/number column
    if (reqIdColIdx < 0 && (txt === '#' || txt === 'no.' || txt === 'no' || txt === 'id' ||
        txt === 'req#' || txt === 'req #' || txt === 'sl.no' || txt === 's.no' || txt === 'item no')) {
      reqIdColIdx = c;
      continue;
    }
    // First substantive column that isn't the ID or vendor response
    if (reqTextColIdx < 0 && txt.length > 1) {
      reqTextColIdx = c;
    }
  }
  // Fallback: if still not found, pick first column that isn't vendorColIdx
  if (reqTextColIdx < 0) {
    reqTextColIdx = vendorColIdx === 0 ? 1 : 0;
  }

  // ── Step 2: Process data rows (everything after the header row) ────────────
  const seenIds = {};

  for (let i = headerRowIdx + 1; i < allTrs.length; i++) {
    const cells = getCells(allTrs[i].xml);
    if (cells.length <= vendorColIdx) continue; // row doesn't have enough columns

    const reqText = reqTextColIdx < cells.length ? cells[reqTextColIdx].text.trim() : '';
    if (reqText.length < 3) continue; // skip empty / spacer rows

    // Skip rows that look like sub-headers inside the table
    const SKIP_HDR = ['req#','req #','requirement','description','no.','s.no','sl.no','item no','item #','id','#','category','section','criteria','title','subject'];
    if (reqText.length < 40 && SKIP_HDR.some(k => reqText.toLowerCase() === k)) continue;

    // Build a unique, regex-safe ID
    let rawId = '';
    if (reqIdColIdx >= 0 && reqIdColIdx < cells.length) {
      rawId = cells[reqIdColIdx].text.trim();
    }
    if (!rawId) rawId = `ROW${i}`;
    // Sanitise and make unique
    rawId = rawId.replace(/\s+/g,'_').replace(/[^a-zA-Z0-9_\-]/g,'').substring(0, 30) || `ROW${i}`;
    if (seenIds[rawId]) { rawId = rawId + '_' + i; }
    seenIds[rawId] = true;

    // Find extra description column (between reqText and vendor resp)
    let reqDesc = '';
    for (let c = 0; c < cells.length; c++) {
      if (c === vendorColIdx || c === reqTextColIdx || c === reqIdColIdx) continue;
      const t = cells[c].text.trim();
      if (t.length > 3) { reqDesc = t; break; }
    }

    const existing      = cells[vendorColIdx].text.trim();
    const placeholder   = `__RFPFILL_${rawId}__`;
    const respCellXml   = cells[vendorColIdx].xml;
    const propsM        = respCellXml.match(/<w:tcPr>[\s\S]*?<\/w:tcPr>/);
    const cellProps     = propsM ? propsM[0] : '';
    const placeholderCell = `<w:tc>${cellProps}<w:p><w:r><w:t xml:space="preserve">${placeholder}</w:t></w:r></w:p></w:tc>`;

    // Replace exactly the vendor-response cell in markedXml
    const trAbsStart = allTrs[i].index + offset;
    let cellCount = 0;
    const tcRe2 = /<w:tc>[\s\S]*?<\/w:tc>/g;
    let cm2;
    const trChunk = markedXml.substring(trAbsStart);
    while ((cm2 = tcRe2.exec(trChunk)) !== null) {
      if (cellCount === vendorColIdx) {
        const cellAbsStart = trAbsStart + cm2.index;
        const cellAbsEnd   = cellAbsStart + cm2[0].length;
        markedXml = markedXml.substring(0, cellAbsStart) + placeholderCell + markedXml.substring(cellAbsEnd);
        offset += placeholderCell.length - cm2[0].length;
        break;
      }
      cellCount++;
      if (cm2.index > allTrs[i].xml.length + 1000) break;
    }

    rows.push({ reqId: rawId, reqTitle: reqText, reqDesc, existing, placeholder });
  }

  return { rows, markedXml };
}

// Step 2: Build a proper <w:tc> with response text, preserving original cell width
function buildResponseCell(text, origCellXml) {
  const esc = text
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&apos;');
  const parasXml = esc.split(/\n+/).filter(p => p.trim()).map(p =>
    `<w:p><w:pPr><w:spacing w:before="60" w:after="80"/></w:pPr>` +
    `<w:r><w:rPr><w:sz w:val="20"/><w:szCs w:val="20"/></w:rPr>` +
    `<w:t xml:space="preserve">${p.trim()}</w:t></w:r></w:p>`
  ).join('');
  const propsM = origCellXml.match(/<w:tcPr>[\s\S]*?<\/w:tcPr>/);
  return `<w:tc>${propsM ? propsM[0] : ''}${parasXml}</w:tc>`;
}

// Step 3: Replace placeholder cells with filled cells including source note
function applyResponses(markedXml, responseMap) {
  let result = markedXml;
  let filled = 0;

  for (const [reqId, item] of Object.entries(responseMap)) {
    const responseText = typeof item === 'string' ? item : item.response;
    const sourceText   = typeof item === 'string' ? 'AI Generated' : (item.source || 'Azure Industry Best Practices');
    const placeholder  = `__RFPFILL_${reqId}__`;

    // Find the placeholder position using plain string search — no regex cross-cell risk
    const phIdx = result.indexOf(placeholder);
    if (phIdx === -1) continue; // placeholder not found, skip

    // Walk backwards from placeholder to find the opening <w:tc> of this cell
    const cellOpenTag = '<w:tc>';
    let cellStart = result.lastIndexOf(cellOpenTag, phIdx);
    if (cellStart === -1) continue;

    // Walk forwards from placeholder to find the closing </w:tc> of this cell
    const cellCloseTag = '</w:tc>';
    let cellEnd = result.indexOf(cellCloseTag, phIdx);
    if (cellEnd === -1) continue;
    cellEnd += cellCloseTag.length; // include the closing tag itself

    // Extract the original cell XML to preserve <w:tcPr> (column width etc.)
    const origCellXml = result.substring(cellStart, cellEnd);
    const propsM      = origCellXml.match(/<w:tcPr>[\s\S]*?<\/w:tcPr>/);

    // Build replacement XML — handle multi-line template output and Unicode checkboxes
    const lines = (responseText || '(no response)').split(/\n/);
    const paragraphs = lines.map(line => {
      const trimmed = line; // preserve leading spaces for indentation
      if (!trimmed.trim()) {
        // Empty line → spacing paragraph
        return `<w:p><w:pPr><w:spacing w:before="40" w:after="40"/></w:pPr></w:p>`;
      }
      // Detect if this line is a status/checkbox line (short, structured)
      const isStatusLine = /^[☐☑✓✗□■✔●○]/.test(trimmed.trim()) ||
                           /\b(compliant|yes|no|n\/a)\b.*[☐☑]/i.test(trimmed);
      const fontSize = isStatusLine ? '20' : '20';
      const isBold   = /^(compliance status|response|status|comments?|answer|remarks?)\s*[:：]/i.test(trimmed.trim());

      // XML-escape the text
      const esc = trimmed
        .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
        .replace(/"/g,'&quot;');

      const rPr = `<w:rPr>${isBold ? '<w:b/>' : ''}<w:sz w:val="${fontSize}"/><w:szCs w:val="${fontSize}"/></w:rPr>`;
      return `<w:p><w:pPr><w:spacing w:before="40" w:after="40"/></w:pPr>` +
             `<w:r>${rPr}<w:t xml:space="preserve">${esc}</w:t></w:r></w:p>`;
    }).join('');

    const escSrc = sourceText
      .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
      .replace(/"/g,'&quot;');

    const sourceNote =
      `<w:p><w:pPr><w:spacing w:before="40" w:after="0"/></w:pPr>` +
      `<w:r><w:rPr><w:i/><w:sz w:val="16"/><w:szCs w:val="16"/><w:color w:val="888888"/></w:rPr>` +
      `<w:t xml:space="preserve">Source: ${escSrc}</w:t></w:r></w:p>`;

    const newCell = `<w:tc>${propsM ? propsM[0] : ''}${paragraphs}${sourceNote}</w:tc>`;

    // Splice the new cell in — no regex, just string slicing
    result = result.substring(0, cellStart) + newCell + result.substring(cellEnd);
    filled++;
  }

  return { result, filled };
}

// AI: Enhance a single response — used when historical text is found but needs improving
async function enhanceResponse(client, reqId, reqTitle, reqDesc, historicalText, fileName, tone, sentenceCount) {
  const prompt = `You are an expert RFP response writer. A previous vendor response for this requirement has been found in the document "${fileName}". Your job is to ENHANCE it — keep all the original substance and intent, but improve clarity, add technical depth, strengthen compliance language, and make it more compelling. Do NOT replace it with generic content.

REQUIREMENT: ${reqId} — ${reqTitle}
DESCRIPTION: ${reqDesc}

ORIGINAL RESPONSE FROM "${fileName}" (MUST be used as the primary basis):
${historicalText}

Return ONLY the enhanced response text (${sentenceCount} sentences). No JSON, no labels, no source attribution — just the improved response.`;

  const msg = await client.messages.create({
    model: 'claude-sonnet-4-20250514',
    max_tokens: 600,
    messages: [{ role: 'user', content: prompt }]
  });
  return msg.content.map(b => b.text || '').join('').trim();
}

// ── Template detection: identify structured input cells ───────────────────────
function detectTemplate(text) {
  if (!text) return null;
  const t = text;

  // Checkbox-style selectors
  const hasCheckbox     = /[☐☑✓✗□■]/.test(t) || /\[\s*\]/.test(t) || /\(\s*\)/.test(t);

  // Explicit vendor tags
  const hasVendorTag    = /\[vendor\s*(to complete|response|answer|fill|input)\]/i.test(t);

  // Compliance status with checkboxes
  const hasStatusField  = /\b(compliant|non.compliant|partially|status|yes|no|n\/a)\b/i.test(t) && hasCheckbox;

  // Named response/comment/answer fields
  const hasResponseTag  = /^(response|comments?|answer|justification)\s*[:：]/im.test(t);

  // Labelled section fields (e.g. "SOLUTION DESCRIPTION:", "EVIDENCE / APPENDIX REF:")
  const hasSectionLabel = /^[A-Z][A-Z\s\/&]{3,40}:\s*$/m.test(t) ||
                          /^(solution description|evidence|appendix ref|compliance status|technical approach|implementation|pricing|references?)\s*[:：]/im.test(t);

  // Dropdown placeholders: [Select from dropdown], [Select ▼], [Choose one]
  const hasDropdown     = /\[select\b[^\]]{0,40}\]/i.test(t) || /\[choose\b[^\]]{0,30}\]/i.test(t) ||
                          /\bfrom dropdown\b/i.test(t) || /▼/.test(t);

  // Bracket placeholders: [Describe how...], [Enter your...], [Provide...], [Reference any...]
  const hasPlaceholder  = /\[(?:describe|enter|provide|reference|specify|state|list|explain|include|attach|insert)[^\]]{5,120}\]/i.test(t);

  // Colon-field placeholders: FIELD: [placeholder] or FIELD: ___
  const hasColonField   = /:\s*\[[^\]]{5,}\]/.test(t) || /:\s*_{3,}/.test(t);

  const isTemplate = hasCheckbox || hasVendorTag || hasStatusField || hasResponseTag ||
                     hasSectionLabel || hasDropdown || hasPlaceholder || hasColonField;

  if (!isTemplate) return null;

  return {
    isTemplate: true,
    hasCheckbox, hasVendorTag, hasStatusField, hasResponseTag,
    hasSectionLabel, hasDropdown, hasPlaceholder, hasColonField,
    raw: t
  };
}

// ── AI: Fill a structured template cell intelligently ─────────────────────────
async function fillTemplateResponse(client, reqId, reqTitle, reqDesc, templateText, vendorProfile, tone, sentenceCount, libContext) {
  const tmplInfo     = detectTemplate(templateText) || {};
  const isAdnocStyle = /compliance status/i.test(templateText) && /solution description/i.test(templateText);
  const hasEvidence  = /evidence|appendix ref/i.test(templateText);

  const prompt = `You are an expert vendor completing an RFP/RFI response in an Excel or Word cell.
The cell has a STRUCTURED TEMPLATE with labelled sections. Fill EVERY section — keep ALL labels intact.

FILLING RULES:
- "[Select from dropdown ▼]" or "[Select...]" → replace the ENTIRE bracket with the value (e.g. COMPLIANT). No brackets in output.
- "[Describe how...]", "[Reference any...]", "[Enter your...]", "[Specify...]" → replace the ENTIRE bracket with real content.
- COMPLIANCE STATUS → choose: COMPLIANT | PARTIALLY COMPLIANT | NON-COMPLIANT (default COMPLIANT if fully achievable).
- SOLUTION DESCRIPTION → write ${sentenceCount} professional sentences. Name specific Azure services, tools, and your methodology.${isAdnocStyle ? '\n- SOLUTION DESCRIPTION must reference: the exact Azure service(s) needed, your implementation approach, and how acceptance criteria are met.' : ''}
${hasEvidence ? '- EVIDENCE / APPENDIX REF → list relevant certifications (e.g. ISO 27001, SOC 2 Type II), Azure documentation, and appendix labels (e.g. Appendix A).\n' : ''}- Keep SECTION LABELS (e.g. "COMPLIANCE STATUS:", "SOLUTION DESCRIPTION:") exactly as-is on their own line.
- Keep blank lines between sections as in the template.
- Plain text only — no markdown, no asterisks, no bullet symbols unless already in the template.
- Do NOT add new sections. Do NOT include preamble or explanation outside the template structure.

${vendorProfile ? 'VENDOR PROFILE: ' + vendorProfile + '\n' : ''}${libContext ? 'LIBRARY REFERENCE:\n' + libContext + '\n\n' : ''}REQUIREMENT: ${reqTitle}
${reqDesc ? 'ACCEPTANCE CRITERIA: ' + reqDesc + '\n' : ''}
TEMPLATE:
---
${templateText}
---

Return ONLY the completed template. Preserve all labels and line breaks exactly.`;

  const msg = await client.messages.create({
    model: 'claude-sonnet-4-20250514',
    max_tokens: 1200,
    messages: [{ role: 'user', content: prompt }]
  });
  return msg.content.map(b => b.text || '').join('').trim();
}

// AI: Write a fresh response from scratch using best practices
async function writeNewResponse(client, reqId, reqTitle, reqDesc, vendorProfile, tone, sentenceCount, libContext) {
  const prompt = `You are an expert RFP response writer.
${vendorProfile ? 'VENDOR: ' + vendorProfile + '\n' : ''}${libContext ? 'LIBRARY CONTEXT:\n' + libContext + '\n\n' : ''}Write a professional vendor response for this requirement. Confirm compliance and explain specifically HOW it will be met using Azure services and tools.

REQUIREMENT: ${reqId} — ${reqTitle}
DESCRIPTION: ${reqDesc}
TONE: ${tone || 'Formal & Professional'} | LENGTH: ${sentenceCount} sentences

Return ONLY the response text. No JSON, no labels, no preamble.`;

  const msg = await client.messages.create({
    model: 'claude-sonnet-4-20250514',
    max_tokens: 600,
    messages: [{ role: 'user', content: prompt }]
  });
  return msg.content.map(b => b.text || '').join('').trim();
}

app.post('/api/fill-docx', auth, upload.fields([
  { name: 'rfpDocx',    maxCount: 1 },
  { name: 'histFiles',  maxCount: 5 }
]), async (req, res) => {
  const rfpFile = req.files && req.files['rfpDocx'] && req.files['rfpDocx'][0];
  if (!rfpFile) return res.status(400).json({ error: 'No RFP .docx uploaded' });

  const user = req.user;
  const _apiKey = req.effectiveApiKey; if (!_apiKey) return res.status(400).json({ error: "No API key set. Contact your administrator to add one in Settings." });

  const library = db.getLibrary(req.user.id);
  const { tone, length, instructions } = req.body;
  const sentenceCount = length === 'Brief (2-3 sentences)' ? '2-3'
                      : length === 'Detailed (5-7 sentences)' ? '5-7' : '3-5';

  try {
    // ── Step A: Extract ALL rows with responses from every uploaded historical doc ──
    const allHistoricalRows = []; // flat list across all uploaded files
    const histFilesUsed     = [];

    if (req.files && req.files['histFiles']) {
      for (const hf of req.files['histFiles']) {
        try {
          const hz  = new AdmZip(hf.buffer);
          const he  = hz.getEntry('word/document.xml');
          if (!he) continue;
          const xml     = he.getData().toString('utf8');
          const extracted = extractHistoricalRows(xml, hf.originalname);
          if (extracted.length > 0) {
            histFilesUsed.push({ name: hf.originalname, matchCount: 0, reqIds: [] });
            allHistoricalRows.push(...extracted);
          }
        } catch(e) { /* skip unreadable files */ }
      }
    }

    // ── Step B: Library context (for requirements with no historical match) ──
    const libraryItemsUsed = library.slice(0, 3);
    const libContext = libraryItemsUsed.length
      ? libraryItemsUsed.map(l => `[${l.rfp_name}]\n${(l.response||'').substring(0, 400)}`).join('\n\n')
      : '';

    // ── Step C: Parse the new RFP docx ──
    const zip      = new AdmZip(rfpFile.buffer);
    const docEntry = zip.getEntry('word/document.xml');
    if (!docEntry) return res.status(400).json({ error: 'Invalid .docx — document.xml not found' });
    const docXml   = docEntry.getData().toString('utf8');

    const { rows, markedXml } = injectPlaceholders(docXml);
    if (!rows.length) return res.status(400).json({ error: 'No requirement rows found in the document. The file must contain a table with at least 2 columns — one for the requirement text and one for the vendor response. Make sure the document has a table (not just plain text paragraphs).' });

    const vendorProfile = [
      user.org_name ? `Company: ${user.org_name}` : '',
      user.org_bio  ? user.org_bio.substring(0, 300) : '',
      instructions  ? `Special instructions: ${instructions}` : ''
    ].filter(Boolean).join(' | ');

    const client = new Anthropic({ apiKey: req.effectiveApiKey });

    // ── Step D: Semantic matching — find best historical row for each new requirement ──
    // First try exact ID match (fast), then semantic match for remainder
    const semanticMatchMap = {}; // { newReqId -> historicalRow }

    if (allHistoricalRows.length > 0) {
      // Pass 1: exact ID match
      const unmatchedRows = [];
      for (const row of rows) {
        const exactMatch = allHistoricalRows.find(h =>
          h.reqId && h.reqId.trim().toUpperCase() === row.reqId.trim().toUpperCase()
        );
        if (exactMatch) {
          semanticMatchMap[row.reqId] = { ...exactMatch, matchType: 'exact-id' };
        } else {
          unmatchedRows.push(row);
        }
      }

      // Pass 2: semantic match for rows that didn't match by ID
      if (unmatchedRows.length > 0) {
        const semanticMatches = await semanticMatch(client, unmatchedRows, allHistoricalRows);
        for (const [newReqId, histRow] of Object.entries(semanticMatches)) {
          semanticMatchMap[newReqId] = { ...histRow, matchType: 'semantic' };
        }
      }

      // Update histFilesUsed with actual matched counts
      for (const [newReqId, histRow] of Object.entries(semanticMatchMap)) {
        const fileEntry = histFilesUsed.find(f => f.name === histRow.fileName);
        if (fileEntry && !fileEntry.reqIds.includes(newReqId)) {
          fileEntry.reqIds.push(newReqId);
          fileEntry.matchCount++;
        }
      }
    }

    // ── Step E: For each requirement — enhance matched historical OR write new ──
    const responseMap = {};
    const PARALLEL    = 4;

    for (let i = 0; i < rows.length; i += PARALLEL) {
      const batch = rows.slice(i, i + PARALLEL);
      const results = await Promise.all(batch.map(async (row) => {
        const hist     = semanticMatchMap[row.reqId];
        const tmpl     = detectTemplate(row.existing);
        const hasRealExisting = row.existing && row.existing.length > 20 &&
                                !row.existing.toLowerCase().includes('[vendor') &&
                                !row.existing.toLowerCase().includes('source:') &&
                                !tmpl;

        if (tmpl) {
          // PRIORITY 1 (TEMPLATE): Structured cell — fill in-place preserving format
          const filledTmpl = await fillTemplateResponse(
            client, row.reqId, row.reqTitle, row.reqDesc,
            tmpl.raw, vendorProfile, tone, sentenceCount, libContext
          );
          const libSuffix = libraryItemsUsed.length ? ' + library' : '';
          return { reqId: row.reqId, response: filledTmpl, source: `AI Template Fill${libSuffix}` };

        } else if (hist) {
          // PRIORITY 2: Historical match — enhance with history
          const matchLabel = hist.matchType === 'exact-id'
            ? `${hist.fileName} (ID match: ${hist.reqId})`
            : `${hist.fileName} (semantic match from: "${hist.reqTitle}")`;
          const enhanced = await enhanceResponse(
            client, row.reqId, row.reqTitle, row.reqDesc,
            hist.response, matchLabel, tone, sentenceCount
          );
          return { reqId: row.reqId, response: enhanced, source: matchLabel };

        } else if (hasRealExisting) {
          // PRIORITY 3: Partial response already in cell — enhance it
          const enhanced = await enhanceResponse(
            client, row.reqId, row.reqTitle, row.reqDesc,
            row.existing, `${rfpFile.originalname} (existing content)`, tone, sentenceCount
          );
          return { reqId: row.reqId, response: enhanced, source: `${rfpFile.originalname} (existing, enhanced)` };

        } else {
          // PRIORITY 4: Write from scratch
          const fresh = await writeNewResponse(
            client, row.reqId, row.reqTitle, row.reqDesc,
            vendorProfile, tone, sentenceCount, libContext
          );
          const libSuffix = libraryItemsUsed.length ? ` + library context` : '';
          return { reqId: row.reqId, response: fresh, source: `Azure Industry Best Practices${libSuffix}` };
        }
      }));

      results.forEach(r => { responseMap[r.reqId] = { response: r.response, source: r.source }; });
    }

    // ── Step E: Write responses into docx ──
    const { result: finalXml, filled } = applyResponses(markedXml, responseMap);
    zip.updateFile('word/document.xml', Buffer.from(finalXml, 'utf8'));
    const outBuf  = zip.toBuffer();
    const safeName = rfpFile.originalname.replace(/[^a-zA-Z0-9._-]/g, '_').replace(/\.docx$/i, '');
    const outName  = safeName + '_AI_Filled_' + Date.now() + '.docx';

    // Build per-source breakdown for UI
    const sourceBreakdown = {};
    for (const [reqId, item] of Object.entries(responseMap)) {
      const src = item.source || 'Azure Industry Best Practices';
      if (!sourceBreakdown[src]) sourceBreakdown[src] = [];
      sourceBreakdown[src].push(reqId);
    }

    const histMatchedTotal = Object.keys(semanticMatchMap).length;
    const histFileSummary  = histFilesUsed
      .filter(f => f.matchCount > 0)
      .map(f => `${f.name} (${f.matchCount} reqs: ${f.reqIds.join(', ')})`)
      .join(' | ');

    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
    res.setHeader('Content-Disposition', `attachment; filename="${outName}"`);
    res.setHeader('X-Reqs-Found',         rows.length.toString());
    res.setHeader('X-Reqs-Filled',        filled.toString());
    res.setHeader('X-Hist-Files',         histFilesUsed.length.toString());
    res.setHeader('X-Hist-Names',         histFilesUsed.map(f => f.name).join(' | '));
    res.setHeader('X-Hist-Matched',       histMatchedTotal.toString());
    res.setHeader('X-Hist-File-Summary',  histFileSummary);
    res.setHeader('X-Lib-Used',           libraryItemsUsed.length.toString());
    res.setHeader('X-Lib-Names',          libraryItemsUsed.map(l => l.rfp_name).join(' | '));
    res.setHeader('X-Existing-Enhanced',  rows.filter(r => r.existing && r.existing.length > 20).length.toString());
    res.setHeader('X-Source-Breakdown',   encodeURIComponent(JSON.stringify(sourceBreakdown)));
    res.setHeader('Access-Control-Expose-Headers',
      'X-Reqs-Found, X-Reqs-Filled, X-Hist-Files, X-Hist-Names, X-Hist-Matched, X-Hist-File-Summary, X-Lib-Used, X-Lib-Names, X-Existing-Enhanced, X-Source-Breakdown'
    );
    res.send(outBuf);

  } catch(err) {
    const msg = err.status === 401 ? 'Invalid API key.'
              : err.status === 400 ? 'Credit balance too low — add credits at console.anthropic.com'
              : err.message || 'Server error';
    res.status(500).json({ error: msg });
  }
});

// ── AI: Fill Excel RFP ────────────────────────────────────────────────────────
app.post('/api/fill-xlsx', auth, upload.single('rfpXlsx'), async (req, res) => {
  const rfpFile = req.file;
  if (!rfpFile) return res.status(400).json({ error: 'No Excel file uploaded' });

  const _apiKey = req.effectiveApiKey;
  if (!_apiKey) return res.status(400).json({ error: 'No API key set. Contact your administrator.' });

  const user = req.user;
  const { tone, length, instructions } = req.body;
  const sentenceCount = length === 'Brief (2-3 sentences)'    ? '2-3'
                      : length === 'Detailed (5-7 sentences)' ? '5-7' : '3-5';

  try {
    // ── Step A: Read workbook preserving all styles and validation ─────────────
    const wb = XLSX.read(rfpFile.buffer, {
      type: 'buffer', cellStyles: true, cellDates: true,
      sheetStubs: true, // include empty cells so we can detect them
    });

    // Use first visible sheet (skip hidden sheets)
    let wsName = wb.SheetNames[0];
    let ws     = wb.Sheets[wsName];

    // ── Step B: Scan ALL cells to extract text (handles merged/shared strings) ─
    function getCellText(ws, r, c) {
      const cell = ws[XLSX.utils.encode_cell({ r, c })];
      if (!cell) return '';
      // .w = formatted text (most reliable for display value)
      // .v = raw value
      // .r = rich text (array of objects with .t)
      let text = '';
      if (cell.w !== undefined) text = String(cell.w);
      else if (cell.v !== undefined) text = String(cell.v);
      if (!text && cell.r) {
        // Rich text: array of run objects
        try {
          text = (Array.isArray(cell.r) ? cell.r : [cell.r])
            .map(run => typeof run === 'object' ? (run.t || '') : String(run || ''))
            .join('');
        } catch(e) {}
      }
      return text.replace(/\r\n/g, '\n').replace(/\r/g, '\n').trim();
    }

    // ── Step C: Detect header row & columns ────────────────────────────────────
    const range  = XLSX.utils.decode_range(ws['!ref'] || 'A1');
    const maxRow = range.e.r;
    const maxCol = range.e.c;

    const VENDOR_RESP_TIERS = [
      // Tier 0: unambiguous vendor response labels
      ['vendor response','vendor responses','your response','proposed response',
       'vendor to complete','vendor answer','company response','complete this column'],
      ['compliance response','response to requirement','your answer','supplier response'],
      ['answer','response'],
      ['comments','remarks','notes'],
    ];
    const REQ_ID_KEYS      = ['req#','req #','req id','reqid','id','#','no.','no','sl.no','s.no','item no','sr.no'];
    const REQUIREMENT_KEYS = ['requirement','requirements','description','description & acceptance',
                               'item description','scope','specification','criteria'];
    const DESCRIPTION_KEYS = ['description & acceptance','acceptance criteria','description and acceptance',
                               'description & criteria'];

    // ── CRITICAL: evaluate each row independently — do NOT let title rows pollute column indices ──
    let headerRow = -1, reqIdCol = -1, requirementCol = -1, descCol = -1, vendorRespCol = -1;

    for (let r = 0; r <= Math.min(9, maxRow); r++) {
      // Collect column assignments FOR THIS ROW ONLY
      let rowReqId = -1, rowReqCol = -1, rowDescCol = -1, rowVendorCol = -1;
      let rowVendorTier = 999;
      let idFound = false, reqFound = false, respFound = false;

      for (let c = 0; c <= maxCol; c++) {
        const val = getCellText(ws, r, c).toLowerCase();
        // Only consider SHORT header-like values (avoid title rows which are long sentences)
        if (!val || val.length < 2) continue;

        if (REQ_ID_KEYS.some(k => val === k || val.startsWith(k + ' '))) {
          rowReqId = c; idFound = true;
        }
        if (DESCRIPTION_KEYS.some(k => val.includes(k))) {
          rowDescCol = c; reqFound = true;
        }
        if (rowDescCol < 0 && REQUIREMENT_KEYS.some(k => val.includes(k))) {
          rowReqCol = c; reqFound = true;
        }
        for (let tier = 0; tier < VENDOR_RESP_TIERS.length; tier++) {
          if (VENDOR_RESP_TIERS[tier].some(k => val === k || val.includes(k))) {
            // REJECT if this row's cell is very long (likely a title/paragraph, not a header)
            const rawVal = getCellText(ws, r, c);
            if (rawVal.length > 80 && (idFound || reqFound)) {
              // Long cell in a row that already has short header cells — likely a content row
              break;
            }
            if (tier < rowVendorTier) {
              rowVendorCol = c; rowVendorTier = tier; respFound = true;
            }
            break;
          }
        }
      }

      // Count how many distinct cells have SHORT values in this row (title/merged rows have only 1)
      let nonEmptyCells = 0;
      for (let c = 0; c <= maxCol; c++) {
        const v = getCellText(ws, r, c);
        if (v && v.length >= 2 && v.length <= 120) nonEmptyCells++;
      }

      // Commit this row as the header only if:
      // 1. It has BOTH a requirement column AND a vendor response column
      // 2. It has multiple distinct non-empty cells (not a merged title row)
      const score = (idFound?1:0) + (reqFound?1:0) + (respFound?1:0);
      if (score >= 2 && rowVendorCol >= 0 && nonEmptyCells >= 3) {
        headerRow      = r;
        reqIdCol       = rowReqId;
        requirementCol = rowDescCol >= 0 ? rowDescCol : rowReqCol;
        descCol        = rowDescCol;
        vendorRespCol  = rowVendorCol;
        break;
      }
    }

    if (headerRow      === -1) headerRow      = 0;
    if (requirementCol === -1) requirementCol = Math.max(0, (vendorRespCol >= 0 ? vendorRespCol : maxCol) - 1);
    if (vendorRespCol  === -1) {
      vendorRespCol = maxCol + 1;
      ws[XLSX.utils.encode_cell({ r: headerRow, c: vendorRespCol })] = { v: 'Vendor Response', t: 's' };
      const nr = XLSX.utils.decode_range(ws['!ref'] || 'A1');
      nr.e.c = Math.max(nr.e.c, vendorRespCol);
      ws['!ref'] = XLSX.utils.encode_range(nr);
    }

    // ── Step D: Collect rows to fill ───────────────────────────────────────────
    // Also find a secondary "Requirement" col for the row title
    let reqTitleCol = requirementCol;
    for (let c = 0; c <= maxCol; c++) {
      if (c === requirementCol || c === vendorRespCol) continue;
      const hdrVal = getCellText(ws, headerRow, c).toLowerCase();
      if (hdrVal === 'requirement' || hdrVal === 'requirements') { reqTitleCol = c; break; }
    }

    const rows = [];
    for (let r = headerRow + 1; r <= maxRow; r++) {
      const reqText  = getCellText(ws, r, requirementCol);
      const reqTitle = reqTitleCol !== requirementCol ? getCellText(ws, r, reqTitleCol) : '';
      if (!reqText && !reqTitle) continue; // completely empty row

      const idCell   = reqIdCol >= 0 ? getCellText(ws, r, reqIdCol) : `ROW-${r}`;
      const existing = getCellText(ws, r, vendorRespCol);

      // Skip only if genuinely filled (no template markers)
      const cellTmpl = detectTemplate(existing);
      if (!cellTmpl && existing.length > 30 &&
          !/\[select|\[describe|\[provide|\[enter|\[reference|\[specify|\bvendor\b/i.test(existing)) continue;

      rows.push({
        r,
        reqId:   String(idCell || `ROW-${r}`),
        reqText: reqText || reqTitle,
        reqDesc: reqTitle !== reqText ? reqTitle : '',
        existing,
        tmpl:    cellTmpl,
      });
    }

    if (!rows.length) {
      return res.status(400).json({ error: 'No unfilled requirement rows found in the sheet "' + wsName + '". Ensure the Vendor Response column has template placeholders or is empty.' });
    }

    // ── Step E: Generate AI responses ─────────────────────────────────────────
    const client       = new Anthropic({ apiKey: _apiKey });
    const library      = db.getLibrary(req.user.id);
    const libContext   = library.slice(0, 3).map(l => `[${l.rfp_name}]\n${(l.response||'').substring(0,400)}`).join('\n\n');
    const vendorProfile = [
      user.org_name ? `Company: ${user.org_name}` : '',
      user.org_bio  ? user.org_bio.substring(0, 300) : '',
      instructions  ? `Special instructions: ${instructions}` : ''
    ].filter(Boolean).join(' | ');

    const PARALLEL = 4;
    let filled = 0;

    for (let i = 0; i < rows.length; i += PARALLEL) {
      const batch   = rows.slice(i, i + PARALLEL);
      const results = await Promise.all(batch.map(async (row) => {
        let response;
        if (row.tmpl) {
          response = await fillTemplateResponse(
            client, row.reqId, row.reqText, row.reqDesc,
            row.tmpl.raw, vendorProfile, tone, sentenceCount, libContext
          );
        } else {
          response = await writeNewResponse(
            client, row.reqId, row.reqText, row.reqDesc,
            vendorProfile, tone, sentenceCount, libContext
          );
        }
        return { row, response };
      }));

      // Write responses back into the correct cell
      for (const { row, response } of results) {
        const addr = XLSX.utils.encode_cell({ r: row.r, c: vendorRespCol });
        // Preserve the original cell object but update value
        const origCell = ws[addr] || {};
        ws[addr] = {
          ...origCell,        // keep existing styles, comments, validation refs
          v: response,
          w: response,        // formatted text = same as value
          t: 's',             // string type
          s: {                // override style: wrap + green tint
            ...(origCell.s || {}),
            alignment: { wrapText: true, vertical: 'top' },
            fill:      { patternType: 'solid', fgColor: { rgb: 'E8F5E9' } },
            font:      { sz: 10, ...(origCell.s && origCell.s.font ? origCell.s.font : {}) },
          },
        };
        filled++;
      }
    }

    // ── Step F: Column widths & row heights ────────────────────────────────────
    if (!ws['!cols']) ws['!cols'] = [];
    for (let c = 0; c <= Math.max(maxCol, vendorRespCol); c++) {
      ws['!cols'][c] = ws['!cols'][c] || {};
      if (c === vendorRespCol)   ws['!cols'][c].wch = 65;
      else if (c === requirementCol) ws['!cols'][c].wch = 50;
      else ws['!cols'][c].wch = ws['!cols'][c].wch || 18;
    }
    if (!ws['!rows']) ws['!rows'] = [];
    for (let r = headerRow + 1; r <= maxRow; r++) {
      ws['!rows'][r] = { ...(ws['!rows'][r] || {}), hpt: 80 };
    }

    // ── Step G: Write out ──────────────────────────────────────────────────────
    const outBuf  = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx', cellStyles: true });
    const safeName = rfpFile.originalname.replace(/[^a-zA-Z0-9._-]/g, '_').replace(/\.(xlsx?|xls)$/i, '');
    const outName  = safeName + '_AI_Filled.xlsx';

    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="${outName}"`);
    res.setHeader('X-Reqs-Found',   rows.length.toString());
    res.setHeader('X-Reqs-Filled',  filled.toString());
    res.setHeader('X-Sheet-Name',   wsName);
    res.setHeader('X-Vendor-Col',   XLSX.utils.encode_col(vendorRespCol));
    res.setHeader('X-Header-Row',   (headerRow + 1).toString());
    res.setHeader('Access-Control-Expose-Headers', 'X-Reqs-Found, X-Reqs-Filled, X-Sheet-Name, X-Vendor-Col, X-Header-Row');
    res.send(outBuf);

  } catch(err) {
    const msg = err.status === 401 ? 'Invalid API key.'
              : err.status === 400 ? 'API credit balance too low.'
              : err.message || 'Server error';
    res.status(500).json({ error: msg });
  }
});

// ── AI: Fill PDF RFP ──────────────────────────────────────────────────────────
// PDFs can't be edited in-place, so we:
//   1. Extract all text from the PDF
//   2. Parse requirement rows from the text (table-style or numbered list)
//   3. Generate AI responses for each row
//   4. Return a filled Word (.docx) document mirroring the PDF structure
app.post('/api/fill-pdf', auth, upload.single('rfpPdf'), async (req, res) => {
  const rfpFile = req.file;
  if (!rfpFile) return res.status(400).json({ error: 'No PDF file uploaded' });

  const _apiKey = req.effectiveApiKey;
  if (!_apiKey) return res.status(400).json({ error: 'No API key set. Contact your administrator.' });

  const user = req.user;
  const { tone, length, instructions } = req.body;
  const sentenceCount = length === 'Brief (2-3 sentences)'    ? '2-3'
                      : length === 'Detailed (5-7 sentences)' ? '5-7' : '3-5';
  const library = db.getLibrary(req.user.id);
  const libContext = library.slice(0, 3).map(l => `[${l.rfp_name}]\n${(l.response||'').substring(0,400)}`).join('\n\n');
  const vendorProfile = [
    user.org_name ? `Company: ${user.org_name}` : '',
    user.org_bio  ? user.org_bio.substring(0, 300) : '',
    instructions  ? `Special instructions: ${instructions}` : ''
  ].filter(Boolean).join(' | ');

  try {
    // ── Step A: Extract text from PDF ────────────────────────────────────────
    const pdfData = await pdfParse(rfpFile.buffer);
    const fullText = pdfData.text || '';
    if (!fullText.trim()) {
      return res.status(400).json({ error: 'Could not extract text from this PDF. It may be a scanned image — please use a text-based PDF.' });
    }

    // ── Step B: Parse requirement rows from extracted text ────────────────────
    // Detect: numbered rows (1. / 1.1 / REQ-001), table rows, bullet items
    const VENDOR_MARKERS = /\[vendor\s*(to complete|response|fill|input)\]|\bvendor response\b|\bresponse\s*:\s*$/im;
    const rows = [];
    const lines = fullText.split(/\n/);
    const seenIds = {};

    // Strategy 1: Tab/pipe-separated table rows
    const tableRows = lines.filter(l => (l.match(/\t/g)||[]).length >= 2 || (l.match(/\|/g)||[]).length >= 2);
    if (tableRows.length >= 3) {
      // Find header row
      let hdrIdx = -1, vendorCol = -1, reqCol = -1;
      for (let i = 0; i < Math.min(tableRows.length, 5); i++) {
        const cols = tableRows[i].split(/\t|\|/).map(c => c.trim());
        for (let c = 0; c < cols.length; c++) {
          const v = cols[c].toLowerCase();
          if (['vendor response','response','your response','answer'].some(k => v.includes(k))) { vendorCol = c; }
          if (['requirement','description','item'].some(k => v.includes(k))) { reqCol = c; }
        }
        if (vendorCol >= 0 || reqCol >= 0) { hdrIdx = i; break; }
      }
      if (hdrIdx >= 0) {
        if (reqCol < 0) reqCol = vendorCol > 0 ? 0 : 1;
        if (vendorCol < 0) vendorCol = reqCol + 1;
        for (let i = hdrIdx + 1; i < tableRows.length; i++) {
          const cols = tableRows[i].split(/\t|\|/).map(c => c.trim());
          const reqText = cols[reqCol] || '';
          if (reqText.length < 4) continue;
          const existing = cols[vendorCol] || '';
          const rawId = `ROW${i}`;
          rows.push({ reqId: rawId, reqTitle: reqText, reqDesc: '', existing, isTemplate: !!detectTemplate(existing) });
        }
      }
    }

    // Strategy 2: Numbered / structured paragraphs (if table parsing got < 3 rows)
    if (rows.length < 3) {
      rows.length = 0;
      const REQ_LINE = /^(\d+[\.\)]\d*[\.\)]?\d*|REQ[-\s]?\d+|[A-Z]{1,3}[-]\d+|[•\-*]\s{1,3})\s+(.{8,})/;
      let currentId = null, currentText = '', currentTemplate = '';
      let reqCounter = 0;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        const m = line.match(REQ_LINE);
        if (m) {
          // Save previous
          if (currentId && currentText.length > 4) {
            const rawId = currentId.replace(/[^a-zA-Z0-9_\-]/g,'').substring(0,20) || `ROW${reqCounter}`;
            rows.push({ reqId: rawId, reqTitle: currentText.trim(), reqDesc: '', existing: currentTemplate, isTemplate: !!detectTemplate(currentTemplate) });
          }
          reqCounter++;
          currentId   = m[1].replace(/\s/g,'');
          currentText = m[2];
          currentTemplate = '';
          // Check next lines for vendor response template
          for (let j = i+1; j < Math.min(i+6, lines.length); j++) {
            const nextLine = lines[j].trim();
            if (VENDOR_MARKERS.test(nextLine) || detectTemplate(nextLine)) {
              currentTemplate = lines.slice(j, Math.min(j+4, lines.length)).join('\n').trim();
              break;
            }
          }
        } else if (currentId && line.length > 2) {
          currentText += ' ' + line;
        }
      }
      // Save last
      if (currentId && currentText.length > 4) {
        const rawId = currentId.replace(/[^a-zA-Z0-9_\-]/g,'').substring(0,20) || `ROW${reqCounter}`;
        rows.push({ reqId: rawId, reqTitle: currentText.trim(), reqDesc: '', existing: currentTemplate, isTemplate: !!detectTemplate(currentTemplate) });
      }
    }

    if (!rows.length) {
      return res.status(400).json({ error: 'No requirement rows found in the PDF. Ensure the PDF has numbered requirements or a table with requirement descriptions.' });
    }

    // ── Step C: Generate AI responses ────────────────────────────────────────
    const client = new Anthropic({ apiKey: _apiKey });
    const PARALLEL = 4;
    const responseMap = {};

    for (let i = 0; i < rows.length; i += PARALLEL) {
      const batch = rows.slice(i, i + PARALLEL);
      const results = await Promise.all(batch.map(async (row) => {
        let response;
        if (row.isTemplate && row.existing) {
          response = await fillTemplateResponse(client, row.reqId, row.reqTitle, row.reqDesc, row.existing, vendorProfile, tone, sentenceCount, libContext);
        } else {
          response = await writeNewResponse(client, row.reqId, row.reqTitle, row.reqDesc, vendorProfile, tone, sentenceCount, libContext);
        }
        return { reqId: row.reqId, response };
      }));
      results.forEach(r => { responseMap[r.reqId] = r.response; });
    }

    // ── Step D: Build a Word document with the responses ─────────────────────
    // Table: Req# | Requirement | Vendor Response
    function xmlEsc(s) {
      return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }
    function makeCell(text, width, bold) {
      const esc = xmlEsc(text);
      const paras = esc.split(/\n/).map(l =>
        `<w:p><w:r><w:rPr>${bold?'<w:b/>':''}<w:sz w:val="20"/></w:rPr><w:t xml:space="preserve">${l||' '}</w:t></w:r></w:p>`
      ).join('');
      return `<w:tc><w:tcPr><w:tcW w:w="${width}" w:type="dxa"/></w:tcPr>${paras}</w:tc>`;
    }

    const hdrRow = `<w:tr>
      ${makeCell('Req #', 800, true)}
      ${makeCell('Requirement / Description', 4200, true)}
      ${makeCell('Vendor Response', 4000, true)}
    </w:tr>`;

    const dataRows = rows.map(row => `<w:tr>
      ${makeCell(row.reqId, 800, false)}
      ${makeCell(row.reqTitle + (row.reqDesc ? '\n' + row.reqDesc : ''), 4200, false)}
      ${makeCell(responseMap[row.reqId] || '', 4000, false)}
    </w:tr>`).join('');

    const tableXml = `<w:tbl>
      <w:tblPr>
        <w:tblStyle w:val="TableGrid"/>
        <w:tblW w:w="9000" w:type="dxa"/>
        <w:tblBorders>
          <w:top w:val="single" w:sz="4" w:color="272160"/>
          <w:left w:val="single" w:sz="4" w:color="272160"/>
          <w:bottom w:val="single" w:sz="4" w:color="272160"/>
          <w:right w:val="single" w:sz="4" w:color="272160"/>
          <w:insideH w:val="single" w:sz="4" w:color="CCCCCC"/>
          <w:insideV w:val="single" w:sz="4" w:color="CCCCCC"/>
        </w:tblBorders>
      </w:tblPr>
      <w:tblGrid>
        <w:gridCol w:w="800"/>
        <w:gridCol w:w="4200"/>
        <w:gridCol w:w="4000"/>
      </w:tblGrid>
      ${hdrRow}${dataRows}
    </w:tbl>`;

    const titlePara = `<w:p><w:pPr><w:spacing w:after="200"/></w:pPr>
      <w:r><w:rPr><w:b/><w:sz w:val="32"/><w:color w:val="272160"/></w:rPr>
        <w:t>RFP Response — ${xmlEsc(rfpFile.originalname.replace(/\.pdf$/i,''))}</w:t>
      </w:r></w:p>
    <w:p><w:pPr><w:spacing w:after="80"/></w:pPr>
      <w:r><w:rPr><w:sz w:val="18"/><w:color w:val="888888"/></w:rPr>
        <w:t>Generated by RFP Agent · ${new Date().toLocaleDateString('en-GB',{day:'2-digit',month:'long',year:'numeric'})}</w:t>
      </w:r></w:p>
    <w:p><w:pPr><w:spacing w:after="120"/></w:pPr></w:p>`;

    const docXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:wpc="http://schemas.microsoft.com/office/word/2010/wordprocessingCanvas"
  xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"
  xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <w:body>
    ${titlePara}
    ${tableXml}
    <w:sectPr>
      <w:pgSz w:w="12240" w:h="15840"/>
      <w:pgMar w:top="720" w:right="720" w:bottom="720" w:left="720"/>
    </w:sectPr>
  </w:body>
</w:document>`;

    // Minimal .docx zip structure
    const docxZip = new AdmZip();
    docxZip.addFile('word/document.xml', Buffer.from(docXml, 'utf8'));
    docxZip.addFile('word/_rels/document.xml.rels', Buffer.from(
      `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
</Relationships>`, 'utf8'));
    docxZip.addFile('[Content_Types].xml', Buffer.from(
      `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>`, 'utf8'));
    docxZip.addFile('_rels/.rels', Buffer.from(
      `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`, 'utf8'));

    const outBuf  = docxZip.toBuffer();
    const safeName = rfpFile.originalname.replace(/[^a-zA-Z0-9._-]/g,'_').replace(/\.pdf$/i,'');
    const outName  = safeName + '_AI_Filled.docx';
    const filled   = Object.keys(responseMap).length;

    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
    res.setHeader('Content-Disposition', `attachment; filename="${outName}"`);
    res.setHeader('X-Reqs-Found',  rows.length.toString());
    res.setHeader('X-Reqs-Filled', filled.toString());
    res.setHeader('Access-Control-Expose-Headers', 'X-Reqs-Found, X-Reqs-Filled');
    res.send(outBuf);

  } catch(err) {
    const msg = err.status === 401 ? 'Invalid API key.'
              : err.status === 400 ? 'API credit balance too low.'
              : err.message || 'Server error';
    res.status(500).json({ error: msg });
  }
});

// ── AI: Effort Estimation ─────────────────────────────────────────────────────
app.post('/api/estimate-effort', auth, upload.fields([
  { name: 'histFiles', maxCount: 5 }
]), async (req, res) => {
  const user = req.user;
  const _apiKey = req.effectiveApiKey; if (!_apiKey) return res.status(400).json({ error: "No API key set. Contact your administrator to add one in Settings." });

  const { deploymentType, durationMonths, projectScope, vatpIncluded, vaptAmount, ipCost, azureCostPerMonth } = req.body;

  // Parse optional additional cost items
  let extraCosts = [];
  if (req.body.extraCostsJson) {
    try {
      const parsed = JSON.parse(req.body.extraCostsJson);
      extraCosts = parsed.filter(c => c.label && typeof c.amount === 'number').slice(0, 20);
    } catch(e) {}
  }
  const extraCostsTotal = extraCosts.reduce((s, c) => s + (parseFloat(c.amount) || 0), 0);

  // Load saved rate card (falls back to defaults if not set)
  let savedRateCard = [];
  try { savedRateCard = JSON.parse(user.rate_card || '[]'); } catch(e) {}

  let savedAzureServices = [];
  try { savedAzureServices = JSON.parse(user.azure_services || '[]'); } catch(e) {}

  // Build rate map for prompt  { roleName -> dailyRateAED }
  const rateMap = {};
  savedRateCard.forEach(r => { if (r.role && r.rate) rateMap[r.role] = r.rate; });

  // Extract effort/staffing context from historical docs (docx + all other formats)
  let histContext = '';
  if (req.files && req.files['histFiles']) {
    for (const hf of req.files['histFiles']) {
      try {
        const hz  = new AdmZip(hf.buffer);
        const he  = hz.getEntry('word/document.xml');
        if (!he) continue;
        const text = he.getData().toString('utf8').replace(/<[^>]+>/g,' ').replace(/\s+/g,' ');
        const effortSection = text.match(/(?:effort|staffing|team|resource|days?|months?|FTE|role)[^.]{0,500}/gi) || [];
        histContext += `[${hf.originalname}]\n${effortSection.slice(0,20).join('. ')}\n\n`;
      } catch(e) {}
    }
  }
  // Also accept pre-extracted text from PDF/Excel/TXT sent by browser
  if (req.body && req.body.histTextsJson) {
    try {
      const histTexts = JSON.parse(req.body.histTextsJson);
      for (const ht of histTexts) {
        const keywords = /(?:effort|staffing|team|resource|days?|months?|FTE|role|cost|budget|AED|USD|rate)/gi;
        const effortSection = (ht.text||'').match(new RegExp('.{0,30}(?:effort|staffing|team|resource|days?|months?|FTE|role|cost|budget|rate).{0,300}','gi')) || [];
        if (effortSection.length > 0) {
          histContext += `[${ht.name}]\n${effortSection.slice(0,20).join('. ')}\n\n`;
        } else {
          histContext += `[${ht.name}]\n${(ht.text||'').substring(0,1500)}\n\n`;
        }
      }
    } catch(e) {}
  }

  const months    = parseInt(durationMonths) || 3;
  const monthCols = Array.from({length: months}, (_, i) => `M${i+1}`);

  const roles = [
    'Infrastructure Architect',
    'Security Architect',
    'Senior DevSecOps Engineer',
    'Senior Cloud Infrastructure Engineer',
    'Network Security Engineer',
    'Site Reliability Engineer (SRE)',
    'Senior MLOps Engineer',
    'InfoSec Specialist',
    'Project Manager',
    'QA / Test Engineer'
  ];

  // Build rate card instruction for AI — use stored rates if available
  const rateCardNote = roles.map(r => {
    const rate = rateMap[r];
    return rate ? `${r}: ${rate} AED/day (USE THIS EXACT RATE)` : `${r}: estimate market rate`;
  }).join('\n');

  const prompt = `You are an expert Azure cloud delivery manager estimating effort for a ${deploymentType} engagement.

PROJECT SCOPE: ${projectScope || 'Azure Landing Zone, Hub-and-Spoke Networking, Cybersecurity Controls (Defender, Sentinel), Identity (Entra ID/PIM), Compliance'}
DEPLOYMENT TYPE: ${deploymentType}
DURATION: ${months} months (${monthCols.join(', ')})
${histContext ? 'HISTORICAL STAFFING REFERENCE:\n' + histContext.substring(0, 1500) + '\n' : ''}

RATE CARD (use these daily rates in AED — do not change rates marked with USE THIS EXACT RATE):
${rateCardNote}

Estimate staffing in days per month for each role. Consider:
- Design & Architecture is front-loaded (M1-M2 heavy)
- Implementation peaks in middle months
- Testing in penultimate month
- Handover/support in final month
- ${deploymentType === 'On-Premise Deployment' ? 'On-prem needs more hands-on infra and network roles' : ''}
- ${deploymentType === 'Customer Tenant Deployment' ? 'Customer tenant needs strong governance, identity, compliance focus' : ''}
- ${deploymentType === 'Vendor-Managed Deployment' ? 'Vendor-managed needs SRE, strong DevSecOps and ongoing support roles' : ''}

ROLES TO ESTIMATE (use exactly these names):
${roles.map((r,i) => `${i+1}. ${r}`).join('\n')}

For each role and each month, provide days (0-22 max per month, 0 if not needed).
Use the daily_rate_aed from the RATE CARD above. phase = Design/Implement/Test/Support.

Reply ONLY with valid JSON, no markdown:
{
  "summary": "2-3 sentence summary of the engagement staffing approach",
  "roles": [
    {
      "role": "Infrastructure Architect",
      "phase": "Design & Implement",
      "daily_rate_aed": 3500,
      "months": {"M1": 15, "M2": 10, "M3": 5}
    }
  ]
}`;

  try {
    const client = new Anthropic({ apiKey: req.effectiveApiKey });
    const msg = await client.messages.create({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 2000,
      messages: [{ role: 'user', content: prompt }]
    });
    const raw     = msg.content.map(b => b.text || '').join('').trim();
    const cleaned = raw.replace(/^```[a-z]*\n?/,'').replace(/\n?```$/,'').trim();
    const data    = JSON.parse(cleaned);

    // Override AI rates with stored rates if set
    data.roles.forEach(r => {
      if (!r.months) r.months = {};
      monthCols.forEach(m => { if (r.months[m] === undefined) r.months[m] = 0; });
      const stored = rateMap[r.role];
      if (stored) r.daily_rate_aed = parseFloat(stored);
    });

    const vaptCost  = vatpIncluded === 'true' ? (parseFloat(vaptAmount) || 150000) : 0;
    const ipCostVal = parseFloat(ipCost)            || 0;
    const azureCost = parseFloat(azureCostPerMonth) || 0;

    let totalEffortDays = 0, totalEffortCost = 0;
    data.roles.forEach(r => {
      const days = monthCols.reduce((s, m) => s + (r.months[m] || 0), 0);
      const cost = days * (r.daily_rate_aed || 0);
      r.total_days = days;
      r.total_cost_aed = cost;
      totalEffortDays += days;
      totalEffortCost += cost;
    });

    const totalAzure = azureCost * months;
    const grandTotal = totalEffortCost + vaptCost + ipCostVal + totalAzure + extraCostsTotal;

    // Use saved azure services breakdown if available, otherwise default percentages
    const azureBreakdown = savedAzureServices.length > 0
      ? savedAzureServices
      : null; // null = use frontend defaults

    const estimatePayload = {
      summary: data.summary,
      roles: data.roles,
      monthCols,
      costs: { effort: totalEffortCost, vapt: vaptCost, ip: ipCostVal, azureMonthly: azureCost, azureTotal: totalAzure, extraCostsTotal, grandTotal },
      extraCosts,
      totalDays: totalEffortDays,
      deploymentType,
      months,
      azureBreakdown,
      projectScope: projectScope || '',
      title: `${deploymentType} — ${months}mo`
    };
    // Auto-save to estimations history
    db.addEstimation({ id: uuidv4(), user_id: req.user.id, ...estimatePayload, created_at: new Date().toISOString() });
    res.json({ success: true, ...estimatePayload });
  } catch(err) {
    res.status(500).json({ error: err.message || 'AI estimation failed' });
  }
});


// ═══════════════════════════════════════════════════════════════════════════════
// AZURE BILLING AGENT
// ═══════════════════════════════════════════════════════════════════════════════

const https = require('https');

// ── Azure credential helpers ──────────────────────────────────────────────────
function getAzureCreds(user) {
  return {
    tenantId:     user.az_tenant_id     || '',
    clientId:     user.az_client_id     || '',
    clientSecret: decrypt(user.az_client_secret || ''),
    subscriptions:(user.az_subscriptions|| '').split(',').map(s=>s.trim()).filter(Boolean)
  };
}

async function getAzureToken(tenantId, clientId, clientSecret) {
  return new Promise((resolve, reject) => {
    const body = new URLSearchParams({
      grant_type:    'client_credentials',
      client_id:     clientId,
      client_secret: clientSecret,
      scope:         'https://management.azure.com/.default'
    }).toString();
    const req = https.request({
      hostname: 'login.microsoftonline.com',
      path:     `/${tenantId}/oauth2/v2.0/token`,
      method:   'POST',
      headers:  { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) }
    }, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => {
        try { const j = JSON.parse(d); j.access_token ? resolve(j.access_token) : reject(new Error(j.error_description || 'Auth failed')); }
        catch(e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.write(body); req.end();
  });
}

async function azureGet(token, path) {
  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: 'management.azure.com',
      path,
      method:  'GET',
      headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' }
    }, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => {
        try { resolve(JSON.parse(d)); }
        catch(e) { reject(new Error('Invalid JSON: ' + d.substring(0,200))); }
      });
    });
    req.on('error', reject);
    req.end();
  });
}

async function azurePost(token, path, body) {
  return new Promise((resolve, reject) => {
    const bodyStr = JSON.stringify(body);
    const req = https.request({
      hostname: 'management.azure.com',
      path,
      method:  'POST',
      headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(bodyStr) }
    }, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => {
        try { resolve(JSON.parse(d)); }
        catch(e) { reject(new Error('Invalid JSON: ' + d.substring(0,200))); }
      });
    });
    req.on('error', reject);
    req.write(bodyStr); req.end();
  });
}

// ── Save Azure credentials ────────────────────────────────────────────────────
app.put('/api/azure/credentials', auth, (req, res) => {
  const { az_tenant_id, az_client_id, az_client_secret, az_subscriptions } = req.body;
  db.updateUser(req.user.id, { az_tenant_id:az_tenant_id||'', az_client_id:az_client_id||'', az_client_secret:encrypt(az_client_secret||''), az_subscriptions:az_subscriptions||'' });
  res.json({ success: true });
});

// ── Test Azure connection ─────────────────────────────────────────────────────
app.get('/api/azure/test', auth, async (req, res) => {
  const { tenantId, clientId, clientSecret, subscriptions } = getAzureCreds(req.user);
  if (!tenantId || !clientId || !clientSecret) return res.status(400).json({ error: 'Azure credentials not configured. Go to Settings → Azure Billing.' });
  try {
    const token = await getAzureToken(tenantId, clientId, clientSecret);
    const subList = [];
    for (const subId of subscriptions.slice(0,5)) {
      try {
        const sub = await azureGet(token, `/subscriptions/${subId}?api-version=2020-01-01`);
        subList.push({ id: subId, name: sub.displayName || subId, state: sub.state });
      } catch(e) { subList.push({ id: subId, name: subId, state: 'Error: ' + e.message }); }
    }
    res.json({ success: true, subscriptions: subList, message: 'Connected successfully' });
  } catch(e) { res.status(400).json({ error: 'Connection failed: ' + e.message }); }
});

// ── Get cost by subscription (current + last month) ───────────────────────────
app.get('/api/azure/billing/subscriptions', auth, async (req, res) => {
  const { tenantId, clientId, clientSecret, subscriptions } = getAzureCreds(req.user);
  if (!tenantId || !clientId || !clientSecret) return res.status(400).json({ error: 'Azure credentials not configured' });
  try {
    const token = await getAzureToken(tenantId, clientId, clientSecret);
    const now = new Date();
    const firstThisMonth = new Date(now.getFullYear(), now.getMonth(), 1).toISOString().split('T')[0];
    const today = now.toISOString().split('T')[0];
    const firstLastMonth = new Date(now.getFullYear(), now.getMonth()-1, 1).toISOString().split('T')[0];
    const lastLastMonth  = new Date(now.getFullYear(), now.getMonth(), 0).toISOString().split('T')[0];
    const results = [];
    for (const subId of subscriptions) {
      try {
        const [curr, prev] = await Promise.all([
          azurePost(token, `/subscriptions/${subId}/providers/Microsoft.CostManagement/query?api-version=2023-11-01`, {
            type: 'ActualCost', timeframe: 'Custom',
            timePeriod: { from: firstThisMonth, to: today },
            dataset: { granularity: 'None', aggregation: { totalCost: { name: 'Cost', function: 'Sum' } } }
          }),
          azurePost(token, `/subscriptions/${subId}/providers/Microsoft.CostManagement/query?api-version=2023-11-01`, {
            type: 'ActualCost', timeframe: 'Custom',
            timePeriod: { from: firstLastMonth, to: lastLastMonth },
            dataset: { granularity: 'None', aggregation: { totalCost: { name: 'Cost', function: 'Sum' } } }
          })
        ]);
        const subInfo = await azureGet(token, `/subscriptions/${subId}?api-version=2020-01-01`);
        const currCost = curr.properties?.rows?.[0]?.[0] || 0;
        const prevCost = prev.properties?.rows?.[0]?.[0] || 0;
        const currency = curr.properties?.rows?.[0]?.[1] || 'USD';
        const change   = prevCost > 0 ? ((currCost - prevCost) / prevCost * 100) : 0;
        results.push({ id: subId, name: subInfo.displayName || subId, currentMonth: currCost, lastMonth: prevCost, currency, changePercent: change });
      } catch(e) { results.push({ id: subId, name: subId, error: e.message }); }
    }
    res.json({ success: true, data: results, asOf: today });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Cost by resource group ─────────────────────────────────────────────────────
app.get('/api/azure/billing/resourcegroups/:subId', auth, async (req, res) => {
  const { tenantId, clientId, clientSecret } = getAzureCreds(req.user);
  if (!tenantId || !clientId || !clientSecret) return res.status(400).json({ error: 'Azure credentials not configured' });
  try {
    const token = await getAzureToken(tenantId, clientId, clientSecret);
    const now = new Date();
    const from = new Date(now.getFullYear(), now.getMonth(), 1).toISOString().split('T')[0];
    const to   = now.toISOString().split('T')[0];
    const result = await azurePost(token, `/subscriptions/${req.params.subId}/providers/Microsoft.CostManagement/query?api-version=2023-11-01`, {
      type: 'ActualCost', timeframe: 'Custom',
      timePeriod: { from, to },
      dataset: {
        granularity: 'None',
        aggregation: { totalCost: { name: 'Cost', function: 'Sum' } },
        grouping: [{ type: 'Dimension', name: 'ResourceGroupName' }],
        sorting: [{ direction: 'Descending', name: 'Cost' }]
      }
    });
    const rows = result.properties?.rows || [];
    const cols = result.properties?.columns || [];
    const costIdx = cols.findIndex(c => c.name === 'Cost');
    const rgIdx   = cols.findIndex(c => c.name === 'ResourceGroupName');
    const curIdx  = cols.findIndex(c => c.name === 'Currency');
    const data = rows.slice(0,20).map(r => ({
      resourceGroup: r[rgIdx] || 'Unknown',
      cost:          r[costIdx] || 0,
      currency:      r[curIdx] || 'USD'
    }));
    res.json({ success: true, data, period: `${from} to ${to}` });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Top billed resources ───────────────────────────────────────────────────────
app.get('/api/azure/billing/topresources/:subId', auth, async (req, res) => {
  const { tenantId, clientId, clientSecret } = getAzureCreds(req.user);
  if (!tenantId || !clientId || !clientSecret) return res.status(400).json({ error: 'Azure credentials not configured' });
  try {
    const token = await getAzureToken(tenantId, clientId, clientSecret);
    const now = new Date();
    const from = new Date(now.getFullYear(), now.getMonth(), 1).toISOString().split('T')[0];
    const to   = now.toISOString().split('T')[0];
    const result = await azurePost(token, `/subscriptions/${req.params.subId}/providers/Microsoft.CostManagement/query?api-version=2023-11-01`, {
      type: 'ActualCost', timeframe: 'Custom',
      timePeriod: { from, to },
      dataset: {
        granularity: 'None',
        aggregation: { totalCost: { name: 'Cost', function: 'Sum' } },
        grouping: [
          { type: 'Dimension', name: 'ResourceId' },
          { type: 'Dimension', name: 'ResourceType' },
          { type: 'Dimension', name: 'ResourceGroupName' }
        ],
        sorting: [{ direction: 'Descending', name: 'Cost' }]
      }
    });
    const rows = result.properties?.rows || [];
    const cols = result.properties?.columns || [];
    const costIdx = cols.findIndex(c => c.name === 'Cost');
    const ridIdx  = cols.findIndex(c => c.name === 'ResourceId');
    const rtIdx   = cols.findIndex(c => c.name === 'ResourceType');
    const rgIdx   = cols.findIndex(c => c.name === 'ResourceGroupName');
    const curIdx  = cols.findIndex(c => c.name === 'Currency');
    const data = rows.slice(0,15).map(r => ({
      resourceId:    r[ridIdx] || '',
      resourceName:  (r[ridIdx] || '').split('/').pop() || 'Unknown',
      resourceType:  r[rtIdx] || '',
      resourceGroup: r[rgIdx] || '',
      cost:          r[costIdx] || 0,
      currency:      r[curIdx] || 'USD'
    }));
    res.json({ success: true, data, period: `${from} to ${to}` });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Cost trend (last 6 months) ─────────────────────────────────────────────────
app.get('/api/azure/billing/trend/:subId', auth, async (req, res) => {
  const { tenantId, clientId, clientSecret } = getAzureCreds(req.user);
  if (!tenantId || !clientId || !clientSecret) return res.status(400).json({ error: 'Azure credentials not configured' });
  try {
    const token  = await getAzureToken(tenantId, clientId, clientSecret);
    const months = parseInt(req.query.months) || 6;
    const now    = new Date();
    const from   = new Date(now.getFullYear(), now.getMonth() - months + 1, 1).toISOString().split('T')[0];
    const to     = now.toISOString().split('T')[0];
    const result = await azurePost(token, `/subscriptions/${req.params.subId}/providers/Microsoft.CostManagement/query?api-version=2023-11-01`, {
      type: 'ActualCost', timeframe: 'Custom',
      timePeriod: { from, to },
      dataset: {
        granularity: 'Monthly',
        aggregation: { totalCost: { name: 'Cost', function: 'Sum' } }
      }
    });
    const rows = result.properties?.rows || [];
    const cols = result.properties?.columns || [];
    const costIdx = cols.findIndex(c => c.name === 'Cost');
    const dateIdx = cols.findIndex(c => c.name === 'BillingMonth' || c.name === 'UsageDate');
    const curIdx  = cols.findIndex(c => c.name === 'Currency');
    const data = rows.map(r => ({
      month:    String(r[dateIdx] || '').substring(0,6),
      cost:     r[costIdx] || 0,
      currency: r[curIdx] || 'USD'
    }));
    res.json({ success: true, data });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Idle/unused resource detection ────────────────────────────────────────────
app.get('/api/azure/billing/idle/:subId', auth, async (req, res) => {
  const { tenantId, clientId, clientSecret } = getAzureCreds(req.user);
  if (!tenantId || !clientId || !clientSecret) return res.status(400).json({ error: 'Azure credentials not configured' });
  try {
    const token = await getAzureToken(tenantId, clientId, clientSecret);
    const idle  = [];

    // 1. Unattached managed disks
    try {
      const disks = await azureGet(token, `/subscriptions/${req.params.subId}/providers/Microsoft.Compute/disks?api-version=2023-04-02`);
      (disks.value || []).forEach(d => {
        if (!d.managedBy) {
          idle.push({ type: 'Unattached Disk', name: d.name, resourceGroup: d.id.split('/')[4], sku: d.sku?.name, sizeGB: d.properties?.diskSizeGB, severity: 'high', saving: 'Stop paying for unused disk storage', id: d.id });
        }
      });
    } catch(e) {}

    // 2. Unassociated public IPs
    try {
      const pips = await azureGet(token, `/subscriptions/${req.params.subId}/providers/Microsoft.Network/publicIPAddresses?api-version=2023-06-01`);
      (pips.value || []).forEach(p => {
        if (!p.properties?.ipConfiguration) {
          idle.push({ type: 'Unused Public IP', name: p.name, resourceGroup: p.id.split('/')[4], sku: p.sku?.name, severity: 'medium', saving: '~$3-5/mo per static IP', id: p.id });
        }
      });
    } catch(e) {}

    // 3. Empty / unused NSGs
    try {
      const nsgs = await azureGet(token, `/subscriptions/${req.params.subId}/providers/Microsoft.Network/networkSecurityGroups?api-version=2023-06-01`);
      (nsgs.value || []).forEach(n => {
        const ifaces = (n.properties?.networkInterfaces || []).length;
        const subnets = (n.properties?.subnets || []).length;
        if (ifaces === 0 && subnets === 0) {
          idle.push({ type: 'Unattached NSG', name: n.name, resourceGroup: n.id.split('/')[4], severity: 'low', saving: 'No direct cost but indicates orphaned resources', id: n.id });
        }
      });
    } catch(e) {}

    // 4. Stopped (deallocated) VMs still with disks
    try {
      const vms = await azureGet(token, `/subscriptions/${req.params.subId}/providers/Microsoft.Compute/virtualMachines?api-version=2023-07-01&$expand=instanceView`);
      (vms.value || []).forEach(vm => {
        const statuses = vm.properties?.instanceView?.statuses || [];
        const powerState = statuses.find(s => s.code?.startsWith('PowerState/'));
        if (powerState && (powerState.code === 'PowerState/deallocated' || powerState.code === 'PowerState/stopped')) {
          idle.push({ type: 'Stopped VM', name: vm.name, resourceGroup: vm.id.split('/')[4], size: vm.properties?.hardwareProfile?.vmSize, severity: 'high', saving: 'VM deallocated but OS disk still billed — consider deleting if unused', id: vm.id });
        }
      });
    } catch(e) {}

    // 5. Old snapshots (>90 days)
    try {
      const snaps = await azureGet(token, `/subscriptions/${req.params.subId}/providers/Microsoft.Compute/snapshots?api-version=2023-04-02`);
      const cutoff = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);
      (snaps.value || []).forEach(sn => {
        const created = new Date(sn.properties?.timeCreated);
        if (created < cutoff) {
          const ageDays = Math.floor((Date.now() - created) / 86400000);
          idle.push({ type: 'Old Snapshot', name: sn.name, resourceGroup: sn.id.split('/')[4], sizeGB: sn.properties?.diskSizeGB, ageDays, severity: 'medium', saving: 'Old snapshots accumulate cost — delete if no longer needed', id: sn.id });
        }
      });
    } catch(e) {}

    res.json({ success: true, data: idle, count: idle.length });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── AI recommendations ─────────────────────────────────────────────────────────
app.post('/api/azure/billing/recommend', auth, async (req, res) => {
  const user = req.user;
  const _apiKey = req.effectiveApiKey; if (!_apiKey) return res.status(400).json({ error: "No API key configured. Contact your administrator." });
  const { billingData, idleResources, topResources, trend } = req.body;

  const prompt = `You are an Azure FinOps expert. Analyse this Azure billing data and provide clear, actionable recommendations.

SUBSCRIPTION COSTS (this month vs last month):
${JSON.stringify(billingData || [], null, 1)}

TOP BILLED RESOURCES:
${JSON.stringify(topResources?.slice(0,10) || [], null, 1)}

IDLE/UNUSED RESOURCES DETECTED:
${JSON.stringify(idleResources || [], null, 1)}

COST TREND (last 6 months):
${JSON.stringify(trend || [], null, 1)}

Provide recommendations in this exact JSON format (no markdown, no preamble):
{
  "summary": "2-3 sentence executive summary of the billing situation",
  "totalSavingsOpportunity": 500,
  "recommendations": [
    {
      "priority": "high",
      "category": "Cost Reduction",
      "title": "Delete 3 unattached managed disks",
      "description": "3 managed disks are unattached and costing approximately $45/month with no benefit",
      "estimatedSaving": 45,
      "action": "Go to Azure Portal → Disks → filter by Unattached → Delete",
      "effort": "low"
    }
  ],
  "budgetAlerts": [
    {
      "subscription": "name",
      "trend": "increasing",
      "message": "Cost increased 23% vs last month"
    }
  ]
}`;

  try {
    const client = new Anthropic({ apiKey: req.effectiveApiKey });
    const msg = await client.messages.create({
      model: 'claude-sonnet-4-20250514', max_tokens: 2000,
      messages: [{ role: 'user', content: prompt }]
    });
    const raw     = msg.content.map(b => b.text || '').join('').trim();
    const cleaned = raw.replace(/^```[a-z]*\n?/, '').replace(/\n?```$/, '').trim();
    const data    = JSON.parse(cleaned);
    res.json({ success: true, ...data });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── AI Chat for billing queries ────────────────────────────────────────────────
app.post('/api/azure/billing/chat', auth, async (req, res) => {
  const user = req.user;
  const _apiKey = req.effectiveApiKey; if (!_apiKey) return res.status(400).json({ error: "No API key configured. Contact your administrator." });
  const { message, context } = req.body;
  const prompt = `You are an Azure billing and FinOps assistant. Answer the user's question based on the billing data provided. Be specific with numbers and actionable with advice.

CURRENT BILLING CONTEXT:
${JSON.stringify(context || {}, null, 1)}

USER QUESTION: ${message}

Respond in plain text, be concise and specific. Use numbers from the data when available.`;

  try {
    const client = new Anthropic({ apiKey: req.effectiveApiKey });
    const msg = await client.messages.create({
      model: 'claude-sonnet-4-20250514', max_tokens: 1000,
      messages: [{ role: 'user', content: prompt }]
    });
    res.json({ success: true, response: msg.content.map(b => b.text || '').join('') });
  } catch(e) { res.status(500).json({ error: e.message }); }
});


app.listen(PORT, () => {
  console.log('\n✅  RFP Agent v3.0  →  http://localhost:' + PORT);
  console.log('   Data stored in: ' + DATA_DIR);
  console.log('   Registration: DISABLED (use: node manage.js create-user <email> <password>)');
  const users = (loadDB().users || []);
  if (users.length === 0) {
    console.log('\n⚠️  NO USERS EXIST YET.');
    console.log('   Create your account: node manage.js create-user you@email.com yourpassword\n');
  } else {
    console.log('   Users: ' + users.length + ' account(s) registered\n');
  }
});
