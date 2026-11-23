require('dotenv').config();
const express = require('express'), helmet = require('helmet'), rateLimit = require('express-rate-limit');
const Database = require('better-sqlite3'), crypto = require('crypto'), fs = require('fs'), path = require('path');
const { PORT = 3000, BASE_URL = 'http://localhost:3000', ADMIN_PASSWORD, DB_PATH = './data/clodale.db' } = process.env;
if (!ADMIN_PASSWORD || ADMIN_PASSWORD.length < 10) { console.error('Définissez ADMIN_PASSWORD (10 caractères minimum) dans .env'); process.exit(1); }
const https = BASE_URL.startsWith('https');

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new Database(DB_PATH);
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, nom, prenom, tel, email, naissance, salt, hash, moyen, pay_num, pay_ref, etat TEXT DEFAULT 'attente', created TEXT);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER, admin INTEGER DEFAULT 0, exp INTEGER);
CREATE TABLE IF NOT EXISTS otps(k TEXT PRIMARY KEY, hash TEXT, exp INTEGER, tries INTEGER DEFAULT 0, sent INTEGER);`);

// ---------- utilitaires ----------
const norm = s => String(s || '').trim().toLowerCase();
const digits = s => String(s || '').replace(/\D/g, '');
const sameId = (a, b) => {
  a = String(a || ''); b = String(b || '');
  if (!a || !b) return false;
  if (a.includes('@') || b.includes('@')) return norm(a) === norm(b);
  const x = digits(a), y = digits(b); return x.length >= 8 && x.slice(-8) === y.slice(-8);
};
const intl = n => /^\+[1-9]\d{7,14}$/.test(String(n || '').replace(/[\s.\-()]/g, ''));
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const hashPw = (pw, salt = crypto.randomBytes(16).toString('hex')) => ({ salt, hash: crypto.scryptSync(pw, salt, 64).toString('hex') });
const okPw = (pw, u) => { const h = crypto.scryptSync(pw, u.salt, 64), b = Buffer.from(u.hash, 'hex'); return b.length === h.length && crypto.timingSafeEqual(h, b); };
const pub = u => ({ prenom: u.prenom, nom: u.nom, tel: u.tel, email: u.email, naissance: u.naissance, etat: u.etat });
const cookies = req => Object.fromEntries((req.headers.cookie || '').split(';').map(c => c.trim().split('=')).filter(a => a[0]).map(a => [a[0], decodeURIComponent(a[1] || '')]));
function newSession(res, userId, admin) {
  const token = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO sessions VALUES(?,?,?,?)').run(token, userId, admin ? 1 : 0, Date.now() + 7 * 864e5);
  res.setHeader('Set-Cookie', `sid=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800${https ? '; Secure' : ''}`);
}
const session = req => { const t = cookies(req).sid; return t ? db.prepare('SELECT * FROM sessions WHERE token=? AND exp>?').get(t, Date.now()) : null; };
const findUser = test => db.prepare('SELECT * FROM users').all().find(test);
setInterval(() => db.prepare('DELETE FROM sessions WHERE exp<?').run(Date.now()), 36e5).unref();

// ---------- envoi des codes (SMS / e-mail) ----------
function devLog(to, text) {
  if (process.env.NODE_ENV === 'production') throw new Error('Aucun service d’envoi configuré');
  console.log('[DEV] message pour', to, ':', text);
}
async function sendMessage(to, text) {
  if (to.includes('@')) {
    if (!process.env.RESEND_API_KEY) return devLog(to, text);
    const r = await fetch('https://api.resend.com/emails', { method: 'POST',
      headers: { Authorization: 'Bearer ' + process.env.RESEND_API_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from: process.env.MAIL_FROM, to: [to], subject: 'Votre code CLODALE', text }) });
    if (!r.ok) throw new Error('Resend ' + r.status);
  } else {
    if (!process.env.AT_API_KEY) return devLog(to, text);
    const sandbox = process.env.AT_USERNAME === 'sandbox';
    const body = new URLSearchParams({ username: process.env.AT_USERNAME, to: '+' + digits(to), message: text });
    if (process.env.AT_SENDER) body.set('from', process.env.AT_SENDER);
    const r = await fetch(`https://api.${sandbox ? 'sandbox.' : ''}africastalking.com/version1/messaging`, { method: 'POST',
      headers: { apiKey: process.env.AT_API_KEY, Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' }, body });
    if (!r.ok) throw new Error('Africa’s Talking ' + r.status);
  }
}
const otpKey = (purpose, dest) => purpose + ':' + norm(dest.includes('@') ? dest : '+' + digits(dest));
function checkOtp(purpose, dest, code) {
  const k = otpKey(purpose, String(dest || '')), r = db.prepare('SELECT * FROM otps WHERE k=?').get(k);
  if (!r || r.exp < Date.now() || r.tries >= 5) return false;
  db.prepare('UPDATE otps SET tries=tries+1 WHERE k=?').run(k);
  if (sha(String(code || '').trim() + k) !== r.hash) return false;
  db.prepare('DELETE FROM otps WHERE k=?').run(k); return true;
}

// ---------- application ----------
const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: { directives: {
  defaultSrc: ["'self'"], scriptSrc: ["'self'", "'unsafe-inline'"], styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
  fontSrc: ['https://fonts.gstatic.com'], imgSrc: ["'self'", 'data:'], connectSrc: ["'self'"], objectSrc: ["'none'"], frameAncestors: ["'none'"],
  upgradeInsecureRequests: https ? [] : null } } }));
app.use(express.json({ limit: '20kb' }));
app.use('/api', (req, res, next) => (req.method === 'POST' && !req.is('application/json')) ? res.status(415).json({ error: 'Requête invalide.' }) : next());
const lim = (min, n) => rateLimit({ windowMs: min * 60000, limit: n, standardHeaders: true, legacyHeaders: false, message: { error: 'Trop de tentatives. Réessayez plus tard.' } });
const bad = (res, m, c = 400) => res.status(c).json({ error: m });

app.post('/api/otp/send', lim(10, 6), async (req, res) => {
  const { purpose, to } = req.body || {}, dest = String(to || '').trim();
  if (!['register', 'reset'].includes(purpose) || dest.length < 6 || dest.length > 120) return bad(res, 'Demande invalide.');
  if (!dest.includes('@') && !intl(dest)) return bad(res, 'Saisissez le numéro avec l’indicatif du pays, par exemple +225…');
  const k = otpKey(purpose, dest), old = db.prepare('SELECT sent FROM otps WHERE k=?').get(k);
  if (old && Date.now() - old.sent < 60000) return bad(res, 'Patientez une minute avant de redemander un code.', 429);
  const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  try { await sendMessage(dest, `CLODALE : votre code de vérification est ${code}. Il expire dans 10 minutes.`); }
  catch (e) { console.error(e.message); return bad(res, 'Envoi impossible pour le moment.', 502); }
  db.prepare('INSERT OR REPLACE INTO otps VALUES(?,?,?,0,?)').run(k, sha(code + k), Date.now() + 600000, Date.now());
  res.json({ sent: true });
});

app.post('/api/register', lim(60, 15), (req, res) => {
  const b = req.body || {}, p = b.paiement || {}, S = k => String(b[k] || '').trim();
  const nom = S('nom'), prenom = S('prenom'), tel = S('tel'), email = S('email'), naissance = S('naissance'), pw = String(b.pw || '');
  if (!intl(tel)) return bad(res, 'Saisissez votre téléphone avec l’indicatif du pays (+225…).');
  if (!intl(p.numero)) return bad(res, 'Le numéro utilisé pour payer doit comporter l’indicatif du pays (+225…).');
  if (!nom || !prenom || !/^\S+@\S+\.\S+$/.test(email) || !/^\d{4}-\d{2}-\d{2}$/.test(naissance) || [nom, prenom, tel, email].some(x => x.length > 120)) return bad(res, 'Vérifiez les informations saisies.');
  if (pw.length < 8 || pw.length > 200) return bad(res, 'Le mot de passe doit contenir au moins 8 caractères.');
  if (!['Wave', 'Orange Money', 'Moov Money'].includes(p.moyen) || String(p.reference || '').trim().length < 6) return bad(res, 'Paiement de 3 000 XOF requis.');
  if (b.cgu !== true) return bad(res, 'Vous devez accepter les conditions d’utilisation.');
  const to = String(b.otpTo || '').trim();
  if (!(sameId(to, tel) || sameId(to, email)) || !checkOtp('register', to, b.code)) return bad(res, 'Code de vérification incorrect ou expiré.');
  if (findUser(u => sameId(u.tel, tel) || norm(u.email) === norm(email))) return bad(res, 'Vous êtes déjà inscrit. Connectez-vous.', 409);
  const h = hashPw(pw);
  const id = db.prepare('INSERT INTO users(nom,prenom,tel,email,naissance,salt,hash,moyen,pay_num,pay_ref,created) VALUES(?,?,?,?,?,?,?,?,?,?,?)')
    .run(nom, prenom, tel, email, naissance, h.salt, h.hash, p.moyen, String(p.numero || '').slice(0, 40), String(p.reference).trim().slice(0, 80), new Date().toISOString()).lastInsertRowid;
  newSession(res, Number(id), false); res.json({ ok: true });
});

app.post('/api/login', lim(15, 10), (req, res) => {
  const { id, pw } = req.body || {};
  const u = findUser(x => sameId(id, x.email) || sameId(id, x.tel));
  if (!u || !okPw(String(pw || ''), u)) return bad(res, 'Identifiants incorrects.', 401);
  newSession(res, u.id, false); res.json({ user: pub(u) });
});

app.get('/api/me', (req, res) => {
  const s = session(req), u = s && !s.admin && db.prepare('SELECT * FROM users WHERE id=?').get(s.user_id);
  u ? res.json({ user: pub(u) }) : bad(res, 'Non connecté.', 401);
});

app.post('/api/reset', lim(15, 8), (req, res) => {
  const { nom, prenom, id, code, pw } = req.body || {}, np = String(pw || '');
  if (np.length < 8 || np.length > 200) return bad(res, 'Le nouveau mot de passe doit contenir au moins 8 caractères.');
  const u = findUser(x => norm(x.nom) === norm(nom) && norm(x.prenom) === norm(prenom) && (sameId(id, x.email) || sameId(id, x.tel)));
  if (!u || !checkOtp('reset', String(id || ''), code)) return bad(res, 'Informations ou code incorrects.');
  const h = hashPw(np);
  db.prepare('UPDATE users SET salt=?, hash=? WHERE id=?').run(h.salt, h.hash, u.id);
  db.prepare('DELETE FROM sessions WHERE user_id=?').run(u.id);
  newSession(res, u.id, false); res.json({ user: pub(u) });
});

const online = new Map();
app.post('/api/ping', lim(1, 10), (req, res) => {
  const { cid, n } = req.body || {}; if (!cid || String(cid).length > 40) return res.json({});
  const s = session(req), u = s && !s.admin && db.prepare('SELECT prenom FROM users WHERE id=?').get(s.user_id);
  online.set(String(cid), { n: u ? u.prenom : String(n || 'Visiteur').slice(0, 40), t: Date.now() }); res.json({});
});

// ---------- espace propriétaire ----------
const isAdmin = (req, res, next) => { const s = session(req); s && s.admin ? next() : bad(res, 'Accès refusé.', 403); };
app.post('/api/admin/login', lim(15, 5), (req, res) => {
  const a = Buffer.from(sha(String((req.body || {}).password || ''))), b = Buffer.from(sha(ADMIN_PASSWORD));
  if (!crypto.timingSafeEqual(a, b)) return bad(res, 'Mot de passe incorrect.', 401);
  newSession(res, null, true); res.json({ ok: true });
});
app.get('/api/admin/overview', isAdmin, (req, res) => {
  const now = Date.now();
  for (const [k, v] of online) if (now - v.t > 70000) online.delete(k);
  res.json({ users: db.prepare('SELECT id,nom,prenom,tel,email,naissance,moyen,pay_num,pay_ref,etat,created FROM users ORDER BY id DESC').all(), online: [...online.values()].map(v => v.n) });
});
app.post('/api/admin/etat', isAdmin, (req, res) => {
  const { id, etat } = req.body || {};
  if (!['attente', 'valide', 'refuse'].includes(etat)) return bad(res, 'État invalide.');
  db.prepare('UPDATE users SET etat=? WHERE id=?').run(etat, Number(id)); res.json({ ok: true });
});

// ---------- pages ----------
const page = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8').replaceAll('__BASE_URL__', BASE_URL);
app.get('/', (req, res) => res.type('html').send(page));
app.get('/og-image.png', (req, res) => res.sendFile(path.join(__dirname, 'og-image.png')));
app.listen(PORT, () => console.log('CLODALE en ligne sur le port ' + PORT));
