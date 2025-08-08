// server.js (secured with shared secret header)
import express from 'express';
import fetch from 'node-fetch';
import cors from 'cors';

const app = express();

/** Security: set allowed origins via env (comma-separated) */
const ORIGINS = (process.env.CORS_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

const SHARED_SECRET = process.env.SHARED_SECRET || ''; // e.g., long random string
const AUTH_HEADER = process.env.AUTH_HEADER || 'x-ch-secret'; // header name to expect

const corsOptions = {
  origin: function (origin, cb) {
    if (!origin || ORIGINS.length === 0 || ORIGINS.includes(origin)) {
      return cb(null, true);
    }
    return cb(new Error('Not allowed by CORS: ' + origin));
  },
  methods: ['GET'],
  credentials: false
};
app.use(cors(corsOptions));

/** Basic rate limit — lightweight */
const WINDOW_MS = 60 * 1000;
const MAX_REQS = 60;
const hits = new Map();
app.use((req, res, next) => {
  const key = req.ip;
  const now = Date.now();
  const entry = hits.get(key) || { count: 0, ts: now };
  if (now - entry.ts > WINDOW_MS) { entry.count = 0; entry.ts = now; }
  entry.count++;
  hits.set(key, entry);
  if (entry.count > MAX_REQS) return res.status(429).json({ error: 'Rate limit exceeded' });
  next();
});

/** Minimal auth middleware (skip for /health) */
app.use((req, res, next) => {
  if (req.path === '/health') return next();
  if (!SHARED_SECRET) return res.status(500).json({ error: 'Server not configured (missing SHARED_SECRET)' });
  const token = req.headers[AUTH_HEADER] || req.headers[AUTH_HEADER.toLowerCase()] || req.headers[AUTH_HEADER.toUpperCase()];
  if (!token || token !== SHARED_SECRET) {
    return res.status(401).json({ error: 'Unauthorised' });
  }
  next();
});

/** Config */
const CH_API_KEY = process.env.CH_API_KEY;
const CH_BASE = 'https://api.company-information.service.gov.uk';

if (!CH_API_KEY) {
  console.warn('⚠️ CH_API_KEY not set — Companies House calls will fail.');
}

/** Healthcheck */
app.get('/health', (_req, res) => res.json({ ok: true }));

/** Companies House: company search */
app.get('/companies-house/search', async (req, res) => {
  const q = (req.query.q || '').toString();
  if (!q || q.length < 3) return res.json({ items: [] });

  try {
    const r = await fetch(`${CH_BASE}/search/companies?q=${encodeURIComponent(q)}&items_per_page=20`, {
      headers: { 'Authorization': 'Basic ' + Buffer.from(CH_API_KEY + ':').toString('base64') }
    });
    if (!r.ok) {
      const text = await r.text();
      return res.status(r.status).json({ error: 'CH error', detail: text });
    }
    const data = await r.json();
    const items = (data.items || []).map(x => ({
      title: x.title,
      company_number: x.company_number,
      company_status: x.company_status,
      address_snippet: x.address_snippet
    }));
    res.json({ items });
  } catch (e) {
    console.error('CH search failed', e);
    res.status(500).json({ items: [] });
  }
});

/** Officers endpoint (for director dropdown) */
app.get('/companies-house/:number/officers', async (req, res) => {
  const number = (req.params.number || '').toString();
  if (!number) return res.json({ items: [] });
  try {
    const r = await fetch(`${CH_BASE}/company/${encodeURIComponent(number)}/officers?items_per_page=50`, {
      headers: { 'Authorization': 'Basic ' + Buffer.from(CH_API_KEY + ':').toString('base64') }
    });
    if (!r.ok) {
      const text = await r.text();
      return res.status(r.status).json({ error: 'CH error', detail: text });
    }
    const data = await r.json();
    const items = (data.items || []).map(o => ({
      name: o.name,
      appointed_on: o.appointed_on,
      resigned_on: o.resigned_on,
      role: o.officer_role
    }));
    res.json({ items });
  } catch (e) {
    console.error('CH officers failed', e);
    res.status(500).json({ items: [] });
  }
});

/** Companies House: get company details (for status etc) */
app.get('/companies-house/:number', async (req, res) => {
  const number = (req.params.number || '').toString();
  if (!number) return res.status(400).json({ error: 'No company number' });
  try {
    const r = await fetch(`${CH_BASE}/company/${encodeURIComponent(number)}`, {
      headers: { 'Authorization': 'Basic ' + Buffer.from(CH_API_KEY + ':').toString('base64') }
    });
    if (!r.ok) {
      const text = await r.text();
      return res.status(r.status).json({ error: 'CH error', detail: text });
    }
    const data = await r.json();
    res.json(data);
  } catch (e) {
    console.error('CH details failed', e);
    res.status(500).json({ error: 'Failed to fetch company details' });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log('CH proxy (secure) running on :' + port));
