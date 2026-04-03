const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;
const IS_VERCEL = !!process.env.VERCEL;
const DATA_DIR = IS_VERCEL ? '/tmp/data' : path.join(__dirname, 'data');

// --- Persistent JWT Secret ---
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

let JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  const SECRET_FILE = path.join(DATA_DIR, '.jwt_secret');
  if (fs.existsSync(SECRET_FILE)) {
    JWT_SECRET = fs.readFileSync(SECRET_FILE, 'utf8').trim();
  } else {
    JWT_SECRET = crypto.randomBytes(64).toString('hex');
    fs.writeFileSync(SECRET_FILE, JWT_SECRET, { mode: 0o600 });
  }
}

// --- Data Files ---
const FILES = {
  users: path.join(DATA_DIR, 'users.json'),
  services: path.join(DATA_DIR, 'services.json'),
  reports: path.join(DATA_DIR, 'reports.json'),
};
Object.values(FILES).forEach(f => {
  if (!fs.existsSync(f)) fs.writeFileSync(f, '[]');
});

app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(express.static(__dirname));

// --- DB Helpers ---
function read(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { return []; }
}
function write(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

// --- Rate Limiting ---
const rateMap = new Map();
function isRateLimited(ip, action, maxPerHour = 15) {
  const key = `${ip}:${action}`;
  const now = Date.now();
  const hour = 3600000;
  const entries = (rateMap.get(key) || []).filter(t => now - t < hour);
  if (entries.length >= maxPerHour) return true;
  entries.push(now);
  rateMap.set(key, entries);
  return false;
}

// --- Auth Middleware ---
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required. Please log in.' });
  }
  try {
    const decoded = jwt.verify(header.slice(7), JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired session. Please log in again.' });
  }
}

// --- Input Helpers ---
function sanitize(str, maxLen = 500) {
  if (typeof str !== 'string') return '';
  return str.trim().slice(0, maxLen);
}

const VALID_CATEGORIES = [
  'Technology & IT', 'Design & Creative', 'Business & Finance',
  'Education & Tutoring', 'Health & Wellness', 'Home & Maintenance',
  'Legal & Consulting', 'Marketing & Sales', 'Transport & Delivery',
  'Food & Catering', 'Beauty & Personal Care', 'Other'
];

const LICENSE_TYPES = [
  'DED Mainland License', 'Free Zone License', 'Freelance Permit',
  'Home-Based Business License', 'Professional License', 'Pending / In Process', 'Other'
];

// ============================================================
// AUTH ROUTES
// ============================================================

// REGISTER
app.post('/api/auth/register', (req, res) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  if (isRateLimited(ip, 'register', 5)) {
    return res.status(429).json({ error: 'Too many registration attempts. Try again later.' });
  }

  const { email, password, fullName, phone } = req.body;

  if (!email || !password || !fullName) {
    return res.status(400).json({ error: 'Email, password, and full name are required.' });
  }

  const cleanEmail = sanitize(email, 254).toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
    return res.status(400).json({ error: 'Invalid email format.' });
  }

  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  }

  const users = read(FILES.users);
  if (users.find(u => u.email === cleanEmail)) {
    return res.status(409).json({ error: 'An account with this email already exists.' });
  }

  const user = {
    id: uuidv4(),
    email: cleanEmail,
    password: bcrypt.hashSync(password, 12),
    fullName: sanitize(fullName, 100),
    phone: sanitize(phone, 20),
    pdplConsentAt: new Date().toISOString(),
    pdplConsentVersion: '2026-04',
    createdAt: new Date().toISOString()
  };

  users.push(user);
  write(FILES.users, users);

  const token = jwt.sign({ id: user.id, email: user.email, fullName: user.fullName }, JWT_SECRET, { expiresIn: '30d' });
  res.status(201).json({
    token,
    user: { id: user.id, email: user.email, fullName: user.fullName, phone: user.phone }
  });
});

// LOGIN
app.post('/api/auth/login', (req, res) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  if (isRateLimited(ip, 'login', 20)) {
    return res.status(429).json({ error: 'Too many login attempts. Try again later.' });
  }

  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  const users = read(FILES.users);
  const user = users.find(u => u.email === sanitize(email, 254).toLowerCase());
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Invalid email or password.' });
  }

  const token = jwt.sign({ id: user.id, email: user.email, fullName: user.fullName }, JWT_SECRET, { expiresIn: '30d' });
  res.json({
    token,
    user: { id: user.id, email: user.email, fullName: user.fullName, phone: user.phone }
  });
});

// GET current user profile
app.get('/api/auth/me', auth, (req, res) => {
  const users = read(FILES.users);
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found.' });
  res.json({ id: user.id, email: user.email, fullName: user.fullName, phone: user.phone });
});

// ============================================================
// SERVICES ROUTES
// ============================================================

// GET all services (public) — strips userId for privacy
app.get('/api/services', (req, res) => {
  const services = read(FILES.services);
  const publicServices = services.map(({ userId, ...rest }) => rest);
  res.json(publicServices);
});

// GET my services (auth required) — MUST be before /:id
app.get('/api/services/mine', auth, (req, res) => {
  const services = read(FILES.services);
  res.json(services.filter(s => s.userId === req.user.id));
});

// GET single service (public)
app.get('/api/services/:id', (req, res) => {
  const services = read(FILES.services);
  const service = services.find(s => s.id === req.params.id);
  if (!service) return res.status(404).json({ error: 'Service not found.' });
  const { userId, ...publicService } = service;
  res.json(publicService);
});

// POST new service (auth required)
app.post('/api/services', auth, (req, res) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  if (isRateLimited(ip, 'post-service', 10)) {
    return res.status(429).json({ error: 'Too many submissions. Please try again later.' });
  }

  const {
    title, category, description,
    businessName, licenseNumber, licenseType,
    phone, email, website, location,
    acceptedTerms, confirmedLicense
  } = req.body;

  // Required fields
  if (!title || !category || !description) {
    return res.status(400).json({ error: 'Title, category, and description are required.' });
  }
  if (!acceptedTerms) {
    return res.status(400).json({ error: 'You must accept the Terms of Use.' });
  }
  if (!confirmedLicense) {
    return res.status(400).json({ error: 'You must confirm your trade license status.' });
  }
  if (!licenseType) {
    return res.status(400).json({ error: 'License type is required.' });
  }
  if (!VALID_CATEGORIES.includes(category)) {
    return res.status(400).json({ error: 'Invalid category.' });
  }
  if (!LICENSE_TYPES.includes(licenseType)) {
    return res.status(400).json({ error: 'Invalid license type.' });
  }

  // Validate contact — at least one method required
  const cleanPhone = sanitize(phone, 20);
  const cleanEmail = sanitize(email, 254);
  if (!cleanPhone && !cleanEmail) {
    return res.status(400).json({ error: 'At least one contact method (phone or email) is required.' });
  }

  if (cleanEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
    return res.status(400).json({ error: 'Invalid email format.' });
  }

  const service = {
    id: uuidv4(),
    userId: req.user.id,
    providerName: req.user.fullName,
    title: sanitize(title, 120),
    category,
    description: sanitize(description, 2000),
    businessName: sanitize(businessName, 150),
    licenseNumber: sanitize(licenseNumber, 50),
    licenseType: licenseType,
    phone: cleanPhone,
    email: cleanEmail,
    website: sanitize(website, 200),
    location: sanitize(location, 100),
    termsAcceptedAt: new Date().toISOString(),
    termsVersion: '2026-04',
    createdAt: new Date().toISOString(),
    status: 'active'
  };

  const services = read(FILES.services);
  services.unshift(service);
  write(FILES.services, services);

  res.status(201).json(service);
});

// PUT update service (only owner)
app.put('/api/services/:id', auth, (req, res) => {
  const services = read(FILES.services);
  const index = services.findIndex(s => s.id === req.params.id);
  if (index === -1) return res.status(404).json({ error: 'Service not found.' });
  if (services[index].userId !== req.user.id) {
    return res.status(403).json({ error: 'You can only edit your own listings.' });
  }

  const {
    title, category, description,
    businessName, licenseNumber, licenseType,
    phone, email, website, location
  } = req.body;

  if (category && !VALID_CATEGORIES.includes(category)) {
    return res.status(400).json({ error: 'Invalid category.' });
  }
  if (licenseType && !LICENSE_TYPES.includes(licenseType)) {
    return res.status(400).json({ error: 'Invalid license type.' });
  }

  const cleanEmail = sanitize(email, 254);
  if (cleanEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
    return res.status(400).json({ error: 'Invalid email format.' });
  }

  const s = services[index];
  if (title) s.title = sanitize(title, 120);
  if (category) s.category = category;
  if (description) s.description = sanitize(description, 2000);
  if (businessName !== undefined) s.businessName = sanitize(businessName, 150);
  if (licenseNumber !== undefined) s.licenseNumber = sanitize(licenseNumber, 50);
  if (licenseType) s.licenseType = licenseType;
  if (phone !== undefined) s.phone = sanitize(phone, 20);
  if (email !== undefined) s.email = cleanEmail;
  if (website !== undefined) s.website = sanitize(website, 200);
  if (location !== undefined) s.location = sanitize(location, 100);
  s.updatedAt = new Date().toISOString();

  write(FILES.services, services);
  const { userId, ...publicService } = s;
  res.json(publicService);
});

// DELETE a service (only owner)
app.delete('/api/services/:id', auth, (req, res) => {
  const services = read(FILES.services);
  const index = services.findIndex(s => s.id === req.params.id);
  if (index === -1) return res.status(404).json({ error: 'Service not found.' });
  if (services[index].userId !== req.user.id) {
    return res.status(403).json({ error: 'You can only delete your own listings.' });
  }

  services.splice(index, 1);
  write(FILES.services, services);
  res.json({ success: true });
});

// REPORT a listing (auth required)
app.post('/api/services/:id/report', auth, (req, res) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  if (isRateLimited(ip, 'report', 10)) {
    return res.status(429).json({ error: 'Too many reports. Try again later.' });
  }

  const services = read(FILES.services);
  if (!services.find(s => s.id === req.params.id)) {
    return res.status(404).json({ error: 'Service not found.' });
  }

  const { reason } = req.body || {};
  if (!reason) {
    return res.status(400).json({ error: 'A reason is required.' });
  }

  const reports = read(FILES.reports);

  // Prevent duplicate reports from same user on same service
  if (reports.find(r => r.serviceId === req.params.id && r.reportedBy === req.user.id)) {
    return res.status(409).json({ error: 'You have already reported this listing.' });
  }

  reports.push({
    id: uuidv4(),
    serviceId: req.params.id,
    reportedBy: req.user.id,
    reason: sanitize(reason, 500),
    date: new Date().toISOString()
  });
  write(FILES.reports, reports);
  res.json({ success: true, message: 'Report submitted. Thank you.' });
});

// ============================================================
if (!IS_VERCEL) {
  app.listen(PORT, () => {
    console.log(`UAE Community Services Hub running at http://localhost:${PORT}`);
  });
}

module.exports = app;
