require('dotenv').config();
const express = require('express');
const passport = require('passport');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

const app = express();

// 1. KONTROL AKSES (CORS) - Mengizinkan Frontend mengakses Backend
app.use(cors({ origin: process.env.FRONTEND_URL, credentials: true }));
app.use(cookieParser());

// 2. KONFIGURASI SESSION (Diberi fallback secret agar tidak crash di serverless)
app.use(session({
  secret: process.env.SESSION_SECRET || 'super-secret-fallback-key-12345',
  resave: false,
  saveUninitialized: false,
}));

// Inisialisasi Passport (Baris app.use(passport.session()) sudah dihapus dari sini)
app.use(passport.initialize());

// 3. STRATEGI GOOGLE OAUTH (Dibuat dinamis untuk Vercel & Localhost)
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.BACKEND_URL 
    ? `${process.env.BACKEND_URL}/auth/google/callback` 
    : 'http://localhost:5000/auth/google/callback',
}, (accessToken, refreshToken, profile, done) => {
  const user = {
    id: profile.id,
    name: profile.displayName,
    email: profile.emails && profile.emails[0] ? profile.emails[0].value : '',
    photo: profile.photos && profile.photos[0] ? profile.photos[0].value : '',
  };
  return done(null, user);
}));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// 4. ROUTE LOGIN GOOGLE (Ditambahkan session: false agar ramah serverless)
app.get('/auth/google', passport.authenticate('google', {
  scope: ['profile', 'email'],
  session: false
}));

// 5. ROUTE CALLBACK GOOGLE (Konfigurasi cookie disesuaikan untuk HTTPS Vercel)
app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/auth/failed', session: false }),
  (req, res) => {
    const token = jwt.sign(req.user, process.env.JWT_SECRET || 'jwt-fallback-secret', { expiresIn: '7d' });
    
    // Cek apakah aplikasi berjalan di Vercel (Production) atau komputer sendiri (Local)
    const isProduction = process.env.NODE_ENV === 'production' || !!process.env.BACKEND_URL;
    
    res.cookie('token', token, {
      httpOnly: true,
      secure: isProduction, // Wajib true di Vercel (HTTPS) agar tidak diblokir browser
      sameSite: isProduction ? 'none' : 'lax', // Wajib 'none' untuk cross-domain frontend-backend
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
    
    res.redirect(`${process.env.FRONTEND_URL}/dashboard`);
  }
);

// 6. ROUTE CEK DATA LOGIN USER
app.get('/auth/me', (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const user = jwt.verify(token, process.env.JWT_SECRET || 'jwt-fallback-secret');
    res.json({ user });
  } catch {
    res.status(401).json({ error: 'Token tidak valid' });
  }
});

// 7. ROUTE LOGOUT (Menghapus Cookie)
app.get('/auth/logout', (req, res) => {
  const isProduction = process.env.NODE_ENV === 'production' || !!process.env.BACKEND_URL;
  res.clearCookie('token', {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? 'none' : 'lax'
  });
  res.redirect(process.env.FRONTEND_URL);
});

// 8. ROUTE JIKA LOGIN GAGAL
app.get('/auth/failed', (req, res) => {
  res.status(401).json({ error: 'Login gagal' });
});

// 9. MENYALAKAN SERVER (Hanya berjalan di laptop lokal, di Vercel dihandle serverless handler)
if (process.env.NODE_ENV !== 'production') {
  app.listen(5000, () => console.log('Backend jalan di port 5000'));
}

// 10. EKSPOR APP (Wajib untuk Vercel agar serverless function mendeteksi routing Express)
module.exports = app;