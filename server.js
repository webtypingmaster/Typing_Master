const crypto = require('crypto');

const express    = require('express');
const session    = require('express-session');
const MongoStore = require('connect-mongo');
const bodyParser = require('body-parser');
const path       = require('path');
const mongoose   = require('mongoose');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const multer     = require('multer');
const { v4: uuidv4 } = require('uuid');
const paragraphsData = require('./data/paragraphs');

const app  = express();
const PORT = process.env.PORT || 3000;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

// Reverse proxy (Heroku/Render/Nginx etc.) ke peeche secure cookies sahi se kaam
// karein, isliye trust proxy zaroori hai
app.set('trust proxy', 1);

// ─── Admin Credentials (JWT based - alag system) ──────────────────────────────
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const JWT_SECRET     = process.env.JWT_SECRET;

// ─── MongoDB Connection ───────────────────────────────────────────────────────
const MONGO_URI = process.env.MONGO_URI;

mongoose.connect(MONGO_URI)
  .then(() => console.log('✅ MongoDB se connect ho gaya!'))
  .catch(err => console.error('❌ MongoDB error:', err.message));

// ─── Schemas ─────────────────────────────────────────────────────────────────

const userSchema = new mongoose.Schema({
  name:           { type: String, required: true, trim: true },
  username:       { type: String, required: true, unique: true, lowercase: true, trim: true },
  email:          { type: String, required: true, unique: true, lowercase: true, trim: true },
  phone:          { type: String, default: '', trim: true },
  inviteCode:     { type: String, default: '', trim: true },
  invitedBy:      { type: String, default: '', lowercase: true, trim: true }, // username of inviter
  password:       { type: String, required: true },
  // plainPassword field hata diya gaya - plain text password store karna security risk hai
  bio:            { type: String, default: '', maxlength: 200 },
  avatar:         { type: String, default: '' },
  seenParagraphs: { type: [String], default: [] },
  // Forgot password token
  isAdmin:        { type: Boolean, default: false },
  resetToken:     { type: String, default: '' },
  resetTokenExp:  { type: Date, default: null },
  createdAt:      { type: Date, default: Date.now }
});

const resultSchema = new mongoose.Schema({
  userId:       { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  userName:     { type: String, required: true },
  userEmail:    { type: String, required: true },
  level:        { type: Number, required: true },
  paragraphId:  { type: String, default: '' },
  wpm:          { type: Number, required: true },
  accuracy:     { type: Number, required: true },
  correctWords: { type: Number, default: 0 },
  wrongWords:   { type: Number, default: 0 },
  timeTaken:    { type: Number, default: 0 },
  completedAt:  { type: Date, default: Date.now }
});

const User   = mongoose.model('User',   userSchema);
const Result = mongoose.model('Result', resultSchema);

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: MONGO_URI,
    collectionName: 'sessions',
    ttl: 7 * 24 * 60 * 60
  }),
  cookie: {
    maxAge: 7 * 24 * 60 * 60 * 1000,
    httpOnly: true,
    sameSite: 'lax',
    secure: IS_PRODUCTION // HTTPS pe hi cookie bhejo jab production mein ho
  }
}));

// ─── Auth Middleware ──────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (req.session?.user) return next();
  if (req.path.startsWith('/api/')) {
    return res.status(401).json({ success: false, message: 'Login karein pehle.' });
  }
  res.redirect('/');
}

// ─── Admin JWT Middleware ─────────────────────────────────────────────────────
function adminAuth(req, res, next) {
  const header = req.headers['authorization'];
  if (!header) return res.status(401).json({ error: 'Admin token required.' });
  const token = header.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.role !== 'admin') return res.status(403).json({ error: 'Admin access required.' });
    next();
  } catch {
    res.status(401).json({ error: 'Token invalid ya expire ho gaya.' });
  }
}

// ─── Static Files ─────────────────────────────────────────────────────────────
// Admin panel (alag folder - JWT se protected)
app.use('/admin-panel', express.static(path.join(__dirname, 'admin-panel')));
app.get(/^\/admin-panel\/.*$/, (req, res) => {
  res.sendFile(path.join(__dirname, 'admin-panel', 'index.html'));
});

// Public files
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ─── Multer (Profile Photo Upload) ───────────────────────────────────────────
const fs = require('fs');
const uploadsDir = path.join(__dirname, 'uploads', 'avatars');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, req.session.user.id + '_' + Date.now() + ext);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 2 * 1024 * 1024 }, // 2MB max
  fileFilter: (req, file, cb) => {
    const allowed = ['.jpg', '.jpeg', '.png', '.webp', '.gif'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowed.includes(ext)) cb(null, true);
    else cb(new Error('Sirf image files allowed hain (jpg, png, webp, gif).'));
  }
});

// ─── PAGES ───────────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  if (req.session.user) return res.redirect('/typing');
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/typing',      requireAuth, (req, res) => res.sendFile(path.join(__dirname, 'public', 'typing.html')));
app.get('/profile',     requireAuth, (req, res) => res.sendFile(path.join(__dirname, 'public', 'profile.html')));
app.get('/leaderboard', requireAuth, (req, res) => res.sendFile(path.join(__dirname, 'public', 'leaderboard.html')));
app.get('/invite',      requireAuth, (req, res) => res.sendFile(path.join(__dirname, 'public', 'invite.html')));
app.get('/forgot-password', (req, res) => res.sendFile(path.join(__dirname, 'public', 'forgot-password.html')));
app.get('/reset-password', (req, res) => res.sendFile(path.join(__dirname, 'public', 'reset-password.html')));

// ─── AUTH ─────────────────────────────────────────────────────────────────────

// Register
app.post('/register', async (req, res) => {
  try {
    const { name, username, email, phone, password, confirmPassword, inviteCode } = req.body;
    if (!name || !username || !email || !phone || !password || !confirmPassword)
      return res.json({ success: false, message: 'Sab fields bharo.' });

    if (password !== confirmPassword)
      return res.json({ success: false, message: 'Password aur Confirm Password match nahi kar rahe.' });

    // Username format: exactly 4 lowercase letters + 4 digits (e.g. abcd1234)
    const usernameRegex = /^[a-z]{4}\d{4}$/;
    const cleanUsername = username.trim().toLowerCase();
    if (!usernameRegex.test(cleanUsername))
      return res.json({ success: false, message: 'Username mein 4 small letters (a-z) aur 4 numbers (0-9) hone chahiye. Example: abcd1234' });

    // Strong password validation: min 8 chars, 1 uppercase, 1 lowercase, 1 number, 1 special char
    const passRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$/;
    if (!passRegex.test(password))
      return res.json({ success: false, message: 'Password mein kam az kam 8 characters, 1 capital (A-Z), 1 small (a-z), 1 number (0-9) aur 1 special character (!@#$%^&*) hona chahiye.' });

    const emailExists = await User.findOne({ email: email.toLowerCase().trim() });
    if (emailExists)
      return res.json({ success: false, message: 'Yeh email already registered hai.' });

    const usernameExists = await User.findOne({ username: cleanUsername });
    if (usernameExists)
      return res.json({ success: false, message: 'Yeh username already liya gaya hai.' });

    // Invite code (agar diya gaya ho) check karo - yeh kisi existing user ka username hona chahiye
    let invitedBy = '';
    const cleanInvite = inviteCode ? inviteCode.trim().toLowerCase() : '';
    if (cleanInvite) {
      const inviter = await User.findOne({ username: cleanInvite });
      if (!inviter)
        return res.json({ success: false, message: 'Invite code galat hai. Yeh kisi registered user ka username nahi hai.' });
      if (inviter.username === cleanUsername)
        return res.json({ success: false, message: 'Aap apna khud ka invite code use nahi kar sakte.' });
      invitedBy = inviter.username;
    }

    // Naam ko Title Case mein normalize karo (har word ka pehla letter capital)
    const formattedName = name.trim().split(/\s+/)
      .map(w => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase())
      .join(' ');

    const hashed = await bcrypt.hash(password, 10);
    const user   = await User.create({
      name: formattedName,
      username: cleanUsername,
      email,
      phone: phone.trim(),
      inviteCode: cleanInvite,
      invitedBy,
      password: hashed
    });

    req.session.user = { id: user._id.toString(), name: user.name, username: user.username, email: user.email };
    res.json({ success: true, redirect: '/typing' });
  } catch (err) {
    console.error(err);
    res.json({ success: false, message: 'Server error.' });
  }
});

// Login
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.json({ success: false, message: 'Email aur password dono chahiye.' });

    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user)
      return res.json({ success: false, message: 'Email nahi mila.' });

    const match = await bcrypt.compare(password, user.password);
    if (!match)
      return res.json({ success: false, message: 'Galat password.' });

    req.session.user = { id: user._id.toString(), name: user.name, username: user.username, email: user.email };
    res.json({ success: true, redirect: '/typing' });
  } catch (err) {
    console.error(err);
    res.json({ success: false, message: 'Server error.' });
  }
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

// ─── FORGOT PASSWORD ──────────────────────────────────────────────────────────

// Step 1: Email submit - token generate karo
app.post('/api/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.json({ success: false, message: 'Email daalo.' });

    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user)
      return res.json({ success: false, message: 'Yeh email registered nahi hai.' });

    // 6-digit token generate karo
    const token    = Math.floor(100000 + Math.random() * 900000).toString();
    const tokenExp = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

    await User.findByIdAndUpdate(user._id, {
      resetToken: token,
      resetTokenExp: tokenExp
    });

    // SECURITY: token kabhi bhi API response mein wapas mat karo - isse koi bhi
    // sirf email daal kar kisi aur ka account takeover kar sakta hai.
    // Real app mein yahan email service (nodemailer / SES / etc.) se token bhejo.
    // Demo/dev testing ke liye token sirf server console mein log hoga.
    console.log(`🔑 Password reset token for ${user.email}: ${token} (expires in 15 min)`);

    res.json({
      success: true,
      message: 'Agar yeh email registered hai to reset token email pe bhej diya gaya hai.',
      userId: user._id.toString()
    });
  } catch (err) {
    res.json({ success: false, message: 'Server error.' });
  }
});

// Step 2: Token verify + new password set
app.post('/api/reset-password', async (req, res) => {
  try {
    const { userId, token, newPassword, confirmPassword } = req.body;

    if (!userId || !token || !newPassword)
      return res.json({ success: false, message: 'Sab fields bharo.' });

    if (newPassword !== confirmPassword)
      return res.json({ success: false, message: 'Passwords match nahi karte.' });

    // Password validation
    const passRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$/;
    if (!passRegex.test(newPassword))
      return res.json({ success: false, message: 'Password mein kam az kam 8 characters, 1 capital (A-Z), 1 small (a-z), 1 number (0-9) aur 1 special character (!@#$%^&*) hona chahiye.' });

    const user = await User.findById(userId);
    if (!user) return res.json({ success: false, message: 'User nahi mila.' });

    if (user.resetToken !== token)
      return res.json({ success: false, message: 'Token galat hai.' });

    if (!user.resetTokenExp || new Date() > user.resetTokenExp)
      return res.json({ success: false, message: 'Token expire ho gaya. Dobara try karein.' });

    const hashed = await bcrypt.hash(newPassword, 10);
    await User.findByIdAndUpdate(userId, {
      password: hashed,
      resetToken: '',
      resetTokenExp: null
    });

    res.json({ success: true, message: 'Password successfully reset ho gaya!' });
  } catch (err) {
    res.json({ success: false, message: 'Server error.' });
  }
});

// Change Password (logged in user)
app.post('/api/change-password', requireAuth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword)
      return res.json({ success: false, message: 'Dono fields bharo.' });
    // Strong password validation: min 8 chars, 1 uppercase, 1 lowercase, 1 number, 1 special char
    const passRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$/;
    if (!passRegex.test(newPassword))
      return res.json({ success: false, message: 'Password mein kam az kam 8 characters, 1 capital (A-Z), 1 small (a-z), 1 number (0-9) aur 1 special character (!@#$%^&*) hona chahiye.' });

    const user  = await User.findById(req.session.user.id);
    if (!user) return res.json({ success: false, message: 'User nahi mila.' });

    const match = await bcrypt.compare(currentPassword, user.password);
    if (!match) return res.json({ success: false, message: 'Purana password galat hai.' });

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();
    res.json({ success: true, message: 'Password badal diya gaya!' });
  } catch (err) {
    res.json({ success: false, message: 'Server error.' });
  }
});

// Update Profile
app.post('/api/update-profile', requireAuth, async (req, res) => {
  try {
    const { name, bio } = req.body;
    if (!name) return res.json({ success: false, message: 'Naam khali nahi ho sakta.' });

    const user = await User.findByIdAndUpdate(
      req.session.user.id,
      { name: name.trim(), bio: (bio || '').trim().slice(0, 200) },
      { new: true }
    );
    req.session.user.name = user.name;
    res.json({ success: true, message: 'Profile update ho gayi!' });
  } catch (err) {
    res.json({ success: false, message: 'Server error.' });
  }
});

// ─── AVATAR UPLOAD ────────────────────────────────────────────────────────────
app.post('/api/upload-avatar', requireAuth, (req, res) => {
  upload.single('avatar')(req, res, async (err) => {
    if (err) return res.json({ success: false, message: err.message });
    if (!req.file) return res.json({ success: false, message: 'Koi file nahi mili.' });

    try {
      const avatarUrl = '/uploads/avatars/' + req.file.filename;

      // Purani photo delete karo agar thi
      const oldUser = await User.findById(req.session.user.id);
      if (oldUser.avatar && oldUser.avatar.startsWith('/uploads/')) {
        const oldPath = path.join(__dirname, oldUser.avatar);
        if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
      }

      await User.findByIdAndUpdate(req.session.user.id, { avatar: avatarUrl });
      res.json({ success: true, avatarUrl, message: 'Photo upload ho gayi!' });
    } catch (e) {
      res.json({ success: false, message: 'Server error.' });
    }
  });
});

// ─── AVATAR DELETE ────────────────────────────────────────────────────────────
app.delete('/api/delete-avatar', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.session.user.id);
    if (user.avatar && user.avatar.startsWith('/uploads/')) {
      const oldPath = path.join(__dirname, user.avatar);
      if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
    }
    await User.findByIdAndUpdate(req.session.user.id, { avatar: '' });
    res.json({ success: true, message: 'Photo hata di gayi!' });
  } catch (e) {
    res.json({ success: false, message: 'Server error.' });
  }
});

// ─── USER APIs ────────────────────────────────────────────────────────────────

app.get('/api/me', requireAuth, async (req, res) => {
  try {
    const user    = await User.findById(req.session.user.id).lean();
    if (!user) return res.json({ success: false });

    const results = await Result.find({ userId: user._id }).lean();
    const bestWpm = results.length ? Math.max(...results.map(r => r.wpm)) : 0;
    const avgWpm  = results.length ? Math.round(results.reduce((s, r) => s + r.wpm, 0) / results.length) : 0;
    const avgAcc  = results.length ? Math.round(results.reduce((s, r) => s + r.accuracy, 0) / results.length) : 0;
    const levelsCompleted = new Set(results.map(r => r.level)).size;

    res.json({
      success: true,
      user: {
        id: user._id, name: user.name, username: user.username, email: user.email,
        phone: user.phone || '', bio: user.bio || '', avatar: user.avatar || '', createdAt: user.createdAt,
        stats: { totalTests: results.length, bestWpm, avgWpm, avgAcc, levelsCompleted }
      }
    });
  } catch (err) {
    res.json({ success: false });
  }
});

app.get('/api/my-results', requireAuth, async (req, res) => {
  try {
    const results = await Result.find({ userId: req.session.user.id })
      .sort({ completedAt: -1 }).limit(50).lean();
    res.json({ success: true, results });
  } catch (err) {
    res.json({ success: false, results: [] });
  }
});

app.get('/api/paragraph/:level', requireAuth, async (req, res) => {
  try {
    const level = parseInt(req.params.level);
    if (isNaN(level) || level < 1 || level > 50)
      return res.json({ success: false, message: 'Invalid level.' });

    const user = await User.findById(req.session.user.id).lean();
    const allParas = paragraphsData[level] || [];
    if (allParas.length === 0) return res.json({ success: false, message: 'Level nahi mila.' });

    const seenIds = user.seenParagraphs || [];
    let unseen = allParas.filter(p => !seenIds.includes(p.id));
    if (unseen.length === 0) {
      const levelIds = allParas.map(p => p.id);
      await User.findByIdAndUpdate(req.session.user.id, { $pull: { seenParagraphs: { $in: levelIds } } });
      unseen = allParas;
    }
    const para = unseen[Math.floor(Math.random() * unseen.length)];
    await User.findByIdAndUpdate(req.session.user.id, { $addToSet: { seenParagraphs: para.id } });
    res.json({ success: true, paragraph: { level, text: para.text, id: para.id } });
  } catch (err) {
    res.json({ success: false, message: 'Server error.' });
  }
});

app.post('/api/result', requireAuth, async (req, res) => {
  try {
    const { level, wpm, accuracy, correctWords, wrongWords, timeTaken, paragraphId } = req.body;
    if (!level || wpm === undefined)
      return res.json({ success: false, message: 'Invalid data.' });

    await Result.create({
      userId:       req.session.user.id,
      userName:     req.session.user.name,
      userEmail:    req.session.user.email,
      level:        parseInt(level),
      paragraphId:  paragraphId || '',
      wpm:          parseInt(wpm),
      accuracy:     parseInt(accuracy),
      correctWords: parseInt(correctWords),
      wrongWords:   parseInt(wrongWords),
      timeTaken:    parseFloat(timeTaken)
    });
    res.json({ success: true });
  } catch (err) {
    res.json({ success: false, message: 'Save nahi hua.' });
  }
});

app.get('/api/leaderboard', requireAuth, async (req, res) => {
  try {
    // Pehle wpm descending sort karo, phir har user ka sirf best (top) attempt
    // $first se lo - isse name, wpm, accuracy, level sab EK hi attempt se aayenge
    // (pehle alag-alag $max use ho raha tha jisse mismatched stats show hote thay)
    const best = await Result.aggregate([
      { $sort: { wpm: -1 } },
      { $group: {
        _id: '$userId',
        name:        { $first: '$userName' },
        wpm:         { $first: '$wpm' },
        accuracy:    { $first: '$accuracy' },
        level:       { $first: '$level' },
        completedAt: { $first: '$completedAt' }
      }},
      { $sort: { wpm: -1 } },
      { $limit: 20 }
    ]);

    const leaderboard = best.map((u, i) => ({
      userId: u._id, name: u.name,
      wpm: u.wpm, accuracy: Math.round(u.accuracy),
      level: u.level, date: u.completedAt,
      rank: i + 1
    }));

    res.json({ success: true, leaderboard });
  } catch (err) {
    res.json({ success: false, leaderboard: [] });
  }
});

// Invite stats: apna username, kitne logon ne join kiya, aur unka level progress
app.get('/api/invite-stats', requireAuth, async (req, res) => {
  try {
    const me = await User.findById(req.session.user.id).lean();
    if (!me) return res.json({ success: false });

    const invited = await User.find({ invitedBy: me.username }).lean();

    // Har invited user ke liye alag Result.find() chalane ke bajaye (N+1 queries),
    // ek hi aggregation se sab ke stats nikalo
    const invitedIds = invited.map(u => u._id);
    const statsAgg = await Result.aggregate([
      { $match: { userId: { $in: invitedIds } } },
      { $group: {
        _id: '$userId',
        levels: { $addToSet: '$level' },
        bestWpm: { $max: '$wpm' }
      }}
    ]);
    const statsMap = {};
    statsAgg.forEach(s => {
      statsMap[s._id.toString()] = { levelsCompleted: s.levels.length, bestWpm: s.bestWpm };
    });

    const invitedList = invited.map(u => {
      const stats = statsMap[u._id.toString()] || { levelsCompleted: 0, bestWpm: 0 };
      return {
        name: u.name,
        username: u.username,
        levelsCompleted: stats.levelsCompleted,
        bestWpm: stats.bestWpm,
        joinedAt: u.createdAt
      };
    });

    invitedList.sort((a, b) => new Date(b.joinedAt) - new Date(a.joinedAt));

    res.json({
      success: true,
      username: me.username,
      totalInvited: invitedList.length,
      invitedList
    });
  } catch (err) {
    console.error(err);
    res.json({ success: false });
  }
});

// ─── ADMIN JWT APIs ───────────────────────────────────────────────────────────

// Timing-safe string compare - regular !== string comparison short-circuits
// character by character, jisse response time se password guess ho sakta hai
function safeCompare(a, b) {
  const bufA = Buffer.from(String(a || ''));
  const bufB = Buffer.from(String(b || ''));
  if (bufA.length !== bufB.length) {
    // Length leak na ho isliye bhi same-length dummy compare karo
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

// Admin Login - JWT token milega
app.post('/api/admin/login', (req, res) => {
  // Agar .env mein admin credentials set hi nahi hain, to login hamesha
  // reject karo - warna khaali username/password bhi match ho sakta tha
  if (!ADMIN_USERNAME || !ADMIN_PASSWORD || !JWT_SECRET) {
    console.error('❌ ADMIN_USERNAME / ADMIN_PASSWORD / JWT_SECRET .env mein set nahi hain.');
    return res.status(500).json({ error: 'Admin login configured nahi hai. .env check karein.' });
  }
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(401).json({ error: 'Username ya password galat hai.' });
  if (!safeCompare(username, ADMIN_USERNAME) || !safeCompare(password, ADMIN_PASSWORD))
    return res.status(401).json({ error: 'Username ya password galat hai.' });
  const token = jwt.sign({ role: 'admin', username }, JWT_SECRET, { expiresIn: '8h' });
  res.json({ token });
});

app.get('/api/admin/stats', adminAuth, async (req, res) => {
  try {
    const totalUsers   = await User.countDocuments();
    const totalResults = await Result.countDocuments();
    const allResults   = await Result.find().lean();
    const avgWpm = totalResults ? Math.round(allResults.reduce((s, r) => s + r.wpm, 0) / totalResults) : 0;
    const avgAcc = totalResults ? Math.round(allResults.reduce((s, r) => s + r.accuracy, 0) / totalResults) : 0;

    const byUser = {};
    allResults.forEach(r => {
      if (!byUser[r.userId]) byUser[r.userId] = new Set();
      byUser[r.userId].add(r.level);
    });
    const completedAll = Object.values(byUser).filter(s => s.size >= 50).length;

    const levelCounts = Array.from({ length: 50 }, (_, i) => ({
      level: i + 1,
      count: allResults.filter(r => r.level === i + 1).length
    }));

    const todayStart = new Date(); todayStart.setHours(0, 0, 0, 0);
    const activeToday = await Result.distinct('userId', { completedAt: { $gte: todayStart } });
    const weekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const recentSignups = await User.countDocuments({ createdAt: { $gte: weekAgo } });

    res.json({ success: true, stats: {
      totalUsers, totalResults, completedAll,
      startedOnly: Object.keys(byUser).length - completedAll,
      levelCounts, avgWpm, avgAcc,
      activeToday: activeToday.length, recentSignups
    }});
  } catch (err) {
    res.json({ success: false, message: 'Stats load nahi hue.' });
  }
});

app.get('/api/admin/users', adminAuth, async (req, res) => {
  try {
    const { search } = req.query;
    let filter = {};
    if (search) {
      filter.$or = [
        { name:  { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } }
      ];
    }
    const users = await User.find(filter).lean();

    // Har user ke liye alag query chalane ke bajaye (N+1), ek hi aggregation
    // se sab users ke result stats nikalo
    const userIds = users.map(u => u._id);
    const statsAgg = await Result.aggregate([
      { $match: { userId: { $in: userIds } } },
      { $group: {
        _id: '$userId',
        totalTests: { $sum: 1 },
        levels: { $addToSet: '$level' },
        bestWpm: { $max: '$wpm' }
      }}
    ]);
    const statsMap = {};
    statsAgg.forEach(s => {
      statsMap[s._id.toString()] = {
        totalTests: s.totalTests,
        levelsCompleted: s.levels.length,
        bestWpm: s.bestWpm
      };
    });

    const data = users.map(u => {
      const stats = statsMap[u._id.toString()] || { totalTests: 0, levelsCompleted: 0, bestWpm: 0 };
      return {
        id: u._id, name: u.name, email: u.email,
        isAdmin: u.isAdmin || false,
        createdAt: u.createdAt,
        totalTests: stats.totalTests, levelsCompleted: stats.levelsCompleted, bestWpm: stats.bestWpm
      };
    });
    res.json({ success: true, users: data });
  } catch (err) {
    res.json({ success: false, users: [] });
  }
});

app.get('/api/admin/results', adminAuth, async (req, res) => {
  try {
    const results = await Result.find().sort({ completedAt: -1 }).limit(200).lean();
    res.json({ success: true, results });
  } catch (err) {
    res.json({ success: false, results: [] });
  }
});

app.delete('/api/admin/users/:id', adminAuth, async (req, res) => {
  try {
    await User.findByIdAndDelete(req.params.id);
    await Result.deleteMany({ userId: req.params.id });
    res.json({ success: true, message: 'User aur uske results delete ho gaye.' });
  } catch (err) {
    res.json({ success: false, message: 'Delete nahi hua.' });
  }
});

app.delete('/api/admin/results/:userId', adminAuth, async (req, res) => {
  try {
    await Result.deleteMany({ userId: req.params.userId });
    res.json({ success: true, message: 'Results reset ho gaye.' });
  } catch (err) {
    res.json({ success: false, message: 'Reset nahi hua.' });
  }
});

// Toggle Admin (isAdmin flag)
app.post('/api/admin/toggle-admin/:id', adminAuth, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.json({ success: false, message: 'User nahi mila.' });
    user.isAdmin = !user.isAdmin;
    await user.save();
    res.json({ success: true, message: user.isAdmin ? 'Admin ban gaya.' : 'Admin rights hat gaye.', isAdmin: user.isAdmin });
  } catch (err) {
    res.json({ success: false, message: 'Toggle nahi hua.' });
  }
});

app.put('/api/admin/users/:id/reset-password', adminAuth, async (req, res) => {
  try {
    const { newPassword } = req.body;
    if (!newPassword || newPassword.length < 8)
      return res.json({ success: false, message: 'Password kam az kam 8 characters ka hona chahiye.' });
    const passRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$/;
    if (!passRegex.test(newPassword))
      return res.json({ success: false, message: 'Password mein 1 capital, 1 small, 1 number aur 1 special character (!@#$%^&*) hona chahiye.' });
    const hashed = await bcrypt.hash(newPassword, 10);
    await User.findByIdAndUpdate(req.params.id, { password: hashed });
    res.json({ success: true, message: 'Password reset ho gaya.' });
  } catch (err) {
    res.json({ success: false, message: 'Reset nahi hua.' });
  }
});

// ─── START ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`✅ Typing Master chal raha hai: http://localhost:${PORT}`);
  console.log(`🛡️  Admin Panel: http://localhost:${PORT}/admin-panel`);
});
