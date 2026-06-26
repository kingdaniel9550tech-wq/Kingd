require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// 1. Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});
const upload = multer({
  storage: new CloudinaryStorage({
    cloudinary,
    params: { folder: 'private-feed' }
  }),
  limits: { fileSize: 5 * 1024 * 1024 }
});

// 2. SQLite on Railway Volume. Falls back to./data.db locally
const DB_PATH = process.env.RAILWAY_VOLUME_MOUNT_PATH
 ? path.join(process.env.RAILWAY_VOLUME_MOUNT_PATH, 'data.db')
  : './data.db';

const db = new sqlite3.Database(DB_PATH);

// 3. Tables
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    is_admin INTEGER DEFAULT 0
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS posts(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    text TEXT,
    image TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);
});

app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', maxAge: 1000 * 60 * 60 * 24 * 7 }
}));

// 4. Guards
const requireAuth = (req, res, next) => req.session.userId? next() : res.redirect('/login');
const requireAdmin = (req, res, next) => req.session.isAdmin? next() : res.status(403).send('403 Forbidden');

// 5. Routes - Users see all posts
app.get('/', requireAuth, (req, res) => {
  db.all('SELECT p.*, u.username FROM posts p JOIN users u ON u.id = p.user_id ORDER BY p.created_at DESC',
    (err, posts) => res.render('index', { posts: posts||[], user: req.session.username, isAdmin: req.session.isAdmin }));
});

// 6. Admin only: Post + Delete
app.post('/post', requireAuth, requireAdmin, upload.single('image'), (req, res) => {
  db.run('INSERT INTO posts (user_id, text, image) VALUES (?,?,?)',
    [req.session.userId, req.body.text||'', req.file?.path||null],
    () => res.redirect('/'));
});
app.post('/delete/:id', requireAuth, requireAdmin, (req, res) => {
  db.get('SELECT image FROM posts WHERE id =?', [req.params.id], (err, row) => {
    if(row?.image) cloudinary.uploader.destroy(row.image.split('/').slice(-2).join('/').split('.')[0]);
  });
  db.run('DELETE FROM posts WHERE id =?', [req.params.id], () => res.redirect('/'));
});

// 7. Auth
app.get('/login', (req, res) => res.render('login', { error: null }));
app.post('/login', async (req, res) => {
  db.get('SELECT * FROM users WHERE username =?', [req.body.username], async (err, user) => {
    if (!user ||!(await bcrypt.compare(req.body.password, user.password)))
      return res.render('login', { error: 'Invalid username or password' });
    req.session.userId = user.id; req.session.username = user.username; req.session.isAdmin =!!user.is_admin;
    res.redirect('/');
  });
});
app.get('/logout', (req, res) => req.session.destroy(() => res.redirect('/login')));

// 8. Admin Panel: Users only
app.get('/admin', requireAuth, requireAdmin, (req, res) => {
  db.all('SELECT id, username FROM users WHERE is_admin = 0 ORDER BY username',
    (err, users) => res.render('admin', { users: users||[], error: null }));
});
app.post('/admin/create', requireAuth, requireAdmin, async (req, res) => {
  const { username, password } = req.body;
  if(!username ||!password) return db.all('SELECT id, username FROM users WHERE is_admin = 0', (e, users) => res.render('admin', { users, error: 'All fields required' }));
  const hash = await bcrypt.hash(password, 10);
  db.run('INSERT INTO users (username, password) VALUES (?,?)', [username, hash], (err) => {
    if (err) db.all('SELECT id, username FROM users WHERE is_admin = 0', (e, users) => res.render('admin', { users, error: 'Username taken' }));
    else res.redirect('/admin');
  });
});
app.post('/admin/delete/:id', requireAuth, requireAdmin, (req, res) => {
  db.run('DELETE FROM users WHERE id =? AND is_admin = 0', [req.params.id], () => res.redirect('/admin'));
});

// 9. First run admin
db.get('SELECT COUNT(*) c FROM users', async (err, {c}) => {
  if(c === 0){
    db.run('INSERT INTO users (username, password, is_admin) VALUES (?,?,1)',
      ['admin', await bcrypt.hash('admin123', 10)]);
    console.log('>> First admin: admin / admin123');
  }
});

app.listen(PORT, () => console.log(`Running on ${PORT}, DB: ${DB_PATH}`));
