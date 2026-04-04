import express from 'express';
import bodyParser from 'body-parser';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

const app = express();
const port = process.env.PORT || 3000;

app.set('view engine', 'ejs');
app.set('views', './');
app.use(express.static('.'));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

let posts = [];
let nextId = 1;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const dataDir = path.join(__dirname, 'data');
const dataFile = path.join(dataDir, 'posts.json');

function normalizeName(value) {
  return String(value || '').trim().toLowerCase();
}

function getSafeRedirectPath(value, fallback = '/') {
  const pathValue = String(value || '').trim();
  if (pathValue.startsWith('/') && !pathValue.startsWith('//')) {
    return pathValue;
  }

  return fallback;
}

function parseCookies(cookieHeader = '') {
  return cookieHeader
    .split(';')
    .map(part => part.trim())
    .filter(Boolean)
    .reduce((acc, pair) => {
      const [rawKey, ...rawValueParts] = pair.split('=');
      if (!rawKey) {
        return acc;
      }

      const key = decodeURIComponent(rawKey.trim());
      const value = decodeURIComponent(rawValueParts.join('=').trim());
      acc[key] = value;
      return acc;
    }, {});
}

function getCurrentUser(req) {
  const cookies = parseCookies(req.headers.cookie || '');
  return (cookies.currentUser || '').trim();
}

function getOwnerId(req) {
  const cookies = parseCookies(req.headers.cookie || '');
  return (cookies.ownerId || '').trim();
}

function isPostAuthor(post, currentUser) {
  const postAuthor = normalizeName(post?.author);
  const activeUser = normalizeName(currentUser);
  return Boolean(postAuthor) && postAuthor === activeUser;
}

function isPostOwner(post, ownerId) {
  return Boolean(post?.ownerId) && Boolean(ownerId) && post.ownerId === ownerId;
}

function canManagePost(post, ownerId, currentUser) {
  return isPostOwner(post, ownerId) && isPostAuthor(post, currentUser);
}

function normalizePostContent(content) {
  return String(content || '')
    .replace(/\u00A0/g, ' ')
    .replace(/\r\n/g, '\n')
    .replace(/^\s+/, '')
    .replace(/\n[ \t]+/g, '\n');
}

function withPermissions(post, ownerId, currentUser, legacyClaimEnabled) {
  const canManage = canManagePost(post, ownerId, currentUser);
  const canClaimLegacy =
    !post.ownerId &&
    legacyClaimEnabled &&
    isPostAuthor(post, currentUser);

  return {
    ...post,
    canManage,
    canClaimLegacy
  };
}

function loadPosts() {
  try {
    if (!fs.existsSync(dataFile)) {
      return;
    }

    const rawData = fs.readFileSync(dataFile, 'utf8');
    if (!rawData.trim()) {
      return;
    }

    const saved = JSON.parse(rawData);
    posts = Array.isArray(saved.posts) ? saved.posts : [];
    posts = posts.map(post => ({
      ...post,
      date: post.date ? new Date(post.date) : new Date(),
      comments: Array.isArray(post.comments)
        ? post.comments.map(comment => ({
            ...comment,
            date: comment.date ? new Date(comment.date) : new Date()
          }))
        : []
    }));

    const maxId = posts.reduce((max, post) => Math.max(max, Number(post.id) || 0), 0);
    nextId = Number(saved.nextId) > maxId ? Number(saved.nextId) : maxId + 1;
  } catch (error) {
    console.error('Failed to load persisted posts:', error.message);
  }
}

function savePosts() {
  try {
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }

    const payload = JSON.stringify({ posts, nextId }, null, 2);
    fs.writeFileSync(dataFile, payload, 'utf8');
  } catch (error) {
    console.error('Failed to save posts:', error.message);
  }
}

loadPosts();

app.use((req, res, next) => {
  // Ensure user-switch changes are reflected immediately in rendered HTML.
  res.set('Cache-Control', 'no-store');
  next();
});

app.use((req, res, next) => {
  res.locals.currentUser = getCurrentUser(req);
  res.locals.legacyClaimEnabled = Boolean(process.env.LEGACY_CLAIM_CODE);
  const ownerId = getOwnerId(req);

  if (ownerId) {
    res.locals.ownerId = ownerId;
    next();
    return;
  }

  const generatedOwnerId = crypto.randomUUID();
  res.cookie('ownerId', generatedOwnerId, { httpOnly: true, sameSite: 'lax', path: '/' });
  res.locals.ownerId = generatedOwnerId;
  next();
});

app.get('/login', (req, res) => {
  const nextPath = getSafeRedirectPath(req.query.next, '/');
  res.render('login', { nextPath, loginError: '' });
});

app.post('/login', (req, res) => {
  const currentUser = String(req.body.currentUser || '').trim();
  const nextPath = getSafeRedirectPath(req.body.nextPath, '/');

  if (!currentUser) {
    return res.status(400).render('login', {
      nextPath,
      loginError: 'Please enter your author name to continue.'
    });
  }

  res.cookie('currentUser', currentUser, { httpOnly: true, sameSite: 'lax', path: '/' });
  return res.redirect(303, nextPath);
});

app.post('/logout', (req, res) => {
  const redirectTo = getSafeRedirectPath(req.body.redirectTo, '/');
  res.clearCookie('currentUser', { path: '/' });
  return res.redirect(303, redirectTo);
});

app.post('/set-user', (req, res) => {
  const currentUser = String(req.body.currentUser || '').trim();
  const redirectTo = getSafeRedirectPath(req.body.redirectTo, '/');

  if (!currentUser) {
    res.clearCookie('currentUser', { path: '/' });
    return res.redirect(303, redirectTo);
  }

  res.cookie('currentUser', currentUser, { httpOnly: true, sameSite: 'lax', path: '/' });
  return res.redirect(303, redirectTo);
});

app.post('/claim-legacy/:id', (req, res) => {
  const id = parseInt(req.params.id, 10);
  const { claimCode, redirectTo } = req.body;
  const post = posts.find(p => p.id === id);
  const destination = getSafeRedirectPath(redirectTo, '/');
  const expectedClaimCode = String(process.env.LEGACY_CLAIM_CODE || '');
  const providedClaimCode = String(claimCode || '').trim();

  if (!post) {
    return res.status(404).send('Post not found');
  }

  if (post.ownerId) {
    return res.status(400).send('Post ownership is already claimed.');
  }

  if (!expectedClaimCode) {
    return res.status(503).send('Legacy claiming is disabled.');
  }

  if (providedClaimCode !== expectedClaimCode) {
    return res.status(403).send('Invalid legacy claim code.');
  }

  if (!isPostAuthor(post, res.locals.currentUser)) {
    return res.status(403).send('Only the matching legacy author can claim this post.');
  }

  post.ownerId = res.locals.ownerId;
  savePosts();
  return res.redirect(destination);
});

app.get('/', (req, res) => {
  const postsWithPermissions = posts.map(post =>
    withPermissions(
      post,
      res.locals.ownerId,
      res.locals.currentUser,
      res.locals.legacyClaimEnabled
    )
  );

  res.render('index', { posts: postsWithPermissions });
});

app.post('/', (req, res) => {
  const { title, content, imageUrl, hashtags, author } = req.body;
  if (title && content) {
    posts.push({
      id: nextId++,
      title,
      content,
      author: author ? author.trim() : '',
      ownerId: res.locals.ownerId || '',
      imageUrl: imageUrl || null,
      hashtags: hashtags ? hashtags.split(' ').filter(tag => tag.trim()) : [],
      date: new Date(),
      views: 0,
      likes: 0,
      comments: []
    });
    savePosts();
  }
  res.redirect('/');
});

app.post('/like/:id', (req, res) => {
  const id = parseInt(req.params.id, 10);
  const post = posts.find(p => p.id === id);
  if (post) {
    post.likes = (post.likes || 0) + 1;
    savePosts();
  }
  res.redirect('/');
});

app.post('/comment/:id', (req, res) => {
  const id = parseInt(req.params.id, 10);
  const { name, text } = req.body;
  const post = posts.find(p => p.id === id);
  if (post && name && text) {
    if (!post.comments) post.comments = [];
    post.comments.push({ name, text, date: new Date() });
    savePosts();
  }
  res.redirect('/');
});

app.post('/view/:id', (req, res) => {
  const id = parseInt(req.params.id, 10);
  const post = posts.find(p => p.id === id);
  if (post) {
    post.views = (post.views || 0) + 1;
    savePosts();
  }
  res.json({ views: post?.views || 0 });
});

app.get('/post/:id', (req, res) => {
  const id = parseInt(req.params.id, 10);
  const post = posts.find(p => p.id === id);
  if (post) {
    const postWithPermissions = withPermissions(
      post,
      res.locals.ownerId,
      res.locals.currentUser,
      res.locals.legacyClaimEnabled
    );

    res.render('post', {
      post: postWithPermissions,
      displayContent: normalizePostContent(post.content)
    });
  } else {
    res.status(404).redirect('/');
  }
});

app.get('/edit/:id', (req, res) => {
  const id = parseInt(req.params.id, 10);
  const post = posts.find(p => p.id === id);
  if (!post) {
    res.status(404).send('Post not found');
    return;
  }

  if (!canManagePost(post, res.locals.ownerId, res.locals.currentUser)) {
    res.status(403).send('Only the author can edit this post.');
    return;
  }

  res.render('edit', { post });
});

app.post('/edit/:id', (req, res) => {
  const id = parseInt(req.params.id, 10);
  const { title, content, imageUrl, hashtags } = req.body;
  const post = posts.find(p => p.id === id);

  if (!post) {
    return res.status(404).send('Post not found');
  }

  if (!canManagePost(post, res.locals.ownerId, res.locals.currentUser)) {
    return res.status(403).send('Only the author can edit this post.');
  }

  if (title && content) {
    post.title = title;
    post.content = content;
    post.imageUrl = imageUrl || null;
    post.hashtags = hashtags ? hashtags.split(' ').filter(tag => tag.trim()) : [];
    savePosts();
  }

  res.redirect('/');
});

app.post('/delete/:id', (req, res) => {
  const id = parseInt(req.params.id, 10);
  const post = posts.find(p => p.id === id);

  if (!post) {
    return res.status(404).send('Post not found');
  }

  if (!canManagePost(post, res.locals.ownerId, res.locals.currentUser)) {
    return res.status(403).send('Only the author can delete this post.');
  }

  console.log(`Deleting post ${id}`);
  posts = posts.filter(p => p.id !== id);
  savePosts();
  return res.redirect('/');
});

app.get('/delete/:id', (req, res) => {
  const id = parseInt(req.params.id, 10);
  const post = posts.find(p => p.id === id);

  if (!post) {
    return res.status(404).send('Post not found');
  }

  if (!canManagePost(post, res.locals.ownerId, res.locals.currentUser)) {
    return res.status(403).send('Only the author can delete this post.');
  }

  console.log(`GET delete post ${id}`);
  posts = posts.filter(p => p.id !== id);
  savePosts();
  return res.redirect('/');
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
  console.log('Available routes:');
  console.log('  GET  /');
  console.log('  GET  /login');
  console.log('  POST /login');
  console.log('  POST /logout');
  console.log('  POST /');
  console.log('  POST /set-user');
  console.log('  POST /claim-legacy/:id');
  console.log('  GET  /edit/:id');
  console.log('  POST /edit/:id');
  console.log('  POST /delete/:id');
  console.log('  GET  /delete/:id');
});
