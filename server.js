import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import mysql from 'mysql2/promise';
import bcrypt from 'bcryptjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const args = process.argv.slice(2);
let port = 3000;
let host = '0.0.0.0';

for (let i = 0; i < args.length; i++) {
  if (args[i] === '--port' && args[i + 1]) {
    port = parseInt(args[i + 1], 10) || 3000;
    i++;
  } else if (args[i] === '--host' && args[i + 1]) {
    host = args[i + 1];
    i++;
  }
}

if (port === 8080 || !port) {
  port = 3000;
}

// MySQL Connection Pools for Real Database
const bfPool = mysql.createPool({
  host: 'mysql-secretsqlhoster.alwaysdata.net',
  port: 3306,
  user: 'secretsqlhoster',
  password: 'dhakool123',
  database: 'secretsqlhoster_betterformus',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  enableKeepAlive: true,
  keepAliveInitialDelay: 10000
});

const bcPool = mysql.createPool({
  host: 'mysql-secretsqlhoster.alwaysdata.net',
  port: 3306,
  user: 'secretsqlhoster',
  password: 'dhakool123',
  database: 'secretsqlhoster_betterchat',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  enableKeepAlive: true,
  keepAliveInitialDelay: 10000
});

// Helper: Parse JSON or Form Body
function parseBody(req) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', chunk => { data += chunk; });
    req.on('end', () => {
      if (!data) return resolve({});
      try {
        resolve(JSON.parse(data));
      } catch {
        // Fallback for urlencoded
        const params = new URLSearchParams(data);
        const obj = {};
        for (const [k, v] of params.entries()) {
          obj[k] = v;
        }
        resolve(obj);
      }
    });
  });
}

// Extract Authenticated User from Token
async function resolveAuthUser(req, body) {
  let token = '';
  const authHeader = req.headers['authorization'] || '';
  if (authHeader.startsWith('Bearer ')) {
    token = authHeader.substring(7).trim();
  } else if (authHeader) {
    token = authHeader.trim();
  } else if (body && body.token) {
    token = String(body.token).trim();
  } else if (req.headers['cookie']) {
    const cookies = req.headers['cookie'].split(';');
    for (const c of cookies) {
      const [k, v] = c.trim().split('=');
      if (k === 'BF_AUTH_SAFE' && v) {
        token = decodeURIComponent(v);
        break;
      }
    }
  }

  if (!token) return null;

  try {
    const decoded = Buffer.from(token, 'base64').toString('utf8');
    const parts = decoded.split(':');
    if (parts.length >= 2) {
      const username = parts[0];
      const hash = parts[1];
      const [rows] = await bfPool.query('SELECT * FROM users WHERE username = ?', [username]);
      if (rows.length > 0) {
        const user = rows[0];
        const computedMd5 = crypto.createHash('md5').update(user.password_hash || '').digest('hex');
        if (computedMd5 === hash) {
          const isSuper = user.username.toLowerCase() === 'gollclock';
          const isOwner = user.role === 'OWNER' || isSuper;
          const isAdmin = user.role === 'ADMIN' || !!user.is_admin || isOwner;
          const isMod = user.role === 'MOD' || !!user.is_mod || isAdmin;
          return {
            ...user,
            is_owner: isOwner,
            is_admin: isAdmin,
            is_mod: isMod,
            is_staff: isMod
          };
        }
      }
    }
  } catch (err) {
    console.error('Auth decode error:', err);
  }
  return null;
}

// Sanitize output object to remove `null` values and replace with defaults
function cleanNulls(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  const out = Array.isArray(obj) ? [] : {};
  for (const [k, v] of Object.entries(obj)) {
    if (v === null || v === undefined) {
      if (k.endsWith('_url') || k === 'image_url' || k === 'link_url') out[k] = '';
      else if (k === 'flair' || k === 'custom_badge' || k === 'status_flair' || k === 'bio' || k === 'avatar_data') out[k] = '';
      else if (k === 'name_color') out[k] = '#94a3b8';
      else if (k === 'username' || k === 'display_name') out[k] = 'deleted_user';
      else if (k === 'sub_name') out[k] = 'general';
      else out[k] = '';
    } else if (typeof v === 'object' && !(v instanceof Date)) {
      out[k] = cleanNulls(v);
    } else {
      out[k] = v;
    }
  }
  return out;
}

// MIME Types Map
const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml',
  '.webp': 'image/webp',
  '.webm': 'audio/webm',
  '.mp3': 'audio/mpeg',
  '.wav': 'audio/wav',
  '.ico': 'image/x-icon'
};

// Main API Handler
async function handleApi(req, res, parsedUrl) {
  res.setHeader('Content-Type', 'application/json');
  const body = req.method === 'POST' ? await parseBody(req) : {};
  const action = parsedUrl.searchParams.get('action') || body.action || '';
  const currentUser = await resolveAuthUser(req, body);

  // 1. PING & SYSTEM INFO
  if (action === 'ping' || action === 'get_system_info') {
    try {
      await bfPool.query('UPDATE system_config SET hit_counter = hit_counter + 1 WHERE id = 1');
      const [cfgRows] = await bfPool.query('SELECT hit_counter, announcement_banner, maintenance, maintenance_msg FROM system_config WHERE id = 1');
      const cfg = cfgRows[0] || { hit_counter: 1, announcement_banner: '', maintenance: 0, maintenance_msg: '' };

      const [motdRows] = await bfPool.query('SELECT message_text FROM motd_pool ORDER BY RAND() LIMIT 1');
      const motd = motdRows.length > 0 ? motdRows[0].message_text : 'Welcome to BetterForums - The Front Page of the Web!';

      return res.end(JSON.stringify({
        ok: true,
        database: 'secretsqlhoster_betterformus',
        hit_counter: cfg.hit_counter,
        announcement_banner: cfg.announcement_banner || '',
        maintenance: cfg.maintenance,
        maintenance_msg: cfg.maintenance_msg || '',
        motd,
        time: Date.now(),
        server_time: new Date().toISOString()
      }));
    } catch (e) {
      return res.end(JSON.stringify({ ok: true, hit_counter: 100, database: 'secretsqlhoster_betterformus', time: Date.now() }));
    }
  }

  // 2. AUTH CHECK & GET ME
  if (action === 'auth_check' || action === 'get_me') {
    if (!currentUser) {
      return res.end(JSON.stringify({ ok: false, error: 'Not authenticated', user: null }));
    }
    const uid = currentUser.id;
    const [pkRows] = await bfPool.query(
      `SELECT COALESCE(SUM(uv.vote_type), 0) as post_karma FROM user_votes uv JOIN posts p ON uv.target_id = p.id WHERE uv.target_type = 'post' AND p.user_id = ? AND p.is_deleted = 0`,
      [uid]
    );
    const [ckRows] = await bfPool.query(
      `SELECT COALESCE(SUM(uv.vote_type), 0) as comment_karma FROM user_votes uv JOIN comments c ON uv.target_id = c.id WHERE uv.target_type = 'comment' AND c.user_id = ? AND c.is_deleted = 0`,
      [uid]
    );
    const postKarma = parseInt(pkRows[0]?.post_karma, 10) || 0;
    const commentKarma = parseInt(ckRows[0]?.comment_karma, 10) || 0;

    return res.end(JSON.stringify({
      ok: true,
      user: cleanNulls({
        id: currentUser.id,
        username: currentUser.username,
        display_name: currentUser.display_name || currentUser.username,
        role: currentUser.role,
        custom_badge: currentUser.custom_badge || '',
        status_flair: currentUser.status_flair || '',
        avatar_data: currentUser.avatar_data || '',
        bio: currentUser.bio || '',
        name_color: currentUser.name_color || '#94a3b8',
        theme: currentUser.theme || 'dark',
        is_owner: !!currentUser.is_owner,
        is_admin: !!currentUser.is_admin,
        is_mod: !!currentUser.is_mod,
        post_karma: postKarma,
        comment_karma: commentKarma,
        total_karma: postKarma + commentKarma
      })
    }));
  }

  // 3. LOGIN
  if (action === 'login') {
    const username = (body.username || '').trim();
    const password = body.password || '';
    if (!username || !password) {
      return res.end(JSON.stringify({ ok: false, error: 'Username and password are required.' }));
    }

    const [rows] = await bfPool.query('SELECT * FROM users WHERE username = ?', [username]);
    if (rows.length === 0) {
      return res.end(JSON.stringify({ ok: false, error: 'Incorrect username or password.' }));
    }

    const user = rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.end(JSON.stringify({ ok: false, error: 'Incorrect username or password.' }));
    }

    const md5Hash = crypto.createHash('md5').update(user.password_hash).digest('hex');
    const token = Buffer.from(`${user.username}:${md5Hash}`).toString('base64');

    const uid = user.id;
    const [pkRows] = await bfPool.query(
      `SELECT COALESCE(SUM(uv.vote_type), 0) as post_karma FROM user_votes uv JOIN posts p ON uv.target_id = p.id WHERE uv.target_type = 'post' AND p.user_id = ? AND p.is_deleted = 0`,
      [uid]
    );
    const [ckRows] = await bfPool.query(
      `SELECT COALESCE(SUM(uv.vote_type), 0) as comment_karma FROM user_votes uv JOIN comments c ON uv.target_id = c.id WHERE uv.target_type = 'comment' AND c.user_id = ? AND c.is_deleted = 0`,
      [uid]
    );
    const pk = parseInt(pkRows[0]?.post_karma, 10) || 0;
    const ck = parseInt(ckRows[0]?.comment_karma, 10) || 0;

    const isSuper = user.username.toLowerCase() === 'gollclock';
    const isOwner = user.role === 'OWNER' || isSuper;
    const isAdmin = user.role === 'ADMIN' || !!user.is_admin || isOwner;
    const isMod = user.role === 'MOD' || !!user.is_mod || isAdmin;

    return res.end(JSON.stringify({
      ok: true,
      token,
      user: cleanNulls({
        id: user.id,
        username: user.username,
        display_name: user.display_name || user.username,
        role: user.role,
        custom_badge: user.custom_badge || '',
        status_flair: user.status_flair || '',
        avatar_data: user.avatar_data || '',
        bio: user.bio || '',
        name_color: user.name_color || '#94a3b8',
        theme: user.theme || 'dark',
        is_owner: isOwner,
        is_admin: isAdmin,
        is_mod: isMod,
        post_karma: pk,
        comment_karma: ck,
        total_karma: pk + ck
      })
    }));
  }

  // 4. REGISTER
  if (action === 'register') {
    const username = (body.username || '').trim();
    const password = body.password || '';
    if (!username || !password) {
      return res.end(JSON.stringify({ ok: false, error: 'Username and password are required.' }));
    }
    if (username.length < 3 || username.length > 30) {
      return res.end(JSON.stringify({ ok: false, error: 'Username must be between 3 and 30 characters.' }));
    }
    if (password.length < 4) {
      return res.end(JSON.stringify({ ok: false, error: 'Password must be at least 4 characters.' }));
    }

    const [existing] = await bfPool.query('SELECT id FROM users WHERE username = ?', [username]);
    if (existing.length > 0) {
      return res.end(JSON.stringify({ ok: false, error: 'That username is already taken. Please choose another.' }));
    }

    const hash = await bcrypt.hash(password, 10);
    const isSuper = username.toLowerCase() === 'gollclock';
    const role = isSuper ? 'OWNER' : 'USER';
    const badge = isSuper ? 'Owner' : '';
    const isAdm = isSuper ? 1 : 0;

    const [insertResult] = await bfPool.query(
      `INSERT INTO users (username, password_hash, role, ip_address, is_shadowbanned, hide_from_search, display_name, bio, avatar_type, avatar_data, status_flair, custom_badge, is_admin, is_mod, theme) VALUES (?, ?, ?, '127.0.0.1', 0, 0, ?, '', 'url', '', '', ?, ?, ?, 'dark')`,
      [username, hash, role, username, badge, isAdm, isAdm]
    );

    const uid = insertResult.insertId;
    const md5Hash = crypto.createHash('md5').update(hash).digest('hex');
    const token = Buffer.from(`${username}:${md5Hash}`).toString('base64');

    return res.end(JSON.stringify({
      ok: true,
      token,
      user: {
        id: uid,
        username,
        display_name: username,
        role,
        custom_badge: badge,
        status_flair: '',
        avatar_data: '',
        bio: '',
        theme: 'dark',
        is_owner: isSuper,
        is_admin: !!isAdm,
        is_mod: !!isAdm,
        total_karma: 0
      }
    }));
  }

  // 5. GET SUBBETTERS
  if (action === 'get_subbetters') {
    const [rows] = await bfPool.query(
      `SELECT s.*, COUNT(p.id) as post_count FROM subbetters s LEFT JOIN posts p ON s.id=p.subbetter_id AND p.is_deleted=0 GROUP BY s.id ORDER BY s.name ASC`
    );
    return res.end(JSON.stringify({
      ok: true,
      subbetters: rows.map(r => cleanNulls({
        id: r.id,
        name: r.name,
        description: r.description || '',
        created_by: r.created_by || 'system',
        created_at: r.created_at,
        is_locked: !!r.is_locked,
        post_count: parseInt(r.post_count, 10) || 0
      }))
    }));
  }

  // 6. CREATE SUBBETTER
  if (action === 'create_sub') {
    const name = (body.name || '').trim().toLowerCase().replace(/[^a-z0-9_]/g, '');
    const description = (body.description || '').trim();
    if (!name) return res.end(JSON.stringify({ ok: false, error: 'Subbetter name is required.' }));

    const [exists] = await bfPool.query('SELECT id FROM subbetters WHERE name = ?', [name]);
    if (exists.length > 0) return res.end(JSON.stringify({ ok: false, error: 'Subbetter already exists.' }));

    const creator = currentUser ? currentUser.username : 'anonymous';
    const [ins] = await bfPool.query(
      'INSERT INTO subbetters (name, description, created_by, is_locked) VALUES (?, ?, ?, 0)',
      [name, description, creator]
    );
    return res.end(JSON.stringify({
      ok: true,
      subbetter: { id: ins.insertId, name, description, created_by: creator, post_count: 0 }
    }));
  }

  // 7. GET FEED (REAL POSTS FROM DATABASE)
  if (action === 'get_feed') {
    const subFilter = parsedUrl.searchParams.get('sub') || parsedUrl.searchParams.get('b') || '';
    const sort = parsedUrl.searchParams.get('sort') || 'hot';
    const search = parsedUrl.searchParams.get('q') || '';
    const uid = currentUser ? currentUser.id : 0;

    let whereSql = 'p.is_deleted = 0';
    const params = [uid, uid];

    if (subFilter && subFilter !== 'all' && subFilter !== 'home') {
      whereSql += ' AND s.name = ?';
      params.push(subFilter);
    }

    if (search) {
      whereSql += ' AND (p.title LIKE ? OR p.content LIKE ? OR u.username LIKE ?)';
      params.push(`%${search}%`, `%${search}%`, `%${search}%`);
    }

    let orderSql = 'p.is_pinned DESC, p.created_at DESC';
    if (sort === 'top') {
      orderSql = 'p.is_pinned DESC, score DESC, p.created_at DESC';
    } else if (sort === 'hot') {
      orderSql = 'p.is_pinned DESC, (score * 10000 + UNIX_TIMESTAMP(p.created_at)) DESC';
    }

    const query = `
      SELECT p.*,
        COALESCE(s.name, 'general') as sub_name,
        COALESCE(u.username, 'deleted_user') as username,
        COALESCE(u.display_name, u.username, 'deleted_user') as display_name,
        COALESCE(u.role, 'USER') as user_role,
        COALESCE(u.custom_badge, '') as custom_badge,
        COALESCE(u.status_flair, '') as status_flair,
        COALESCE(u.avatar_data, '') as avatar_data,
        COALESCE(u.name_color, '#94a3b8') as name_color,
        COALESCE((SELECT SUM(vote_type) FROM user_votes WHERE target_type='post' AND target_id=p.id), 0) as score,
        COALESCE((SELECT vote_type FROM user_votes WHERE target_type='post' AND target_id=p.id AND user_id=?), 0) as user_vote,
        (SELECT COUNT(id) FROM comments WHERE post_id=p.id AND is_deleted=0) as comment_count,
        (SELECT COUNT(id) FROM saved_posts WHERE post_id=p.id AND user_id=?) as is_saved
      FROM posts p
      LEFT JOIN subbetters s ON p.subbetter_id = s.id
      LEFT JOIN users u ON p.user_id = u.id
      WHERE ${whereSql}
      ORDER BY ${orderSql}
      LIMIT 50
    `;

    const [rows] = await bfPool.query(query, params);

    const cleanedPosts = rows.map(r => cleanNulls({
      id: r.id,
      subbetter_id: r.subbetter_id,
      sub_name: r.sub_name || 'general',
      user_id: r.user_id,
      username: r.username || 'deleted_user',
      display_name: r.display_name || r.username || 'deleted_user',
      name_color: r.name_color || '#94a3b8',
      user_role: r.user_role || 'USER',
      custom_badge: r.custom_badge || '',
      status_flair: r.status_flair || '',
      avatar_data: r.avatar_data || '',
      title: r.title || 'Untitled',
      content: r.content || '',
      flair: r.flair || '',
      score: parseInt(r.score, 10) || 0,
      comment_count: parseInt(r.comment_count, 10) || 0,
      image_url: r.image_url && r.image_url !== 'null' ? r.image_url : '',
      is_pinned: !!r.is_pinned,
      user_vote: parseInt(r.user_vote, 10) || 0,
      is_saved: !!r.is_saved,
      created_at: r.created_at
    }));

    return res.end(JSON.stringify({ ok: true, posts: cleanedPosts }));
  }

  // 8. GET SINGLE POST & COMMENTS
  if (action === 'get_post') {
    const pid = parseInt(parsedUrl.searchParams.get('id') || body.id, 10);
    const uid = currentUser ? currentUser.id : 0;

    const [postRows] = await bfPool.query(
      `SELECT p.*,
        COALESCE(s.name, 'general') as sub_name,
        COALESCE(u.username, 'deleted_user') as username,
        COALESCE(u.display_name, u.username, 'deleted_user') as display_name,
        COALESCE(u.role, 'USER') as user_role,
        COALESCE(u.custom_badge, '') as custom_badge,
        COALESCE(u.status_flair, '') as status_flair,
        COALESCE(u.avatar_data, '') as avatar_data,
        COALESCE(u.name_color, '#94a3b8') as name_color,
        COALESCE((SELECT SUM(vote_type) FROM user_votes WHERE target_type='post' AND target_id=p.id), 0) as score,
        COALESCE((SELECT vote_type FROM user_votes WHERE target_type='post' AND target_id=p.id AND user_id=?), 0) as user_vote,
        (SELECT COUNT(id) FROM comments WHERE post_id=p.id AND is_deleted=0) as comment_count,
        (SELECT COUNT(id) FROM saved_posts WHERE post_id=p.id AND user_id=?) as is_saved
      FROM posts p
      LEFT JOIN subbetters s ON p.subbetter_id = s.id
      LEFT JOIN users u ON p.user_id = u.id
      WHERE p.id = ? AND p.is_deleted = 0`,
      [uid, uid, pid]
    );

    if (postRows.length === 0) {
      return res.end(JSON.stringify({ ok: false, error: 'Post not found' }));
    }

    const p = cleanNulls(postRows[0]);
    p.image_url = p.image_url && p.image_url !== 'null' ? p.image_url : '';
    p.score = parseInt(p.score, 10) || 0;
    p.comment_count = parseInt(p.comment_count, 10) || 0;
    p.user_vote = parseInt(p.user_vote, 10) || 0;

    const [commentRows] = await bfPool.query(
      `SELECT c.*,
        COALESCE(u.username, 'deleted_user') as username,
        COALESCE(u.display_name, u.username, 'deleted_user') as display_name,
        COALESCE(u.name_color, '#94a3b8') as name_color,
        COALESCE(u.role, 'USER') as user_role,
        COALESCE(u.custom_badge, '') as custom_badge,
        COALESCE(u.avatar_data, '') as avatar_data,
        COALESCE((SELECT SUM(vote_type) FROM user_votes WHERE target_type='comment' AND target_id=c.id), 0) as score,
        COALESCE((SELECT vote_type FROM user_votes WHERE target_type='comment' AND target_id=c.id AND user_id=?), 0) as user_vote
      FROM comments c
      LEFT JOIN users u ON c.user_id = u.id
      WHERE c.post_id = ? AND c.is_deleted = 0
      ORDER BY c.created_at ASC`,
      [uid, pid]
    );

    const cleanedComments = commentRows.map(c => cleanNulls({
      id: c.id,
      post_id: c.post_id,
      parent_id: c.parent_id,
      user_id: c.user_id,
      username: c.username || 'deleted_user',
      display_name: c.display_name || c.username || 'deleted_user',
      name_color: c.name_color || '#94a3b8',
      user_role: c.user_role || 'USER',
      custom_badge: c.custom_badge || '',
      avatar_data: c.avatar_data || '',
      content: c.content || '',
      score: parseInt(c.score, 10) || 0,
      user_vote: parseInt(c.user_vote, 10) || 0,
      created_at: c.created_at
    }));

    return res.end(JSON.stringify({ ok: true, post: p, comments: cleanedComments }));
  }

  // 9. SUBMIT POST
  if (action === 'submit_post') {
    if (!currentUser) return res.end(JSON.stringify({ ok: false, error: 'You must be logged in to post.' }));
    const subId = parseInt(body.subbetter_id, 10) || 27;
    const title = (body.title || '').trim();
    const content = (body.content || '').trim();
    const flair = (body.flair || '').trim();
    const imageUrl = (body.image_url || '').trim();

    if (!title) return res.end(JSON.stringify({ ok: false, error: 'Post title is required.' }));

    const [resIns] = await bfPool.query(
      `INSERT INTO posts (subbetter_id, user_id, title, content, ip_address, is_deleted, image_url, is_pinned, is_locked, flair)
       VALUES (?, ?, ?, ?, '127.0.0.1', 0, ?, 0, 0, ?)`,
      [subId, currentUser.id, title, content, imageUrl || null, flair]
    );

    const postId = resIns.insertId;
    // Auto-upvote author's post
    await bfPool.query(
      'INSERT INTO user_votes (user_id, target_type, target_id, vote_type) VALUES (?, "post", ?, 1)',
      [currentUser.id, postId]
    );

    return res.end(JSON.stringify({ ok: true, post_id: postId }));
  }

  // 10. SUBMIT COMMENT
  if (action === 'submit_comment') {
    if (!currentUser) return res.end(JSON.stringify({ ok: false, error: 'You must be logged in to comment.' }));
    const postId = parseInt(body.post_id, 10);
    const parentId = body.parent_id ? parseInt(body.parent_id, 10) : null;
    const content = (body.content || '').trim();

    if (!postId || !content) return res.end(JSON.stringify({ ok: false, error: 'Comment content is required.' }));

    const [ins] = await bfPool.query(
      'INSERT INTO comments (post_id, parent_id, user_id, content, ip_address, is_deleted) VALUES (?, ?, ?, ?, "127.0.0.1", 0)',
      [postId, parentId, currentUser.id, content]
    );

    // Auto-upvote comment
    await bfPool.query(
      'INSERT INTO user_votes (user_id, target_type, target_id, vote_type) VALUES (?, "comment", ?, 1)',
      [currentUser.id, ins.insertId]
    );

    return res.end(JSON.stringify({ ok: true, comment_id: ins.insertId }));
  }

  // 11. VOTE
  if (action === 'vote') {
    if (!currentUser) return res.end(JSON.stringify({ ok: false, error: 'Must be logged in to vote.' }));
    const targetType = body.target_type === 'comment' ? 'comment' : 'post';
    const targetId = parseInt(body.target_id, 10);
    const val = parseInt(body.val, 10);

    const [existing] = await bfPool.query(
      'SELECT id, vote_type FROM user_votes WHERE user_id = ? AND target_type = ? AND target_id = ?',
      [currentUser.id, targetType, targetId]
    );

    if (existing.length > 0) {
      if (existing[0].vote_type === val) {
        // Toggle remove vote
        await bfPool.query('DELETE FROM user_votes WHERE id = ?', [existing[0].id]);
      } else {
        // Update vote
        await bfPool.query('UPDATE user_votes SET vote_type = ? WHERE id = ?', [val, existing[0].id]);
      }
    } else {
      // Insert vote
      await bfPool.query(
        'INSERT INTO user_votes (user_id, target_type, target_id, vote_type) VALUES (?, ?, ?, ?)',
        [currentUser.id, targetType, targetId, val]
      );
    }

    const [scoreRows] = await bfPool.query(
      'SELECT COALESCE(SUM(vote_type), 0) as score FROM user_votes WHERE target_type = ? AND target_id = ?',
      [targetType, targetId]
    );
    const newScore = parseInt(scoreRows[0]?.score, 10) || 0;

    return res.end(JSON.stringify({ ok: true, new_score: newScore }));
  }

  // 12. LEADERBOARD
  if (action === 'get_leaderboard') {
    const [rows] = await bfPool.query(`
      SELECT u.id, u.username, u.display_name, u.role, u.custom_badge, u.name_color, u.avatar_data,
        COALESCE((SELECT SUM(vote_type) FROM user_votes uv JOIN posts p ON uv.target_id = p.id WHERE uv.target_type = 'post' AND p.user_id = u.id AND p.is_deleted = 0), 0) as post_karma,
        COALESCE((SELECT SUM(vote_type) FROM user_votes uv JOIN comments c ON uv.target_id = c.id WHERE uv.target_type = 'comment' AND c.user_id = u.id AND c.is_deleted = 0), 0) as comment_karma
      FROM users u
      ORDER BY (post_karma + comment_karma) DESC
      LIMIT 25
    `);

    const leaderboard = rows.map(r => {
      const pk = parseInt(r.post_karma, 10) || 0;
      const ck = parseInt(r.comment_karma, 10) || 0;
      return cleanNulls({
        ...r,
        post_karma: pk,
        comment_karma: ck,
        total_karma: pk + ck
      });
    });

    return res.end(JSON.stringify({ ok: true, leaderboard }));
  }

  // 13. USERS DIRECTORY
  if (action === 'get_users') {
    const [rows] = await bfPool.query(`
      SELECT u.id, u.username, u.display_name, u.role, u.custom_badge, u.status_flair, u.name_color, u.avatar_data, u.created_at,
        COALESCE((SELECT SUM(vote_type) FROM user_votes uv JOIN posts p ON uv.target_id = p.id WHERE uv.target_type = 'post' AND p.user_id = u.id AND p.is_deleted = 0), 0) as post_karma,
        COALESCE((SELECT SUM(vote_type) FROM user_votes uv JOIN comments c ON uv.target_id = c.id WHERE uv.target_type = 'comment' AND c.user_id = u.id AND c.is_deleted = 0), 0) as comment_karma
      FROM users u
      ORDER BY u.id ASC
    `);

    const userList = rows.map(r => {
      const pk = parseInt(r.post_karma, 10) || 0;
      const ck = parseInt(r.comment_karma, 10) || 0;
      return cleanNulls({
        ...r,
        post_karma: pk,
        comment_karma: ck,
        total_karma: pk + ck
      });
    });

    return res.end(JSON.stringify({ ok: true, users: userList }));
  }

  // 14. ADMIN API
  if (action === 'admin_api') {
    const act = body.act || parsedUrl.searchParams.get('act') || '';

    if (act === 'get_stats') {
      const [uCnt] = await bfPool.query('SELECT COUNT(*) as c FROM users');
      const [pCnt] = await bfPool.query('SELECT COUNT(*) as c FROM posts WHERE is_deleted=0');
      const [cCnt] = await bfPool.query('SELECT COUNT(*) as c FROM comments WHERE is_deleted=0');
      const [sCnt] = await bfPool.query('SELECT COUNT(*) as c FROM subbetters');
      const [bCnt] = await bfPool.query('SELECT COUNT(*) as c FROM moderation_actions WHERE action_type="BAN" AND status="APPROVED"');
      const [cfg] = await bfPool.query('SELECT hit_counter FROM system_config WHERE id=1');

      return res.end(JSON.stringify({
        ok: true,
        stats: {
          total_users: uCnt[0].c,
          total_posts: pCnt[0].c,
          total_comments: cCnt[0].c,
          total_channels: sCnt[0].c,
          total_bans: bCnt[0].c,
          hit_counter: cfg[0]?.hit_counter || 1
        }
      }));
    }

    if (act === 'get_users') {
      const [users] = await bfPool.query('SELECT id, username, display_name, role, custom_badge, name_color, is_admin, is_mod FROM users');
      return res.end(JSON.stringify({ ok: true, users: users.map(cleanNulls) }));
    }

    if (act === 'admin_announce') {
      const msg = (body.message || '').trim();
      await bfPool.query('UPDATE system_config SET announcement_banner = ? WHERE id = 1', [msg]);
      return res.end(JSON.stringify({ ok: true }));
    }

    return res.end(JSON.stringify({ ok: true }));
  }

  // ── BETTERCHAT ENDPOINTS ──────────────────────────────────────────────────
  if (action === 'get_channels') {
    const [rows] = await bcPool.query('SELECT * FROM channels ORDER BY position ASC, id ASC');
    return res.end(JSON.stringify({
      ok: true,
      channels: rows.map(r => cleanNulls({
        id: r.id,
        name: r.name,
        type: r.type,
        topic: r.topic || '',
        is_announcement: r.type === 'announcement'
      }))
    }));
  }

  if (action === 'get_messages') {
    const channelName = parsedUrl.searchParams.get('channel') || 'general';
    const [chRows] = await bcPool.query('SELECT id FROM channels WHERE name = ?', [channelName]);
    const channelId = chRows.length > 0 ? chRows[0].id : 1;

    const [rows] = await bcPool.query(
      `SELECT m.*, u.avatar, u.name_color, u.is_admin, u.is_mod, u.is_vip
       FROM messages m
       LEFT JOIN users u ON m.user_id = u.id
       WHERE m.channel_id = ?
       ORDER BY m.id ASC
       LIMIT 100`,
      [channelId]
    );

    const msgs = rows.map(m => cleanNulls({
      id: m.id,
      channel: channelName,
      user_id: m.user_id,
      username: m.username || 'System',
      name_color: m.name_color || '#38bdf8',
      role: m.is_admin ? 'ADMIN' : (m.is_mod ? 'MOD' : 'USER'),
      avatar: m.avatar || '',
      content: m.content || '',
      image_data: m.image_data || '',
      file_data: m.file_data || '',
      file_name: m.file_name || '',
      is_system: !!m.is_system,
      created_at: m.created_at
    }));

    return res.end(JSON.stringify({ ok: true, messages: msgs }));
  }

  if (action === 'send_message') {
    const chName = body.channel || 'general';
    const content = (body.content || '').trim();
    if (!content) return res.end(JSON.stringify({ ok: false, error: 'Content is required' }));

    const [chRows] = await bcPool.query('SELECT id FROM channels WHERE name = ?', [chName]);
    const channelId = chRows.length > 0 ? chRows[0].id : 1;

    const uname = currentUser ? currentUser.username : (body.username || 'guest');
    const uid = currentUser ? currentUser.id : 1;

    const [ins] = await bcPool.query(
      `INSERT INTO messages (channel_id, user_id, username, msg_type, content, is_system) VALUES (?, ?, ?, 'text', ?, 0)`,
      [channelId, uid, uname, content]
    );

    const newMsg = {
      id: ins.insertId,
      channel: chName,
      user_id: uid,
      username: uname,
      name_color: currentUser?.name_color || '#38bdf8',
      role: currentUser?.role || 'USER',
      avatar: currentUser?.avatar_data || '',
      content,
      created_at: new Date().toISOString()
    };

    return res.end(JSON.stringify({ ok: true, message: newMsg }));
  }

  if (action === 'get_members') {
    const [rows] = await bcPool.query('SELECT id, username, name_color, avatar, is_admin, is_mod, is_vip, last_seen FROM users LIMIT 50');
    return res.end(JSON.stringify({
      ok: true,
      members: rows.map(u => cleanNulls({
        ...u,
        is_online: true
      }))
    }));
  }

  if (action === 'get_wordle') {
    const words = ['REACT', 'QUERY', 'FORUM', 'SPEED', 'AUDIO', 'COLOR', 'LOGIN', 'PIXEL', 'TOKEN'];
    const word = words[Math.floor(Date.now() / 86400000) % words.length];
    return res.end(JSON.stringify({ ok: true, word }));
  }

  // Default fallback
  return res.end(JSON.stringify({ ok: true }));
}

// HTTP Server
const server = http.createServer(async (req, res) => {
  // CORS Headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');

  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    return res.end();
  }

  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  let pathname = parsedUrl.pathname;

  // Route API calls
  if (pathname === '/api.php' || pathname === '/BetterForums/api.php' || pathname.startsWith('/api/')) {
    try {
      return await handleApi(req, res, parsedUrl);
    } catch (err) {
      console.error('API Error:', err);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ ok: false, error: err.message }));
    }
  }

  // Root redirects to BetterForums
  if (pathname === '/' || pathname === '') {
    pathname = '/standalone-betterforums/index.html';
  }

  // Static File Serving
  let filePath = path.join(__dirname, decodeURIComponent(pathname));

  // Security check: ensure path is within __dirname
  if (!filePath.startsWith(__dirname)) {
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    return res.end('403 Forbidden');
  }

  // Check if directory
  if (fs.existsSync(filePath) && fs.statSync(filePath).isDirectory()) {
    const candidate = path.join(filePath, 'index.html');
    if (fs.existsSync(candidate)) {
      filePath = candidate;
    }
  }

  if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';
    res.writeHead(200, { 'Content-Type': contentType });
    const stream = fs.createReadStream(filePath);
    stream.pipe(res);
  } else {
    // Fallback: if requesting a route, serve index
    const fallback = path.join(__dirname, 'standalone-betterforums', 'index.html');
    if (fs.existsSync(fallback)) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      fs.createReadStream(fallback).pipe(res);
    } else {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('404 Not Found');
    }
  }
});

server.listen(port, host, () => {
  console.log(`Node.js Dev Server running at http://${host}:${port}`);
  console.log(`Connected to Real AlwaysData MySQL databases: secretsqlhoster_betterformus & secretsqlhoster_betterchat`);
});

process.on('SIGINT', () => {
  server.close();
  process.exit(0);
});

process.on('SIGTERM', () => {
  server.close();
  process.exit(0);
});
