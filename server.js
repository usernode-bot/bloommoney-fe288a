const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const verify = require('./lib/verify');

const app = express();
const port = process.env.PORT || 3000;
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const JWT_SECRET = process.env.JWT_SECRET;
const IS_STAGING = process.env.USERNODE_ENV === 'staging';
const BLOOM_ADMIN = process.env.BLOOM_ADMIN_USERNAME || '';
const UNITS = 1_000_000;

// Funding interval: hourly in prod, accelerated (~2 min) in staging so seeded
// history and the next-funding countdown are observable during a preview.
const FUNDING_INTERVAL_MS = IS_STAGING ? 2 * 60 * 1000 : 60 * 60 * 1000;

// Per-day caps applied to Basic-tier users (security layer, Phase 4).
const BASIC_DAILY_TRADE_COUNT = 25;

const PUBLIC_API_PATHS = new Set(['/health', '/favicon.ico', '/oauth/callback']);
const PUBLIC_PREFIXES = ['/explorer-api/'];

app.use(express.json({ limit: '64kb' }));

// ── Security headers ──────────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  // CSP compatible with the Tailwind CDN + the hosted Usernode bridge origin.
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com https://social-vibecoding.usernodelabs.org",
    "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com",
    "connect-src 'self' https://social-vibecoding.usernodelabs.org",
    "img-src 'self' data: https:",
    "frame-ancestors 'self' https://social-vibecoding.usernodelabs.org",
  ].join('; '));
  next();
});

// ── Auth gate ───────────────────────────────────────────────────────────────
app.use((req, res, next) => {
  const token = req.query.token || req.headers['x-usernode-token'];
  if (token && JWT_SECRET) {
    try { req.user = jwt.verify(token, JWT_SECRET); } catch {}
  }
  if (req.method !== 'GET' || req.path.startsWith('/api/')) {
    if (PUBLIC_API_PATHS.has(req.path)) return next();
    if (PUBLIC_PREFIXES.some(p => req.path.startsWith(p))) return next();
    if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
  }
  next();
});

// ── Ban enforcement (Phase 4) ─────────────────────────────────────────────────
// A banned user is blocked from every state-changing request and every /api/*
// call. Reads of the static shell still pass so they see the "banned" UI.
const banCache = new Map(); // user_id -> { banned, ts }
async function isBanned(userId) {
  const c = banCache.get(userId);
  if (c && Date.now() - c.ts < 15000) return c.banned;
  try {
    const { rows } = await pool.query('SELECT is_banned FROM users WHERE user_id=$1', [userId]);
    const banned = !!rows[0]?.is_banned;
    banCache.set(userId, { banned, ts: Date.now() });
    return banned;
  } catch { return false; }
}
app.use(async (req, res, next) => {
  if (!req.user) return next();
  if (req.method === 'GET' && !req.path.startsWith('/api/')) return next();
  if (PUBLIC_API_PATHS.has(req.path)) return next();
  if (PUBLIC_PREFIXES.some(p => req.path.startsWith(p))) return next();
  if (await isBanned(req.user.id)) return res.status(403).json({ error: 'banned' });
  next();
});

// ── Rate limiting (Phase 4) ────────────────────────────────────────────────────
// In-memory token buckets keyed per-user (falling back to IP). Financial and
// verification mutations get a tighter bucket than ordinary reads/writes.
const buckets = new Map();
function rateLimit(key, capacity, refillPerSec) {
  const now = Date.now();
  let b = buckets.get(key);
  if (!b) { b = { tokens: capacity, ts: now }; buckets.set(key, b); }
  b.tokens = Math.min(capacity, b.tokens + (now - b.ts) / 1000 * refillPerSec);
  b.ts = now;
  if (b.tokens < 1) return false;
  b.tokens -= 1;
  return true;
}
const SENSITIVE_RE = /^\/api\/(defi|futures\/positions|markets\/[^/]+\/trade|ico\/[^/]+\/invest|nfts\/mint|verify|holdings|social\/link|zk)/;
app.use((req, res, next) => {
  if (req.method === 'GET') return next();
  if (PUBLIC_PREFIXES.some(p => req.path.startsWith(p))) return next();
  const id = req.user ? `u:${req.user.id}` : `ip:${req.ip}`;
  const sensitive = SENSITIVE_RE.test(req.path);
  const ok = sensitive
    ? rateLimit(`${id}:fin`, 10, 0.5)   // 10 burst, refill 1 / 2s
    : rateLimit(`${id}:gen`, 40, 5);    // 40 burst, refill 5 / s
  if (!ok) return res.status(429).json({ error: 'rate_limited' });
  next();
});
// Periodically evict idle buckets so the map doesn't grow unbounded.
setInterval(() => {
  const now = Date.now();
  for (const [k, b] of buckets) if (now - b.ts > 300000) buckets.delete(k);
}, 300000).unref?.();

// ── Input validation helpers (Phase 4) ─────────────────────────────────────────
function parseAmount(v, { max = 1e15 } = {}) {
  const n = parseFloat(v);
  if (!Number.isFinite(n) || n <= 0 || n > max) return null;
  return n;
}
function validStr(v, max) {
  return typeof v === 'string' && v.length > 0 && v.length <= max;
}
const HTTP_URL_RE = /^https?:\/\//i;

app.get('/health', (_, res) => res.json({ status: 'ok' }));
// ── Helpers ──────────────────────────────────────────────────────────────────

async function upsertUser(u) {
  const isAdmin = !!(BLOOM_ADMIN && u.username === BLOOM_ADMIN);
  await pool.query(`
    INSERT INTO users (user_id, username, usernode_pubkey, is_admin)
    VALUES ($1, $2, $3, $4)
    ON CONFLICT (user_id) DO UPDATE SET
      username = EXCLUDED.username,
      usernode_pubkey = COALESCE(EXCLUDED.usernode_pubkey, users.usernode_pubkey),
      is_admin = users.is_admin OR EXCLUDED.is_admin
  `, [u.id, u.username, u.usernode_pubkey || null, isAdmin]);
}

async function ensureBalances(userId, pubkey) {
  for (const [sym, bal] of [['USDC', 1000000000], ['BLOOM', 100000000], ['ETH', 0], ['BTC', 0]]) {
    await pool.query(
      'INSERT INTO wallet_balances(user_id,token_symbol,balance) VALUES($1,$2,$3) ON CONFLICT DO NOTHING',
      [userId, sym, bal]
    );
  }
  await pool.query('INSERT INTO paper_balances(user_id) VALUES($1) ON CONFLICT DO NOTHING', [userId]);
  if (pubkey) {
    await pool.query(
      "INSERT INTO kyc_verifications(user_id,level,status) VALUES($1,'basic','approved') ON CONFLICT DO NOTHING",
      [userId]
    );
  }
}

const requireWallet = (req, res, next) =>
  req.user?.usernode_pubkey ? next() : res.status(403).json({ error: 'wallet_required' });

async function requireAdmin(req, res, next) {
  try {
    const { rows } = await pool.query('SELECT is_admin FROM users WHERE user_id=$1', [req.user.id]);
    if (!rows[0]?.is_admin) return res.status(403).json({ error: 'forbidden' });
    next();
  } catch (e) { res.status(500).json({ error: e.message }); }
}

const toUnits = v => Math.round(parseFloat(v) * UNITS);
const fromUnits = v => Number(v) / UNITS;

// HTML escaping + address shortening for the server-rendered admin pages.
function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
function shortAddr(a) { return a ? a.slice(0, 6) + '…' + a.slice(-4) : ''; }

// Audit log for admin mutations (Phase 4).
async function logAdmin(adminUserId, actionType, opts = {}) {
  try {
    await pool.query(
      `INSERT INTO admin_actions(admin_user_id,action_type,target_user_id,target_post_id,target_market_id,reason)
       VALUES($1,$2,$3,$4,$5,$6)`,
      [adminUserId, actionType, opts.target_user_id || null, opts.target_post_id || null,
       opts.target_market_id || null, opts.reason || null]
    );
  } catch (e) { console.error('audit err:', e.message); }
}

// Verification tier vocabulary + gating. Single source of truth (Phase 1).
const TIER_RANK = { basic: 0, social: 1, premium: 2 };
function effectiveTier(kyc) {
  if (kyc && kyc.status === 'approved' && TIER_RANK[kyc.level] != null) return kyc.level;
  return 'basic';
}
function tierAllows(level, action) {
  const r = TIER_RANK[level] ?? 0;
  if (action === 'live_futures') return r >= TIER_RANK.social;
  if (action === 'high_leverage') return r >= TIER_RANK.premium;
  return true;
}
function maxLeverageFor(level) {
  if (TIER_RANK[level] >= TIER_RANK.premium) return 20;
  if (TIER_RANK[level] >= TIER_RANK.social) return 5;
  return 1;
}

function featureLimits(tier) {
  return {
    maxHoldings: tier === 'premium' ? 20 : 10,
  };
}

// Per-day Basic-tier trade cap (Phase 4). Returns true when allowed.
async function withinBasicDailyCap(userId, tier) {
  if (tier !== 'basic') return true;
  const { rows } = await pool.query(
    `SELECT COUNT(*)::int AS n FROM transactions
     WHERE user_id=$1 AND created_at > NOW()-INTERVAL '1 day'
       AND type IN ('swap','futures_open','market_trade','ico_invest')`,
    [userId]
  );
  return (rows[0]?.n || 0) < BASIC_DAILY_TRADE_COUNT;
}
async function userTier(userId) {
  const { rows } = await pool.query('SELECT level, status FROM kyc_verifications WHERE user_id=$1', [userId]);
  return effectiveTier(rows[0]);
}
// ── Background price drift + liquidation ─────────────────────────────────────

setInterval(async () => {
  try {
    await pool.query(`
      UPDATE market_prices
      SET price_usd = GREATEST(0.0001, price_usd * (1 + (random() * 0.01 - 0.005))),
          updated_at = NOW()
      WHERE symbol != 'USDC'
    `);
    await pool.query(`
      UPDATE futures_markets
      SET mark_price = GREATEST(0.001, mark_price * (1 + (random() * 0.004 - 0.002))),
          index_price = GREATEST(0.001, index_price * (1 + (random() * 0.004 - 0.002))),
          funding_rate = GREATEST(-0.01, LEAST(0.01, funding_rate + (random() * 0.0002 - 0.0001))),
          updated_at = NOW()
    `);
    await pool.query(`INSERT INTO futures_price_snapshots(market_id, mark_price) SELECT id, mark_price FROM futures_markets`);
    await pool.query(`DELETE FROM futures_price_snapshots WHERE id IN (SELECT id FROM (SELECT id, ROW_NUMBER() OVER (PARTITION BY market_id ORDER BY created_at DESC) AS rn FROM futures_price_snapshots) r WHERE rn > 200)`);
    await runLiquidations();
    await runFunding();
  } catch (e) { console.error('drift err:', e.message); }
}, 30000);

// Force-close any open position whose mark price has crossed its liquidation
// price. Each position is updated under FOR UPDATE so a concurrent manual close
// can't double-settle it (Phase 3 hardening).
async function runLiquidations() {
  const { rows } = await pool.query(`
    SELECT fp.id FROM futures_positions fp
    JOIN futures_markets fm ON fp.market_id = fm.id
    WHERE fp.status='open'
      AND ((fp.side='long' AND fm.mark_price <= fp.liquidation_price)
        OR (fp.side='short' AND fm.mark_price >= fp.liquidation_price))
  `);
  for (const { id } of rows) {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const { rows: [p] } = await client.query(
        "SELECT * FROM futures_positions WHERE id=$1 AND status='open' FOR UPDATE", [id]
      );
      if (!p) { await client.query('ROLLBACK'); continue; }
      await client.query(
        "UPDATE futures_positions SET status='liquidated', realized_pnl=$1, closed_at=NOW() WHERE id=$2",
        [-Number(p.margin), p.id]
      );
      await client.query(
        "INSERT INTO transactions(user_id,type,token_symbol,amount,description) VALUES($1,'futures_pnl','USDC',$2,'Position liquidated')",
        [p.user_id, -Number(p.margin)]
      );
      await client.query('UPDATE futures_markets SET open_interest=GREATEST(0,open_interest-$1) WHERE id=$2', [Number(p.margin), p.market_id]);
      await client.query('COMMIT');
    } catch (e) { await client.query('ROLLBACK'); console.error('liq err:', e.message); }
    finally { client.release(); }
  }
}

// Funding settlement (Phase 3). Markets whose next_funding_at has elapsed pay
// funding to every open position: longs pay shorts when the rate is positive.
async function runFunding() {
  const { rows: due } = await pool.query(
    'SELECT * FROM futures_markets WHERE next_funding_at IS NULL OR next_funding_at <= NOW()'
  );
  for (const m of due) {
    const { rows: positions } = await pool.query(
      "SELECT id FROM futures_positions WHERE market_id=$1 AND status='open'", [m.id]
    );
    for (const { id } of positions) {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const { rows: [p] } = await client.query(
          "SELECT * FROM futures_positions WHERE id=$1 AND status='open' FOR UPDATE", [id]
        );
        if (!p) { await client.query('ROLLBACK'); continue; }
        const rate = Number(m.funding_rate);
        const notional = Number(p.quantity) * Number(m.mark_price); // token units of USD
        // longs pay when rate>0; shorts receive (and vice-versa)
        const sign = p.side === 'long' ? -1 : 1;
        const amount = Math.round(sign * notional * rate * UNITS);
        if (amount !== 0) {
          if (p.mode === 'live') {
            await client.query(
              "INSERT INTO wallet_balances(user_id,token_symbol,balance) VALUES($1,'USDC',$2) ON CONFLICT(user_id,token_symbol) DO UPDATE SET balance=GREATEST(0,wallet_balances.balance+$2), updated_at=NOW()",
              [p.user_id, amount]
            );
          } else {
            await client.query('UPDATE paper_balances SET usdc_balance=GREATEST(0,usdc_balance+$1) WHERE user_id=$2', [amount, p.user_id]);
          }
          await client.query(
            'INSERT INTO funding_payments(position_id,user_id,market_id,amount,rate,mode) VALUES($1,$2,$3,$4,$5,$6)',
            [p.id, p.user_id, m.id, amount, rate, p.mode]
          );
          await client.query(
            "INSERT INTO transactions(user_id,type,token_symbol,amount,description) VALUES($1,'funding','USDC',$2,$3)",
            [p.user_id, amount, `Funding ${m.symbol} @ ${(rate*100).toFixed(4)}%`]
          );
        }
        await client.query('UPDATE futures_positions SET last_funding_at=NOW() WHERE id=$1', [p.id]);
        await client.query('COMMIT');
      } catch (e) { await client.query('ROLLBACK'); console.error('funding err:', e.message); }
      finally { client.release(); }
    }
    await pool.query(
      `UPDATE futures_markets SET last_funding_at=NOW(),
        next_funding_at=NOW() + ($1 || ' milliseconds')::interval WHERE id=$2`,
      [String(FUNDING_INTERVAL_MS), m.id]
    );
  }
}
// ── /api/me ───────────────────────────────────────────────────────────────────

app.get('/api/me', async (req, res) => {
  try {
    await upsertUser(req.user);
    await ensureBalances(req.user.id, req.user.usernode_pubkey);
    const [{ rows: [user] }, { rows: bals }, { rows: [kyc] }, { rows: socialAccounts }] = await Promise.all([
      pool.query('SELECT * FROM users WHERE user_id=$1', [req.user.id]),
      pool.query('SELECT token_symbol, balance FROM wallet_balances WHERE user_id=$1', [req.user.id]),
      pool.query('SELECT * FROM kyc_verifications WHERE user_id=$1', [req.user.id]),
      pool.query('SELECT provider, handle, linked_at FROM social_accounts WHERE user_id=$1 ORDER BY linked_at ASC', [req.user.id]),
    ]);
    res.json({ user, balances: bals, kyc: kyc || null, social_accounts: socialAccounts, feature_limits: featureLimits(effectiveTier(kyc)) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/me', async (req, res) => {
  try {
    const { display_name, bio } = req.body;
    if (display_name != null && String(display_name).length > 80) return res.status(400).json({ error: 'Display name too long' });
    if (bio != null && String(bio).length > 300) return res.status(400).json({ error: 'Bio too long' });
    await pool.query('UPDATE users SET display_name=$1, bio=$2 WHERE user_id=$3',
      [display_name || null, bio || null, req.user.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/profile/:username', async (req, res) => {
  try {
    const { rows: [user] } = await pool.query(
      'SELECT id,user_id,username,display_name,bio,usernode_pubkey,is_admin,created_at FROM users WHERE username=$1',
      [req.params.username]
    );
    if (!user) return res.status(404).json({ error: 'Not found' });
    const [{ rows: [cnts] }, { rows: [kyc] }, { rows: isF }] = await Promise.all([
      pool.query(`SELECT
        (SELECT COUNT(*) FROM posts WHERE user_id=$1 AND deleted=false AND parent_id IS NULL)::int AS post_count,
        (SELECT COUNT(*) FROM follows WHERE following_id=$1)::int AS followers,
        (SELECT COUNT(*) FROM follows WHERE follower_id=$1)::int AS following`, [user.user_id]),
      pool.query('SELECT level, status FROM kyc_verifications WHERE user_id=$1', [user.user_id]),
      pool.query('SELECT 1 FROM follows WHERE follower_id=$1 AND following_id=$2', [req.user.id, user.user_id]),
    ]);
    res.json({ user, counts: cnts, kyc: kyc || null, isFollowing: isF.length > 0 });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Social Feed ───────────────────────────────────────────────────────────────

app.get('/api/feed', async (req, res) => {
  try {
    const tab = req.query.tab || 'global';
    const cursor = req.query.cursor ? parseInt(req.query.cursor) : null;
    const lim = Math.min(parseInt(req.query.limit) || 20, 50);

    let rows;
    if (tab === 'following') {
      const params = [req.user.id, lim];
      const cursorClause = cursor ? `AND p.id < $${params.push(cursor)}` : '';
      ({ rows } = await pool.query(`
        SELECT p.*, (pkv.level = 'premium' AND pkv.status = 'approved') AS is_premium FROM posts p
        LEFT JOIN kyc_verifications pkv ON pkv.user_id = p.user_id
        WHERE p.parent_id IS NULL AND p.deleted = false
          AND (p.user_id = $1 OR p.user_id IN (SELECT following_id FROM follows WHERE follower_id=$1))
          ${cursorClause}
        ORDER BY p.id DESC LIMIT $2
      `, params));
    } else {
      const params = [lim];
      const cursorClause = cursor ? `AND p.id < $${params.push(cursor)}` : '';
      ({ rows } = await pool.query(`
        SELECT p.*, (pkv.level = 'premium' AND pkv.status = 'approved') AS is_premium FROM posts p
        LEFT JOIN kyc_verifications pkv ON pkv.user_id = p.user_id
        WHERE p.parent_id IS NULL AND p.deleted = false ${cursorClause}
        ORDER BY p.id DESC LIMIT $1
      `, params));
    }

    if (rows.length > 0) {
      const { rows: liked } = await pool.query(
        'SELECT post_id FROM post_likes WHERE user_id=$1 AND post_id=ANY($2)',
        [req.user.id, rows.map(r => r.id)]
      );
      const likedSet = new Set(liked.map(r => r.post_id));
      rows = rows.map(r => ({ ...r, liked_by_me: likedSet.has(r.id) }));
    }
    res.json({ posts: rows, nextCursor: rows.length === lim ? rows[rows.length - 1].id : null });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/posts', requireWallet, async (req, res) => {
  try {
    const { content, parent_id } = req.body;
    if (!content || content.length > 280) return res.status(400).json({ error: 'Invalid content' });
    const { rows: [post] } = await pool.query(`
      INSERT INTO posts (user_id, username, content, parent_id) VALUES ($1,$2,$3,$4) RETURNING *
    `, [req.user.id, req.user.username, content, parent_id || null]);
    if (parent_id) {
      await pool.query('UPDATE posts SET reply_count=reply_count+1 WHERE id=$1', [parent_id]);
    }
    res.json({ post });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/posts/:id', async (req, res) => {
  try {
    const { rows: [post] } = await pool.query('SELECT * FROM posts WHERE id=$1 AND deleted=false', [req.params.id]);
    if (!post) return res.status(404).json({ error: 'Not found' });
    const { rows: replies } = await pool.query(
      'SELECT * FROM posts WHERE parent_id=$1 AND deleted=false ORDER BY id ASC', [post.id]
    );
    const { rows: liked } = await pool.query(
      'SELECT 1 FROM post_likes WHERE user_id=$1 AND post_id=$2', [req.user.id, post.id]
    );
    res.json({ post: { ...post, liked_by_me: liked.length > 0 }, replies });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/posts/:id/like', async (req, res) => {
  try {
    const postId = parseInt(req.params.id);
    const { rows: existing } = await pool.query(
      'SELECT 1 FROM post_likes WHERE user_id=$1 AND post_id=$2', [req.user.id, postId]
    );
    if (existing.length > 0) {
      await pool.query('DELETE FROM post_likes WHERE user_id=$1 AND post_id=$2', [req.user.id, postId]);
      await pool.query('UPDATE posts SET like_count=GREATEST(0,like_count-1) WHERE id=$1', [postId]);
      res.json({ liked: false });
    } else {
      await pool.query('INSERT INTO post_likes(post_id,user_id) VALUES($1,$2) ON CONFLICT DO NOTHING', [postId, req.user.id]);
      await pool.query('UPDATE posts SET like_count=like_count+1 WHERE id=$1', [postId]);
      res.json({ liked: true });
    }
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/follow', requireWallet, async (req, res) => {
  try {
    const { username } = req.body;
    const { rows: [target] } = await pool.query('SELECT user_id FROM users WHERE username=$1', [username]);
    if (!target || target.user_id === req.user.id) return res.status(400).json({ error: 'Invalid' });
    await pool.query('INSERT INTO follows(follower_id,following_id) VALUES($1,$2) ON CONFLICT DO NOTHING',
      [req.user.id, target.user_id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/unfollow', async (req, res) => {
  try {
    const { username } = req.body;
    const { rows: [target] } = await pool.query('SELECT user_id FROM users WHERE username=$1', [username]);
    if (!target) return res.status(400).json({ error: 'Invalid' });
    await pool.query('DELETE FROM follows WHERE follower_id=$1 AND following_id=$2', [req.user.id, target.user_id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Balances + Prices ─────────────────────────────────────────────────────────

app.get('/api/balances', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM wallet_balances WHERE user_id=$1', [req.user.id]);
    const { rows: [paper] } = await pool.query('SELECT usdc_balance FROM paper_balances WHERE user_id=$1', [req.user.id]);
    res.json({ balances: rows, paperBalance: paper?.usdc_balance || 0 });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/prices', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM market_prices');
    res.json({ prices: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/price-history', async (req, res) => {
  try {
    const symbol = String(req.query.symbol || '').toUpperCase();
    if (!symbol) return res.status(400).json({ error: 'symbol required' });
    const hours = Math.min(parseInt(req.query.hours) || 24, 168);
    const { rows } = await pool.query(
      `SELECT recorded_at, price_usd::float FROM price_history
       WHERE symbol=$1 AND recorded_at >= NOW() - ($2 * interval '1 hour')
       ORDER BY recorded_at ASC`,
      [symbol, hours]
    );
    res.json({ history: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Investment Holdings ────────────────────────────────────────────────────────

app.get('/api/holdings', async (req, res) => {
  try {
    const { rows: holdings } = await pool.query(
      'SELECT * FROM investment_holdings WHERE user_id=$1 ORDER BY added_at DESC',
      [req.user.id]
    );
    const { rows: prices } = await pool.query('SELECT symbol, price_usd::float FROM market_prices');
    const priceMap = {};
    prices.forEach(p => { priceMap[p.symbol.toUpperCase()] = p.price_usd; });
    res.json({ holdings, prices: priceMap });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/holdings', async (req, res) => {
  try {
    const { asset_name, ticker, asset_type, quantity, purchase_price } = req.body;
    if (!validStr(asset_name, 150)) return res.status(400).json({ error: 'Invalid asset name' });
    if (ticker != null && String(ticker).length > 20) return res.status(400).json({ error: 'Ticker too long' });
    if (!['crypto', 'stock', 'etf', 'other'].includes(asset_type)) return res.status(400).json({ error: 'Invalid asset type' });
    const qty = parseFloat(quantity);
    if (!Number.isFinite(qty) || qty <= 0) return res.status(400).json({ error: 'Invalid quantity' });
    const price = parseFloat(purchase_price);
    if (!Number.isFinite(price) || price < 0) return res.status(400).json({ error: 'Invalid purchase price' });
    const tier = await userTier(req.user.id);
    const limits = featureLimits(tier);
    const { rows: [cnt] } = await pool.query(
      'SELECT COUNT(*)::int AS n FROM investment_holdings WHERE user_id=$1', [req.user.id]
    );
    if ((cnt?.n || 0) >= limits.maxHoldings) {
      return res.status(400).json({ error: `Holdings cap reached (${limits.maxHoldings}). Get Premium tier via zkPassport to increase it.` });
    }
    const tickerUpper = ticker ? String(ticker).toUpperCase().trim() : null;
    const { rows: [holding] } = await pool.query(
      'INSERT INTO investment_holdings(user_id,asset_name,ticker,asset_type,quantity,purchase_price) VALUES($1,$2,$3,$4,$5,$6) RETURNING *',
      [req.user.id, asset_name, tickerUpper, asset_type, qty, price]
    );
    res.json({ holding });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/holdings/:id', async (req, res) => {
  try {
    const { rows: [existing] } = await pool.query(
      'SELECT id FROM investment_holdings WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]
    );
    if (!existing) return res.status(404).json({ error: 'Not found' });
    const { asset_name, ticker, asset_type, quantity, purchase_price } = req.body;
    if (!validStr(asset_name, 150)) return res.status(400).json({ error: 'Invalid asset name' });
    if (ticker != null && String(ticker).length > 20) return res.status(400).json({ error: 'Ticker too long' });
    if (!['crypto', 'stock', 'etf', 'other'].includes(asset_type)) return res.status(400).json({ error: 'Invalid asset type' });
    const qty = parseFloat(quantity);
    if (!Number.isFinite(qty) || qty <= 0) return res.status(400).json({ error: 'Invalid quantity' });
    const price = parseFloat(purchase_price);
    if (!Number.isFinite(price) || price < 0) return res.status(400).json({ error: 'Invalid purchase price' });
    const tickerUpper = ticker ? String(ticker).toUpperCase().trim() : null;
    const { rows: [holding] } = await pool.query(
      'UPDATE investment_holdings SET asset_name=$1,ticker=$2,asset_type=$3,quantity=$4,purchase_price=$5,updated_at=NOW() WHERE id=$6 AND user_id=$7 RETURNING *',
      [asset_name, tickerUpper, asset_type, qty, price, req.params.id, req.user.id]
    );
    res.json({ holding });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/holdings/:id', async (req, res) => {
  try {
    const { rows: [existing] } = await pool.query(
      'SELECT id FROM investment_holdings WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]
    );
    if (!existing) return res.status(404).json({ error: 'Not found' });
    await pool.query('DELETE FROM investment_holdings WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Social Account Linking ────────────────────────────────────────────────────

app.get('/api/social/accounts', async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT id, provider, handle, linked_at FROM social_accounts WHERE user_id=$1 ORDER BY linked_at ASC',
      [req.user.id]
    );
    res.json({ accounts: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/social/link/start', async (req, res) => {
  try {
    const { provider } = req.body;
    if (!verify.isLinkProvider(provider)) return res.status(400).json({ error: 'Invalid provider' });
    const result = verify.startSocialLink(provider, req.user.id);
    res.json(result);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/social/link/complete', async (req, res) => {
  try {
    const { provider, code, state } = req.body;
    if (!verify.isLinkProvider(provider)) return res.status(400).json({ error: 'Invalid provider' });
    const result = await verify.completeSocialLink(provider, code, state);
    if (!result.ok) return res.status(400).json({ error: result.error });
    if (result.user_id !== req.user.id) return res.status(400).json({ error: 'Invalid state' });
    await pool.query(
      `INSERT INTO social_accounts(user_id, provider, provider_user_id, handle)
       VALUES($1,$2,$3,$4)
       ON CONFLICT(user_id, provider) DO UPDATE SET provider_user_id=$3, handle=$4, linked_at=NOW()`,
      [req.user.id, provider, result.provider_user_id, result.handle]
    );
    res.json({ ok: true, provider, handle: result.handle });
  } catch (e) {
    if (e.code === '23505') return res.status(400).json({ error: 'That account is already linked to another user' });
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/social/link/:provider', async (req, res) => {
  try {
    const { provider } = req.params;
    if (!verify.isLinkProvider(provider)) return res.status(400).json({ error: 'Invalid provider' });
    await pool.query(
      'DELETE FROM social_accounts WHERE user_id=$1 AND provider=$2',
      [req.user.id, provider]
    );
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── OAuth popup callback ──────────────────────────────────────────────────────
// Receives the provider redirect, extracts code/state, and postMessages back
// to the opener (which is the BloomMoney iframe). Values are sanitized before
// embedding so no provider-controlled data can escape into script context.

app.get('/oauth/callback', (req, res) => {
  const safeOrigin = 'https://social-vibecoding.usernodelabs.org';
  const code = String(req.query.code || '').replace(/[^a-zA-Z0-9._~-]/g, '').slice(0, 1000);
  const state = String(req.query.state || '').replace(/[^a-zA-Z0-9._~=+/-]/g, '').slice(0, 500);
  const provider = String(req.query.provider || '').replace(/[^a-z]/g, '').slice(0, 20);
  const oauthError = String(req.query.error || '').replace(/[^a-zA-Z0-9_ ]/g, '').slice(0, 200);
  const payload = JSON.stringify({ type: 'oauth_callback', code, state, provider, error: oauthError });
  res.setHeader('Content-Security-Policy', `default-src 'none'; script-src 'unsafe-inline'; frame-ancestors 'self' ${safeOrigin}`);
  res.send(`<!doctype html><html><body><script>
    try { window.opener && window.opener.postMessage(${payload}, '*'); } catch(e) {}
    window.close();
  </script></body></html>`);
});

// ── zkPassport Premium Verification ──────────────────────────────────────────

app.post('/api/zk/start', async (req, res) => {
  try {
    const result = await verify.startZkPassportSession(req.user.id);
    if (!result.ok) return res.status(503).json({ error: result.error });
    res.json({ sessionId: result.sessionId, qrUrl: result.qrUrl, deepLinkUrl: result.deepLinkUrl });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/zk/status/:sessionId', async (req, res) => {
  try {
    const { sessionId } = req.params;
    if (!sessionId || sessionId.length > 300) return res.status(400).json({ error: 'Invalid sessionId' });
    const result = await verify.pollZkPassportSession(sessionId);
    if (result.status === 'verified' && result.nullifier) {
      const nullifier = crypto.createHash('sha256').update(result.nullifier).digest('hex');
      try {
        await pool.query(
          `INSERT INTO zk_verifications(user_id, nullifier) VALUES($1,$2)
           ON CONFLICT(user_id) DO UPDATE SET nullifier=$2, zk_verified_at=NOW()`,
          [req.user.id, nullifier]
        );
        await pool.query(
          `INSERT INTO kyc_verifications(user_id,level,status,provider,attestation_ref,verified_at)
           VALUES($1,'premium','approved','zkpassport',$2,NOW())
           ON CONFLICT(user_id) DO UPDATE SET level='premium', status='approved',
             provider='zkpassport', attestation_ref=$2, verified_at=NOW(), rejection_reason=NULL`,
          [req.user.id, sessionId]
        );
      } catch (dbErr) {
        if (dbErr.code === '23505') return res.status(409).json({ error: 'Passport already used by another account' });
        throw dbErr;
      }
    }
    res.json({ status: result.status });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── DeFi: Swap ────────────────────────────────────────────────────────────────

app.post('/api/defi/swap', requireWallet, async (req, res) => {
  const client = await pool.connect();
  try {
    const { from_token, to_token, from_amount } = req.body;
    const supported = ['USDC', 'BLOOM', 'ETH', 'BTC'];
    if (!supported.includes(from_token) || !supported.includes(to_token) || from_token === to_token)
      return res.status(400).json({ error: 'Invalid tokens' });

    if (parseAmount(from_amount) == null) return res.status(400).json({ error: 'Invalid amount' });
    const fromUnitsAmt = toUnits(from_amount);
    if (fromUnitsAmt <= 0) return res.status(400).json({ error: 'Invalid amount' });

    const tier = await userTier(req.user.id);
    if (!(await withinBasicDailyCap(req.user.id, tier)))
      return res.status(429).json({ error: 'daily_limit', detail: 'Basic tier daily trade limit reached — verify to remove limits.' });
    const { rows: prices } = await client.query('SELECT symbol, price_usd::float FROM market_prices');
    const priceMap = {};
    prices.forEach(p => priceMap[p.symbol] = p.price_usd);

    const rate = priceMap[from_token] / priceMap[to_token];
    const toUnitsAmt = Math.floor(fromUnitsAmt * rate * 0.997);

    await client.query('BEGIN');
    const { rows: [fromBal] } = await client.query(
      'SELECT balance FROM wallet_balances WHERE user_id=$1 AND token_symbol=$2 FOR UPDATE',
      [req.user.id, from_token]
    );
    if (!fromBal || Number(fromBal.balance) < fromUnitsAmt)
      throw new Error('Insufficient balance');

    await client.query(
      'UPDATE wallet_balances SET balance=balance-$1, updated_at=NOW() WHERE user_id=$2 AND token_symbol=$3',
      [fromUnitsAmt, req.user.id, from_token]
    );
    await client.query(
      'UPDATE wallet_balances SET balance=balance+$1, updated_at=NOW() WHERE user_id=$2 AND token_symbol=$3',
      [toUnitsAmt, req.user.id, to_token]
    );
    await client.query(
      'INSERT INTO defi_swaps(user_id,from_token,to_token,from_amount,to_amount,rate) VALUES($1,$2,$3,$4,$5,$6)',
      [req.user.id, from_token, to_token, fromUnitsAmt, toUnitsAmt, rate]
    );
    await client.query(
      "INSERT INTO transactions(user_id,type,token_symbol,amount,description) VALUES($1,'swap',$2,$3,$4)",
      [req.user.id, from_token, -fromUnitsAmt, `Swap ${from_token}→${to_token}`]
    );
    await client.query('COMMIT');
    res.json({ ok: true, to_amount: fromUnits(toUnitsAmt), to_token });
  } catch (e) {
    await client.query('ROLLBACK');
    res.status(400).json({ error: e.message });
  } finally { client.release(); }
});

// ── DeFi: Stake ───────────────────────────────────────────────────────────────

app.get('/api/defi/stakes', async (req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT * FROM defi_stakes WHERE user_id=$1 AND unstaked_at IS NULL ORDER BY staked_at DESC",
      [req.user.id]
    );
    const now = Date.now();
    const stakes = rows.map(s => {
      const elapsed = (now - new Date(s.staked_at).getTime()) / 1000;
      const reward = Math.floor(Number(s.amount) * (s.apy_bps / 10000) * elapsed / 31536000);
      return { ...s, accrued_reward: reward };
    });
    res.json({ stakes });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/defi/stake', requireWallet, async (req, res) => {
  const client = await pool.connect();
  try {
    const amount = toUnits(req.body.amount);
    if (amount <= 0) return res.status(400).json({ error: 'Invalid amount' });
    await client.query('BEGIN');
    const { rows: [bal] } = await client.query(
      "SELECT balance FROM wallet_balances WHERE user_id=$1 AND token_symbol='BLOOM' FOR UPDATE",
      [req.user.id]
    );
    if (!bal || Number(bal.balance) < amount) throw new Error('Insufficient BLOOM');
    await client.query(
      "UPDATE wallet_balances SET balance=balance-$1, updated_at=NOW() WHERE user_id=$2 AND token_symbol='BLOOM'",
      [amount, req.user.id]
    );
    const { rows: [stake] } = await client.query(
      'INSERT INTO defi_stakes(user_id,amount) VALUES($1,$2) RETURNING *', [req.user.id, amount]
    );
    await client.query('COMMIT');
    res.json({ stake });
  } catch (e) {
    await client.query('ROLLBACK');
    res.status(400).json({ error: e.message });
  } finally { client.release(); }
});

app.delete('/api/defi/stakes/:id', async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows: [stake] } = await client.query(
      'SELECT * FROM defi_stakes WHERE id=$1 AND user_id=$2 AND unstaked_at IS NULL FOR UPDATE',
      [req.params.id, req.user.id]
    );
    if (!stake) throw new Error('Stake not found');
    const elapsed = (Date.now() - new Date(stake.staked_at).getTime()) / 1000;
    const reward = Math.floor(Number(stake.amount) * (stake.apy_bps / 10000) * elapsed / 31536000);
    const total = Number(stake.amount) + reward;
    await client.query('UPDATE defi_stakes SET unstaked_at=NOW() WHERE id=$1', [stake.id]);
    await client.query(
      "UPDATE wallet_balances SET balance=balance+$1, updated_at=NOW() WHERE user_id=$2 AND token_symbol='BLOOM'",
      [total, req.user.id]
    );
    await client.query('COMMIT');
    res.json({ ok: true, returned: fromUnits(total), reward: fromUnits(reward) });
  } catch (e) {
    await client.query('ROLLBACK');
    res.status(400).json({ error: e.message });
  } finally { client.release(); }
});

// ── DeFi: Liquidity ────────────────────────────────────────────────────────────

const VALID_POOLS = { BLOOM_USDC: ['BLOOM', 'USDC'], ETH_USDC: ['ETH', 'USDC'] };

app.get('/api/defi/liquidity', async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM defi_liquidity_positions WHERE user_id=$1 AND removed_at IS NULL ORDER BY created_at DESC',
      [req.user.id]
    );
    const now = Date.now();
    const positions = rows.map(p => {
      const days = (now - new Date(p.created_at).getTime()) / 86400000;
      const totalValue = Number(p.token_a_amount) + Number(p.token_b_amount);
      const fees = Math.floor(totalValue * 0.0001 * days);
      return { ...p, accrued_fees: fees };
    });
    res.json({ positions });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/defi/liquidity', requireWallet, async (req, res) => {
  const client = await pool.connect();
  try {
    const { pool_id, token_a_amount, token_b_amount } = req.body;
    if (!VALID_POOLS[pool_id]) return res.status(400).json({ error: 'Invalid pool' });
    const [tokenA, tokenB] = VALID_POOLS[pool_id];
    const amtA = toUnits(token_a_amount);
    const amtB = toUnits(token_b_amount);
    if (amtA <= 0 || amtB <= 0) return res.status(400).json({ error: 'Invalid amounts' });
    await client.query('BEGIN');
    for (const [sym, amt] of [[tokenA, amtA], [tokenB, amtB]]) {
      const { rows: [bal] } = await client.query(
        'SELECT balance FROM wallet_balances WHERE user_id=$1 AND token_symbol=$2 FOR UPDATE',
        [req.user.id, sym]
      );
      if (!bal || Number(bal.balance) < amt) throw new Error(`Insufficient ${sym}`);
      await client.query(
        'UPDATE wallet_balances SET balance=balance-$1, updated_at=NOW() WHERE user_id=$2 AND token_symbol=$3',
        [amt, req.user.id, sym]
      );
    }
    const shares = Math.sqrt(amtA * amtB);
    const { rows: [pos] } = await client.query(
      'INSERT INTO defi_liquidity_positions(user_id,pool_id,token_a_amount,token_b_amount,shares) VALUES($1,$2,$3,$4,$5) RETURNING *',
      [req.user.id, pool_id, amtA, amtB, shares]
    );
    await client.query('COMMIT');
    res.json({ position: pos });
  } catch (e) {
    await client.query('ROLLBACK');
    res.status(400).json({ error: e.message });
  } finally { client.release(); }
});

app.delete('/api/defi/liquidity/:id', async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows: [pos] } = await client.query(
      'SELECT * FROM defi_liquidity_positions WHERE id=$1 AND user_id=$2 AND removed_at IS NULL FOR UPDATE',
      [req.params.id, req.user.id]
    );
    if (!pos) throw new Error('Position not found');
    const days = (Date.now() - new Date(pos.created_at).getTime()) / 86400000;
    const totalValue = Number(pos.token_a_amount) + Number(pos.token_b_amount);
    const fees = Math.floor(totalValue * 0.0001 * days);
    const [tokenA, tokenB] = VALID_POOLS[pos.pool_id];
    await client.query('UPDATE defi_liquidity_positions SET removed_at=NOW() WHERE id=$1', [pos.id]);
    await client.query(
      'UPDATE wallet_balances SET balance=balance+$1, updated_at=NOW() WHERE user_id=$2 AND token_symbol=$3',
      [Number(pos.token_a_amount) + Math.floor(fees / 2), req.user.id, tokenA]
    );
    await client.query(
      'UPDATE wallet_balances SET balance=balance+$1, updated_at=NOW() WHERE user_id=$2 AND token_symbol=$3',
      [Number(pos.token_b_amount) + Math.floor(fees / 2), req.user.id, tokenB]
    );
    await client.query('COMMIT');
    res.json({ ok: true, fees_earned: fromUnits(fees) });
  } catch (e) {
    await client.query('ROLLBACK');
    res.status(400).json({ error: e.message });
  } finally { client.release(); }
});

// ── DeFi: ICO ─────────────────────────────────────────────────────────────────

app.get('/api/ico', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM ico_offerings ORDER BY created_at DESC');
    res.json({ offerings: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/ico/:id/invest', requireWallet, async (req, res) => {
  const client = await pool.connect();
  try {
    const { usdc_amount } = req.body;
    if (parseAmount(usdc_amount) == null) return res.status(400).json({ error: 'Invalid amount' });
    const usdcUnits = toUnits(usdc_amount);
    if (usdcUnits <= 0) return res.status(400).json({ error: 'Invalid amount' });
    const icoTier = await userTier(req.user.id);
    if (!(await withinBasicDailyCap(req.user.id, icoTier)))
      return res.status(429).json({ error: 'daily_limit', detail: 'Basic tier daily trade limit reached — verify to remove limits.' });
    await client.query('BEGIN');
    const { rows: [ico] } = await client.query(
      "SELECT * FROM ico_offerings WHERE id=$1 AND status='active' FOR UPDATE", [req.params.id]
    );
    if (!ico) throw new Error('ICO not available');
    const remaining = Number(ico.hard_cap) - Number(ico.raised);
    const actual = Math.min(usdcUnits, remaining);
    const tokens = Math.floor(actual / Number(ico.price_per_token));
    if (tokens <= 0) throw new Error('ICO is full');
    const { rows: [bal] } = await client.query(
      "SELECT balance FROM wallet_balances WHERE user_id=$1 AND token_symbol='USDC' FOR UPDATE", [req.user.id]
    );
    if (!bal || Number(bal.balance) < actual) throw new Error('Insufficient USDC');
    await client.query("UPDATE wallet_balances SET balance=balance-$1, updated_at=NOW() WHERE user_id=$2 AND token_symbol='USDC'", [actual, req.user.id]);
    await client.query(
      'INSERT INTO wallet_balances(user_id,token_symbol,balance) VALUES($1,$2,$3) ON CONFLICT(user_id,token_symbol) DO UPDATE SET balance=wallet_balances.balance+$3, updated_at=NOW()',
      [req.user.id, ico.token_symbol, tokens]
    );
    await client.query('UPDATE ico_offerings SET raised=raised+$1, tokens_sold=tokens_sold+$2, status=CASE WHEN raised+$1>=hard_cap THEN \'sold_out\' ELSE status END WHERE id=$3', [actual, tokens, ico.id]);
    await client.query('INSERT INTO ico_investments(user_id,ico_id,tokens_purchased,usdc_paid) VALUES($1,$2,$3,$4)', [req.user.id, ico.id, tokens, actual]);
    await client.query(
      "INSERT INTO transactions(user_id,type,token_symbol,amount,description) VALUES($1,'ico_invest','USDC',$2,$3)",
      [req.user.id, -actual, `Invest ${ico.token_symbol} ICO`]
    );
    await client.query('COMMIT');
    res.json({ ok: true, tokens_received: fromUnits(tokens), symbol: ico.token_symbol });
  } catch (e) {
    await client.query('ROLLBACK');
    res.status(400).json({ error: e.message });
  } finally { client.release(); }
});

// ── Opinion Markets ────────────────────────────────────────────────────────────

app.get('/api/markets', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM opinion_markets ORDER BY created_at DESC');
    res.json({ markets: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/markets/:id', async (req, res) => {
  try {
    const { rows: [market] } = await pool.query('SELECT * FROM opinion_markets WHERE id=$1', [req.params.id]);
    if (!market) return res.status(404).json({ error: 'Not found' });
    const { rows: positions } = await pool.query(
      'SELECT * FROM opinion_positions WHERE user_id=$1 AND market_id=$2', [req.user.id, market.id]
    );
    res.json({ market, positions });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/markets', requireWallet, async (req, res) => {
  try {
    const { title, description, resolution_criteria, closes_at } = req.body;
    if (!title || typeof title !== 'string' || title.trim().length < 5 || title.length > 200)
      return res.status(400).json({ error: 'Title must be 5–200 characters' });
    const { rows: [market] } = await pool.query(`
      INSERT INTO opinion_markets(title,description,resolution_criteria,closes_at,created_by_user_id)
      VALUES($1,$2,$3,$4,$5) RETURNING *
    `, [title.trim(), (description || '').slice(0, 500), (resolution_criteria || '').slice(0, 500), closes_at || null, req.user.id]);
    res.status(201).json({ market });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/markets/:id/trade', requireWallet, async (req, res) => {
  const client = await pool.connect();
  try {
    const { outcome, usdc_amount } = req.body;
    if (!['YES', 'NO'].includes(outcome)) return res.status(400).json({ error: 'Invalid outcome' });
    if (parseAmount(usdc_amount) == null) return res.status(400).json({ error: 'Invalid amount' });
    const usdcUnits = toUnits(usdc_amount);
    if (usdcUnits <= 0) return res.status(400).json({ error: 'Invalid amount' });
    const mtTier = await userTier(req.user.id);
    if (!(await withinBasicDailyCap(req.user.id, mtTier)))
      return res.status(429).json({ error: 'daily_limit', detail: 'Basic tier daily trade limit reached — verify to remove limits.' });
    await client.query('BEGIN');
    const { rows: [market] } = await client.query(
      "SELECT * FROM opinion_markets WHERE id=$1 AND status='open' FOR UPDATE", [req.params.id]
    );
    if (!market) throw new Error('Market not available');
    const { rows: [bal] } = await client.query(
      "SELECT balance FROM wallet_balances WHERE user_id=$1 AND token_symbol='USDC' FOR UPDATE", [req.user.id]
    );
    if (!bal || Number(bal.balance) < usdcUnits) throw new Error('Insufficient USDC');
    const yesPool = Number(market.yes_pool);
    const noPool = Number(market.no_pool);
    const totalPool = yesPool + noPool;
    const price = outcome === 'YES' ? yesPool / totalPool : noPool / totalPool;
    const shares = usdcUnits / (price * UNITS);
    await client.query("UPDATE wallet_balances SET balance=balance-$1, updated_at=NOW() WHERE user_id=$2 AND token_symbol='USDC'", [usdcUnits, req.user.id]);
    if (outcome === 'YES') {
      await client.query('UPDATE opinion_markets SET yes_pool=yes_pool+$1 WHERE id=$2', [usdcUnits, market.id]);
    } else {
      await client.query('UPDATE opinion_markets SET no_pool=no_pool+$1 WHERE id=$2', [usdcUnits, market.id]);
    }
    await client.query(
      'INSERT INTO opinion_positions(user_id,market_id,outcome,shares,cost_basis) VALUES($1,$2,$3,$4,$5)',
      [req.user.id, market.id, outcome, shares, usdcUnits]
    );
    await client.query(
      "INSERT INTO transactions(user_id,type,token_symbol,amount,description) VALUES($1,'market_trade','USDC',$2,$3)",
      [req.user.id, -usdcUnits, `Buy ${outcome}`]
    );
    await client.query('COMMIT');
    try {
      const { rows: [ms] } = await pool.query('SELECT yes_pool, no_pool FROM opinion_markets WHERE id=$1', [req.params.id]);
      if (ms) {
        const yesPct = Number(ms.yes_pool) / (Number(ms.yes_pool) + Number(ms.no_pool)) * 100;
        await pool.query('INSERT INTO opinion_market_snapshots(market_id, yes_pct) VALUES($1,$2)', [req.params.id, yesPct.toFixed(3)]);
        await pool.query(`DELETE FROM opinion_market_snapshots WHERE id IN (SELECT id FROM (SELECT id, ROW_NUMBER() OVER (PARTITION BY market_id ORDER BY created_at DESC) AS rn FROM opinion_market_snapshots) r WHERE rn > 200)`);
      }
    } catch {}
    res.json({ ok: true, shares });
  } catch (e) {
    await client.query('ROLLBACK');
    res.status(400).json({ error: e.message });
  } finally { client.release(); }
});

app.post('/api/markets/:id/claim', async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows: [market] } = await client.query(
      "SELECT * FROM opinion_markets WHERE id=$1 AND status='resolved' FOR UPDATE", [req.params.id]
    );
    if (!market) throw new Error('Market not resolved');
    const { rows: positions } = await client.query(
      'SELECT * FROM opinion_positions WHERE user_id=$1 AND market_id=$2 AND outcome=$3 AND claimed=false FOR UPDATE',
      [req.user.id, market.id, market.resolved_outcome]
    );
    if (!positions.length) throw new Error('Nothing to claim');
    const { rows: [totals] } = await client.query(
      'SELECT SUM(cost_basis)::bigint AS total_cost FROM opinion_positions WHERE market_id=$1 AND outcome=$2',
      [market.id, market.resolved_outcome]
    );
    const totalCost = Number(totals.total_cost);
    const totalPool = Number(market.yes_pool) + Number(market.no_pool);
    let totalPayout = 0;
    for (const pos of positions) {
      const payout = Math.min(Math.floor(Number(pos.cost_basis) / totalCost * totalPool), Number(pos.cost_basis) * 2);
      totalPayout += payout;
      await client.query('UPDATE opinion_positions SET claimed=true WHERE id=$1', [pos.id]);
    }
    await client.query("UPDATE wallet_balances SET balance=balance+$1, updated_at=NOW() WHERE user_id=$2 AND token_symbol='USDC'", [totalPayout, req.user.id]);
    await client.query('COMMIT');
    res.json({ ok: true, payout: fromUnits(totalPayout) });
  } catch (e) {
    await client.query('ROLLBACK');
    res.status(400).json({ error: e.message });
  } finally { client.release(); }
});

app.post('/api/markets/:id/resolve', async (req, res) => {
  try {
    const { outcome } = req.body;
    if (!['YES', 'NO'].includes(outcome)) return res.status(400).json({ error: 'Invalid outcome' });
    const { rows: [user] } = await pool.query('SELECT is_admin FROM users WHERE user_id=$1', [req.user.id]);
    const { rows: [market] } = await pool.query('SELECT * FROM opinion_markets WHERE id=$1', [req.params.id]);
    if (!market) return res.status(404).json({ error: 'Not found' });
    if (!user?.is_admin && market.created_by_user_id !== req.user.id)
      return res.status(403).json({ error: 'forbidden' });
    await pool.query(
      "UPDATE opinion_markets SET status='resolved', resolved_outcome=$1, resolved_at=NOW() WHERE id=$2",
      [outcome, req.params.id]
    );
    try {
      const { rows: [ms] } = await pool.query('SELECT yes_pool, no_pool FROM opinion_markets WHERE id=$1', [req.params.id]);
      if (ms) {
        const yesPct = Number(ms.yes_pool) / (Number(ms.yes_pool) + Number(ms.no_pool)) * 100;
        await pool.query('INSERT INTO opinion_market_snapshots(market_id, yes_pct) VALUES($1,$2)', [req.params.id, yesPct.toFixed(3)]);
      }
    } catch {}
    if (user?.is_admin) await logAdmin(req.user.id, 'resolve_market', { target_market_id: parseInt(req.params.id), reason: outcome });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/markets/:id/history', async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT yes_pct, created_at FROM opinion_market_snapshots WHERE market_id=$1 ORDER BY created_at DESC LIMIT 100',
      [req.params.id]
    );
    res.json({ history: rows.reverse() });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Futures ────────────────────────────────────────────────────────────────────

app.get('/api/futures/markets', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM futures_markets ORDER BY id');
    res.json({ markets: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/futures/markets/:id/history', async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT mark_price, created_at FROM futures_price_snapshots WHERE market_id=$1 ORDER BY created_at DESC LIMIT 100',
      [req.params.id]
    );
    res.json({ history: rows.reverse() });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/futures/positions', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT fp.*, fm.symbol, fm.mark_price::float,
             COALESCE((SELECT SUM(amount) FROM funding_payments WHERE position_id=fp.id),0)::bigint AS funding_paid
      FROM futures_positions fp
      JOIN futures_markets fm ON fp.market_id = fm.id
      WHERE fp.user_id = $1
      ORDER BY fp.opened_at DESC
    `, [req.user.id]);
    const positions = rows.map(p => {
      const pnl = p.status === 'open' ?
        Math.round((p.mark_price - parseFloat(p.entry_price)) * parseFloat(p.quantity) * (p.side === 'long' ? 1 : -1) * UNITS) : p.realized_pnl;
      return { ...p, unrealized_pnl: p.status === 'open' ? pnl : 0 };
    });
    res.json({ positions });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/futures/paper-balance', async (req, res) => {
  try {
    const { rows: [pb] } = await pool.query('SELECT usdc_balance FROM paper_balances WHERE user_id=$1', [req.user.id]);
    res.json({ balance: pb?.usdc_balance || 10000000000 });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/futures/positions', requireWallet, async (req, res) => {
  const client = await pool.connect();
  try {
    const { market_id, side, leverage, quantity, mode, idempotency_key } = req.body;
    const lev = Math.max(1, Math.min(20, parseInt(leverage) || 1));
    const qty = parseAmount(quantity, { max: 1e9 });
    if (!qty) return res.status(400).json({ error: 'Invalid quantity' });
    if (!['long', 'short'].includes(side)) return res.status(400).json({ error: 'Invalid side' });
    if (!['paper', 'live'].includes(mode)) return res.status(400).json({ error: 'Invalid mode' });

    const tier = await userTier(req.user.id);
    if (mode === 'live') {
      if (!tierAllows(tier, 'live_futures'))
        return res.status(403).json({ error: 'verify_required', tier_needed: 'social' });
      if (lev > 5 && !tierAllows(tier, 'high_leverage'))
        return res.status(403).json({ error: 'verify_required', tier_needed: 'premium' });
    }
    if (!(await withinBasicDailyCap(req.user.id, tier)))
      return res.status(429).json({ error: 'daily_limit', detail: 'Basic tier daily trade limit reached — verify to remove limits.' });

    // Idempotency guard against double-submit (Phase 4).
    if (idempotency_key) {
      const { rows: dup } = await pool.query(
        "SELECT 1 FROM idempotency_keys WHERE user_id=$1 AND key=$2", [req.user.id, idempotency_key]
      );
      if (dup.length) return res.status(409).json({ error: 'duplicate_request' });
    }

    await client.query('BEGIN');
    if (idempotency_key) {
      await client.query(
        "INSERT INTO idempotency_keys(user_id,key) VALUES($1,$2) ON CONFLICT DO NOTHING",
        [req.user.id, idempotency_key]
      );
    }
    const { rows: [market] } = await client.query('SELECT * FROM futures_markets WHERE id=$1 FOR UPDATE', [market_id]);
    if (!market) throw new Error('Market not found');
    const markPrice = parseFloat(market.mark_price);
    const marginUnits = Math.ceil(qty * markPrice * UNITS / lev);
    const liqPrice = side === 'long' ? markPrice * (1 - 0.9 / lev) : markPrice * (1 + 0.9 / lev);

    if (mode === 'live') {
      const { rows: [bal] } = await client.query(
        "SELECT balance FROM wallet_balances WHERE user_id=$1 AND token_symbol='USDC' FOR UPDATE", [req.user.id]
      );
      if (!bal || Number(bal.balance) < marginUnits) throw new Error('Insufficient USDC');
      await client.query("UPDATE wallet_balances SET balance=balance-$1, updated_at=NOW() WHERE user_id=$2 AND token_symbol='USDC'", [marginUnits, req.user.id]);
    } else {
      const { rows: [pb] } = await client.query('SELECT usdc_balance FROM paper_balances WHERE user_id=$1 FOR UPDATE', [req.user.id]);
      if (!pb || Number(pb.usdc_balance) < marginUnits) throw new Error('Insufficient paper balance');
      await client.query('UPDATE paper_balances SET usdc_balance=usdc_balance-$1 WHERE user_id=$2', [marginUnits, req.user.id]);
    }

    const { rows: [pos] } = await client.query(`
      INSERT INTO futures_positions(user_id,market_id,mode,side,leverage,entry_price,quantity,margin,liquidation_price)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *
    `, [req.user.id, market_id, mode, side, lev, markPrice, qty, marginUnits, liqPrice]);
    await client.query('UPDATE futures_markets SET open_interest=open_interest+$1 WHERE id=$2', [marginUnits, market_id]);
    await client.query(
      "INSERT INTO transactions(user_id,type,token_symbol,amount,description) VALUES($1,'futures_open','USDC',$2,$3)",
      [req.user.id, -marginUnits, `Open ${side} ${lev}x (${mode})`]
    );
    await client.query('COMMIT');
    res.json({ position: pos });
  } catch (e) {
    await client.query('ROLLBACK');
    res.status(400).json({ error: e.message });
  } finally { client.release(); }
});

app.delete('/api/futures/positions/:id', async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows: [pos] } = await client.query(
      'SELECT fp.*, fm.mark_price::float FROM futures_positions fp JOIN futures_markets fm ON fp.market_id=fm.id WHERE fp.id=$1 AND fp.user_id=$2 AND fp.status=\'open\' FOR UPDATE',
      [req.params.id, req.user.id]
    );
    if (!pos) throw new Error('Position not found');
    const pnl = Math.round((pos.mark_price - parseFloat(pos.entry_price)) * parseFloat(pos.quantity) * (pos.side === 'long' ? 1 : -1) * UNITS);
    const returnAmt = Math.max(0, Number(pos.margin) + pnl);
    await client.query("UPDATE futures_positions SET status='closed', realized_pnl=$1, closed_at=NOW() WHERE id=$2", [pnl, pos.id]);
    if (pos.mode === 'live') {
      await client.query("UPDATE wallet_balances SET balance=balance+$1, updated_at=NOW() WHERE user_id=$2 AND token_symbol='USDC'", [returnAmt, req.user.id]);
    } else {
      await client.query('UPDATE paper_balances SET usdc_balance=usdc_balance+$1 WHERE user_id=$2', [returnAmt, req.user.id]);
    }
    await client.query('UPDATE futures_markets SET open_interest=GREATEST(0, open_interest-$1) WHERE id=$2', [pos.margin, pos.market_id]);
    await client.query('COMMIT');
    res.json({ ok: true, pnl: fromUnits(pnl), returned: fromUnits(returnAmt) });
  } catch (e) {
    await client.query('ROLLBACK');
    res.status(400).json({ error: e.message });
  } finally { client.release(); }
});

// ── Activity History ──────────────────────────────────────────────────────────

app.get('/api/activity', async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 20, 50);
    const cursor = req.query.cursor ? parseInt(req.query.cursor) : null;
    const params = [req.user.id, limit + 1];
    const cursorClause = cursor ? `AND id < $${params.push(cursor)}` : '';
    const { rows } = await pool.query(
      `SELECT id, type, token_symbol, amount::text AS amount, description, created_at
       FROM transactions WHERE user_id=$1 ${cursorClause} ORDER BY id DESC LIMIT $2`,
      params
    );
    const hasMore = rows.length > limit;
    const activities = hasMore ? rows.slice(0, limit) : rows;
    const nextCursor = hasMore ? activities[activities.length - 1].id : null;
    res.json({ activities, nextCursor });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── NFT ───────────────────────────────────────────────────────────────────────

app.get('/api/nfts', async (req, res) => {
  try {
    let q = 'SELECT * FROM nfts WHERE burned=false';
    const params = [];
    if (req.query.owner) { q += ` AND owner_username=$${params.push(req.query.owner)}`; }
    q += ' ORDER BY id DESC LIMIT 50';
    const { rows } = await pool.query(q, params);
    res.json({ nfts: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/nfts/mint', requireWallet, async (req, res) => {
  const client = await pool.connect();
  try {
    const { name, description, image_url } = req.body;
    if (!validStr(name, 100)) return res.status(400).json({ error: 'Invalid name' });
    if (!validStr(image_url, 1000) || !HTTP_URL_RE.test(image_url))
      return res.status(400).json({ error: 'image_url must be an http(s) URL' });
    if (description != null && String(description).length > 500)
      return res.status(400).json({ error: 'Description too long' });
    const MINT_COST = 10 * UNITS;
    await client.query('BEGIN');
    const { rows: [bal] } = await client.query(
      "SELECT balance FROM wallet_balances WHERE user_id=$1 AND token_symbol='BLOOM' FOR UPDATE", [req.user.id]
    );
    if (!bal || Number(bal.balance) < MINT_COST) throw new Error('Insufficient BLOOM (need 10)');
    await client.query("UPDATE wallet_balances SET balance=balance-$1, updated_at=NOW() WHERE user_id=$2 AND token_symbol='BLOOM'", [MINT_COST, req.user.id]);
    const { rows: [nft] } = await client.query(
      "INSERT INTO nfts(owner_user_id,owner_username,name,description,image_url,token_id) VALUES($1,$2,$3,$4,$5,'TEMP') RETURNING id",
      [req.user.id, req.user.username, name, description || '', image_url]
    );
    const tokenId = 'BLOOM-' + nft.id.toString(16).padStart(8, '0').toUpperCase();
    await client.query('UPDATE nfts SET token_id=$1 WHERE id=$2', [tokenId, nft.id]);
    await client.query('COMMIT');
    res.json({ ok: true, token_id: tokenId });
  } catch (e) {
    await client.query('ROLLBACK');
    res.status(400).json({ error: e.message });
  } finally { client.release(); }
});

// ── KYC ───────────────────────────────────────────────────────────────────────

app.get('/api/kyc', async (req, res) => {
  try {
    if (req.user.usernode_pubkey) {
      await pool.query(
        "INSERT INTO kyc_verifications(user_id,level,status) VALUES($1,'basic','approved') ON CONFLICT DO NOTHING",
        [req.user.id]
      );
    }
    const { rows: [kyc] } = await pool.query('SELECT * FROM kyc_verifications WHERE user_id=$1', [req.user.id]);
    res.json({ kyc: kyc || null });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Which verification providers are reachable in this environment. The Verify
// screen renders only the social providers that are configured (Phase 1).
app.get('/api/verify/providers', (req, res) => {
  const social = IS_STAGING
    ? verify.SOCIAL_PROVIDERS.slice()
    : verify.configuredSocialProviders();
  res.json({
    staging: IS_STAGING,
    social_enabled: verify.SOCIAL_VERIFY_ENABLED,
    social_providers: social,
    premium_enabled: verify.ZK_VERIFY_ENABLED,
  });
});

// Begin a social-OAuth round-trip. Returns the authorization URL + a signed
// state binding the trip to this wallet + provider.
app.post('/api/verify/social/start', requireWallet, async (req, res) => {
  try {
    const { provider } = req.body;
    if (!verify.isSocialProvider(provider)) return res.status(400).json({ error: 'invalid_provider' });
    const out = verify.startSocialOAuth(provider, req.user.id);
    if (!out.ok) return res.status(400).json({ error: out.error });
    res.json({ oauth_url: out.oauth_url, state: out.state, simulated: !!out.simulated });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Finalize the social-OAuth round-trip and upsert the Social tier. The UNIQUE
// constraint on anti_sybil_token enforces one social account per wallet — a
// collision with a different user returns 403 social_account_in_use.
app.post('/api/verify/social/complete', requireWallet, async (req, res) => {
  try {
    const { provider, code, state } = req.body;
    if (!verify.isSocialProvider(provider)) return res.status(400).json({ error: 'invalid_provider' });
    const out = await verify.completeSocialOAuth(provider, code, state);
    if (!out.ok) return res.status(400).json({ error: out.error });
    if (out.user_id != null && Number(out.user_id) !== Number(req.user.id))
      return res.status(400).json({ error: 'invalid_state' });

    // Pre-check the token is not already bound to a different wallet.
    const { rows: clash } = await pool.query(
      'SELECT user_id FROM kyc_verifications WHERE anti_sybil_token=$1 AND user_id<>$2',
      [out.anti_sybil_token, req.user.id]
    );
    if (clash.length) return res.status(403).json({ error: 'social_account_in_use' });

    try {
      await pool.query(`
        INSERT INTO kyc_verifications(user_id,level,status,provider,attestation_ref,anti_sybil_token,verified_at)
        VALUES($1,'social','approved',$2,$3,$4,NOW())
        ON CONFLICT(user_id) DO UPDATE SET
          level=CASE WHEN kyc_verifications.level='premium' THEN 'premium' ELSE 'social' END,
          status='approved', provider=$2, attestation_ref=$3, anti_sybil_token=$4,
          verified_at=NOW(), rejection_reason=NULL
      `, [req.user.id, provider, out.account_ref, out.anti_sybil_token]);
    } catch (e) {
      if (e.code === '23505') return res.status(403).json({ error: 'social_account_in_use' });
      throw e;
    }
    res.json({ ok: true, level: 'social', provider });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Premium via zkPassport proof (Phase 1).
app.post('/api/verify/zkpassport', requireWallet, async (req, res) => {
  try {
    const { proof } = req.body;
    const out = await verify.verifyZkPassportProof(proof, req.user.id);
    if (!out.ok) return res.status(400).json({ error: out.error });
    await pool.query(`
      INSERT INTO kyc_verifications(user_id,level,status,provider,attestation_ref,verified_at)
      VALUES($1,'premium','approved','zkpassport',$2,NOW())
      ON CONFLICT(user_id) DO UPDATE SET level='premium', status='approved',
        provider='zkpassport', attestation_ref=$2, verified_at=NOW(), rejection_reason=NULL
    `, [req.user.id, out.ref]);
    res.json({ ok: true, level: 'premium' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/kyc/submit', requireWallet, async (req, res) => {
  try {
    const { level, document_type, biometric_consent } = req.body;
    if (!['verified', 'elite'].includes(level)) return res.status(400).json({ error: 'Invalid level' });
    await pool.query(`
      INSERT INTO kyc_verifications(user_id,level,status,document_type,biometric_consent)
      VALUES($1,$2,'pending',$3,$4)
      ON CONFLICT(user_id) DO UPDATE SET level=$2, status='pending', document_type=$3, biometric_consent=$4, submitted_at=NOW(), rejection_reason=NULL
    `, [req.user.id, level, document_type || null, biometric_consent || false]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Admin ─────────────────────────────────────────────────────────────────────

app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  try {
    const { rows: [stats] } = await pool.query(`SELECT
      (SELECT COUNT(*) FROM users)::int AS total_users,
      (SELECT COUNT(*) FROM posts WHERE deleted=false AND created_at > NOW()-INTERVAL '1 day')::int AS posts_today,
      (SELECT COALESCE(SUM(from_amount),0) FROM defi_swaps WHERE from_token='USDC')::bigint AS swap_volume,
      (SELECT COUNT(*) FROM futures_positions WHERE status='open')::int AS open_futures,
      (SELECT COALESCE(SUM(yes_pool+no_pool),0) FROM opinion_markets WHERE status='open')::bigint AS market_liquidity
    `);
    res.json({ stats });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    const search = req.query.search || '';
    const { rows } = await pool.query(
      `SELECT u.*, k.level AS kyc_level,
        (SELECT COUNT(*) FROM posts WHERE user_id=u.user_id AND deleted=false)::int AS post_count
       FROM users u LEFT JOIN kyc_verifications k ON k.user_id=u.user_id
       WHERE u.username ILIKE $1 ORDER BY u.created_at DESC LIMIT 50`,
      [`%${search}%`]
    );
    res.json({ users: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/users/:id/ban', requireAdmin, async (req, res) => {
  try {
    await pool.query('UPDATE users SET is_banned=true WHERE user_id=$1', [req.params.id]);
    await pool.query('UPDATE posts SET deleted=true WHERE user_id=$1', [req.params.id]);
    banCache.delete(parseInt(req.params.id));
    await logAdmin(req.user.id, 'ban_user', { target_user_id: parseInt(req.params.id), reason: req.body.reason });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/users/:id/unban', requireAdmin, async (req, res) => {
  try {
    await pool.query('UPDATE users SET is_banned=false WHERE user_id=$1', [req.params.id]);
    banCache.delete(parseInt(req.params.id));
    await logAdmin(req.user.id, 'unban_user', { target_user_id: parseInt(req.params.id) });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/users/:id/admin', requireAdmin, async (req, res) => {
  try {
    await pool.query('UPDATE users SET is_admin=NOT is_admin WHERE user_id=$1', [req.params.id]);
    await logAdmin(req.user.id, 'toggle_admin', { target_user_id: parseInt(req.params.id) });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Admin manual verification override (Phase 1/5) — grant or revoke a tier.
app.post('/api/admin/verify/:id', requireAdmin, async (req, res) => {
  try {
    const { level } = req.body;
    if (!['basic', 'social', 'premium'].includes(level)) return res.status(400).json({ error: 'invalid_level' });
    await pool.query(
      "UPDATE kyc_verifications SET level=$1, status='approved', verified_at=NOW(), reviewed_by_user_id=$2, rejection_reason=NULL WHERE user_id=$3",
      [level, req.user.id, req.params.id]
    );
    await logAdmin(req.user.id, 'verify_override', { target_user_id: parseInt(req.params.id), reason: level });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/kyc', requireAdmin, async (req, res) => {
  try {
    const status = req.query.status || 'pending';
    const { rows } = await pool.query(
      'SELECT k.*, u.username FROM kyc_verifications k JOIN users u ON u.user_id=k.user_id WHERE k.status=$1 ORDER BY k.submitted_at ASC',
      [status]
    );
    res.json({ verifications: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/kyc/:id/approve', requireAdmin, async (req, res) => {
  try {
    await pool.query(
      "UPDATE kyc_verifications SET status='approved', reviewed_at=NOW(), reviewed_by_user_id=$1, rejection_reason=NULL WHERE id=$2",
      [req.user.id, req.params.id]
    );
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/kyc/:id/reject', requireAdmin, async (req, res) => {
  try {
    await pool.query(
      "UPDATE kyc_verifications SET status='rejected', reviewed_at=NOW(), reviewed_by_user_id=$1, rejection_reason=$2, level='basic' WHERE id=$3",
      [req.user.id, req.body.reason || '', req.params.id]
    );
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/posts/:id/delete', requireAdmin, async (req, res) => {
  try {
    await pool.query('UPDATE posts SET deleted=true WHERE id=$1', [req.params.id]);
    await logAdmin(req.user.id, 'delete_post', { target_post_id: parseInt(req.params.id) });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/ico', requireAdmin, async (req, res) => {
  try {
    const { token_name, token_symbol, description, price_per_token, total_supply, hard_cap, start_date, end_date } = req.body;
    if (!validStr(token_name, 100) || !validStr(token_symbol, 20)) return res.status(400).json({ error: 'Invalid token name/symbol' });
    if ([price_per_token, total_supply, hard_cap].some(v => parseAmount(v) == null)) return res.status(400).json({ error: 'Invalid numbers' });
    const startDateVal = start_date && String(start_date).trim() ? new Date(start_date).toISOString() : null;
    const endDateVal = end_date && String(end_date).trim() ? new Date(end_date).toISOString() : null;
    const status = startDateVal && new Date(startDateVal) > new Date() ? 'upcoming' : 'active';
    const { rows: [ico] } = await pool.query(`
      INSERT INTO ico_offerings(token_name,token_symbol,description,price_per_token,total_supply,hard_cap,status,start_date,end_date,created_by_user_id)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *
    `, [token_name, token_symbol, (description || '').slice(0, 500), toUnits(price_per_token), toUnits(total_supply), toUnits(hard_cap), status, startDateVal, endDateVal, req.user.id]);
    await logAdmin(req.user.id, 'create_ico', { reason: token_symbol });
    res.json({ ico });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/admin/ico/:id', requireAdmin, async (req, res) => {
  try {
    await pool.query("UPDATE ico_offerings SET status='ended' WHERE id=$1", [req.params.id]);
    await logAdmin(req.user.id, 'end_ico', { reason: String(req.params.id) });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/markets', requireAdmin, async (req, res) => {
  try {
    const { title, description, resolution_criteria, closes_at } = req.body;
    if (!validStr(title, 200)) return res.status(400).json({ error: 'Invalid title' });
    const { rows: [market] } = await pool.query(`
      INSERT INTO opinion_markets(title,description,resolution_criteria,closes_at,created_by_user_id)
      VALUES($1,$2,$3,$4,$5) RETURNING *
    `, [title, (description || '').slice(0, 500), (resolution_criteria || '').slice(0, 500), closes_at || null, req.user.id]);
    await logAdmin(req.user.id, 'create_market', { target_market_id: market.id });
    res.json({ market });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Suggested people for the Explore screen (Phase 2): top users by follower
// count, excluding self and anyone already followed.
app.get('/api/explore/people', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT u.username, u.display_name, u.usernode_pubkey,
        (SELECT COUNT(*) FROM follows WHERE following_id=u.user_id)::int AS followers,
        k.level AS kyc_level
      FROM users u
      LEFT JOIN kyc_verifications k ON k.user_id=u.user_id
      WHERE u.user_id <> $1
        AND u.user_id NOT IN (SELECT following_id FROM follows WHERE follower_id=$1)
        AND u.is_banned = false
      ORDER BY followers DESC, u.created_at DESC
      LIMIT 10
    `, [req.user.id]);
    res.json({ people: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Server-rendered Admin console (Phase 5) ─────────────────────────────────────
// Standalone HTML pages at /admin pathnames. They pass the GET branch of the
// auth gate, so each handler re-checks admin explicitly and renders a "not
// authorized" page otherwise. These paths are NOT in PUBLIC_API_PATHS.

function adminLayout(title, body) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} · BloomMoney Admin</title>
<style>
  :root{color-scheme:dark}
  body{font-family:system-ui,sans-serif;background:#0a0a0b;color:#e4e4e7;margin:0}
  header{background:#18181b;border-bottom:1px solid #27272a;padding:.75rem 1.25rem;display:flex;gap:1rem;align-items:center;flex-wrap:wrap}
  header a{color:#a78bfa;text-decoration:none;font-size:.9rem}
  header a:hover{text-decoration:underline}
  main{max-width:60rem;margin:0 auto;padding:1.5rem 1.25rem}
  h1{font-size:1.3rem;margin:0 1rem 0 0}
  h2{font-size:1.05rem;margin:1.5rem 0 .5rem}
  table{width:100%;border-collapse:collapse;font-size:.85rem}
  th,td{text-align:left;padding:.4rem .5rem;border-bottom:1px solid #27272a}
  .cards{display:flex;flex-wrap:wrap;gap:.75rem}
  .card{background:#18181b;border:1px solid #27272a;border-radius:.6rem;padding:1rem;min-width:9rem}
  .stat{font-size:1.5rem;font-weight:700;color:#c4b5fd}
  .muted{color:#71717a;font-size:.8rem}
  form{display:inline}
  input,select{background:#27272a;border:1px solid #3f3f46;color:#fff;border-radius:.4rem;padding:.35rem .5rem;font-size:.85rem}
  button{background:#7c3aed;color:#fff;border:0;border-radius:.4rem;padding:.35rem .7rem;font-size:.8rem;cursor:pointer}
  button.danger{background:#b91c1c}
  .grid-form{display:grid;grid-template-columns:repeat(auto-fit,minmax(10rem,1fr));gap:.5rem;align-items:end;max-width:48rem;margin:.5rem 0}
</style></head><body>
<header>
  <h1>🌸 BloomMoney Admin</h1>
  <a href="/admin">Dashboard</a>
  <a href="/admin/users">Users</a>
  <a href="/admin/verifications">Verifications</a>
  <a href="/admin/markets">Markets</a>
  <a href="/admin/ico">ICO</a>
</header>
<main id="admin-root">${body}</main>
</body></html>`;
}

function notAuthorizedPage(res) {
  return res.status(403).send(adminLayout('Not authorized',
    `<h2>Not authorized</h2><p class="muted">Open BloomMoney inside Usernode as an admin to access this console.</p>`));
}

// HTML-page admin guard (renders a page rather than JSON on failure).
async function requireAdminPage(req, res, next) {
  // Staging demo bypass for the read-only console pages, so a preview / the
  // declared /admin test can render without a seeded admin session. Never
  // applies to POST mutations or in production.
  if (IS_STAGING && req.method === 'GET' && req.query.demo === '1') return next();
  if (!req.user) return notAuthorizedPage(res);
  try {
    const { rows } = await pool.query('SELECT is_admin FROM users WHERE user_id=$1', [req.user.id]);
    if (!rows[0]?.is_admin) return notAuthorizedPage(res);
    next();
  } catch (e) { res.status(500).send(adminLayout('Error', `<p>${esc(e.message)}</p>`)); }
}

// Forward the token so in-console form posts and links stay authenticated
// inside the iframe (the gate accepts ?token= on the query string).
function tok(req) { const t = req.query.token || ''; return t ? `?token=${encodeURIComponent(t)}` : ''; }

app.get('/admin', requireAdminPage, async (req, res) => {
  try {
    const { rows } = await pool.query(`SELECT
      (SELECT COUNT(*) FROM users)::int AS total_users,
      (SELECT COUNT(*) FROM users WHERE is_banned)::int AS banned,
      (SELECT COUNT(*) FROM posts WHERE deleted=false)::int AS posts,
      (SELECT COUNT(*) FROM futures_positions WHERE status='open')::int AS open_futures,
      (SELECT COUNT(*) FROM kyc_verifications WHERE level='social' AND status='approved')::int AS social_verified,
      (SELECT COUNT(*) FROM kyc_verifications WHERE level='premium' AND status='approved')::int AS premium_verified,
      (SELECT COUNT(*) FROM opinion_markets WHERE status='open')::int AS open_markets`);
    const s = rows[0] || {};
    const cards = [
      ['Total users', s.total_users], ['Banned', s.banned], ['Posts', s.posts],
      ['Open futures', s.open_futures], ['Social verified', s.social_verified],
      ['Premium verified', s.premium_verified], ['Open markets', s.open_markets],
    ].map(([l, v]) => `<div class="card"><div class="stat">${v}</div><div class="muted">${l}</div></div>`).join('');
    const { rows: actions } = await pool.query(
      'SELECT a.*, u.username FROM admin_actions a LEFT JOIN users u ON u.user_id=a.admin_user_id ORDER BY a.id DESC LIMIT 15'
    );
    const audit = actions.length ? `<table id="audit-log"><thead><tr><th>When</th><th>Admin</th><th>Action</th><th>Target</th><th>Note</th></tr></thead><tbody>${
      actions.map(a => `<tr><td class="muted">${new Date(a.created_at).toISOString().slice(0,16).replace('T',' ')}</td><td>@${esc(a.username||'?')}</td><td>${esc(a.action_type)}</td><td>${esc(String(a.target_user_id||a.target_market_id||a.target_post_id||''))}</td><td>${esc(a.reason||'')}</td></tr>`).join('')
    }</tbody></table>` : '<p class="muted">No admin actions logged yet.</p>';
    res.send(adminLayout('Dashboard', `<div id="admin-stats"><h2>Platform stats</h2><div class="cards">${cards}</div></div><h2>Recent admin actions</h2>${audit}`));
  } catch (e) { res.status(500).send(adminLayout('Error', `<p>${esc(e.message)}</p>`)); }
});

app.get('/admin/users', requireAdminPage, async (req, res) => {
  try {
    const search = (req.query.search || '').slice(0, 80);
    const { rows } = await pool.query(
      `SELECT u.*, k.level AS kyc_level FROM users u LEFT JOIN kyc_verifications k ON k.user_id=u.user_id
       WHERE u.username ILIKE $1 ORDER BY u.created_at DESC LIMIT 100`, [`%${search}%`]
    );
    const t = tok(req);
    const body = `<h2>User management</h2>
      <form method="get" action="/admin/users">${req.query.token ? `<input type="hidden" name="token" value="${esc(req.query.token)}">` : ''}
        <input name="search" placeholder="Search username" value="${esc(search)}"><button type="submit">Search</button></form>
      <table id="users-table"><thead><tr><th>User</th><th>Wallet</th><th>Tier</th><th>Admin</th><th>Banned</th><th>Actions</th></tr></thead><tbody>${
        rows.map(u => `<tr>
          <td>@${esc(u.username)}</td>
          <td class="muted">${esc(shortAddr(u.usernode_pubkey))}</td>
          <td>${esc(u.kyc_level || 'basic')}</td>
          <td>${u.is_admin ? '✓' : ''}</td>
          <td>${u.is_banned ? '🚫' : ''}</td>
          <td>
            ${u.is_banned
              ? `<form method="post" action="/admin/users/${u.user_id}/unban${t}"><button>Unban</button></form>`
              : `<form method="post" action="/admin/users/${u.user_id}/ban${t}"><button class="danger">Ban</button></form>`}
            <form method="post" action="/admin/users/${u.user_id}/admin${t}"><button>${u.is_admin ? 'Revoke' : 'Grant'} admin</button></form>
          </td></tr>`).join('')
      }</tbody></table>`;
    res.send(adminLayout('Users', body));
  } catch (e) { res.status(500).send(adminLayout('Error', `<p>${esc(e.message)}</p>`)); }
});

app.get('/admin/verifications', requireAdminPage, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT k.*, u.username FROM kyc_verifications k JOIN users u ON u.user_id=k.user_id
       ORDER BY (k.status='pending') DESC, k.verified_at DESC NULLS LAST, k.submitted_at DESC LIMIT 100`
    );
    const t = tok(req);
    const body = `<h2>Verification queue & overrides</h2>
      <table id="verifications-table"><thead><tr><th>User</th><th>Level</th><th>Status</th><th>Provider</th><th>Set tier</th></tr></thead><tbody>${
        rows.map(k => `<tr>
          <td>@${esc(k.username)}</td><td>${esc(k.level)}</td><td>${esc(k.status)}</td><td>${esc(k.provider||'—')}</td>
          <td><form method="post" action="/admin/verifications/${k.user_id}${t}">
            <select name="level"><option>basic</option><option>social</option><option>premium</option></select>
            <button>Set</button></form></td></tr>`).join('')
      }</tbody></table>`;
    res.send(adminLayout('Verifications', body));
  } catch (e) { res.status(500).send(adminLayout('Error', `<p>${esc(e.message)}</p>`)); }
});

app.get('/admin/markets', requireAdminPage, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM opinion_markets ORDER BY created_at DESC LIMIT 100');
    const t = tok(req);
    const tokenField = req.query.token ? `<input type="hidden" name="token" value="${esc(req.query.token)}">` : '';
    const body = `<h2>Create opinion market</h2>
      <form method="post" action="/admin/markets${t}" class="grid-form">${tokenField}
        <input name="title" placeholder="Title" required>
        <input name="description" placeholder="Description">
        <input name="resolution_criteria" placeholder="Resolution criteria">
        <button type="submit">Create</button></form>
      <h2>Markets</h2>
      <table id="markets-table"><thead><tr><th>ID</th><th>Title</th><th>Status</th><th>Resolve</th></tr></thead><tbody>${
        rows.map(m => `<tr><td>${m.id}</td><td>${esc(m.title)}</td><td>${esc(m.status)}</td>
          <td>${m.status === 'open'
            ? `<form method="post" action="/admin/markets/${m.id}/resolve${t}">${tokenField}<select name="outcome"><option>YES</option><option>NO</option></select><button>Resolve</button></form>`
            : esc(m.resolved_outcome || '—')}</td></tr>`).join('')
      }</tbody></table>`;
    res.send(adminLayout('Markets', body));
  } catch (e) { res.status(500).send(adminLayout('Error', `<p>${esc(e.message)}</p>`)); }
});

app.get('/admin/ico', requireAdminPage, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM ico_offerings ORDER BY created_at DESC LIMIT 100');
    const t = tok(req);
    const tokenField = req.query.token ? `<input type="hidden" name="token" value="${esc(req.query.token)}">` : '';
    const body = `<h2>Create ICO offering</h2>
      <form method="post" action="/admin/ico${t}" class="grid-form">${tokenField}
        <input name="token_name" placeholder="Token name" required>
        <input name="token_symbol" placeholder="Symbol" required>
        <input name="price_per_token" type="number" step="any" placeholder="Price (USDC)" required>
        <input name="total_supply" type="number" step="any" placeholder="Total supply" required>
        <input name="hard_cap" type="number" step="any" placeholder="Hard cap (USDC)" required>
        <input name="start_date" type="datetime-local" placeholder="Start date (optional)">
        <input name="end_date" type="datetime-local" placeholder="End date (optional)">
        <button type="submit">Create</button></form>
      <h2>Offerings</h2>
      <table id="ico-table"><thead><tr><th>Symbol</th><th>Status</th><th>Raised</th><th>Start</th><th>End</th><th></th></tr></thead><tbody>${
        rows.map(o => `<tr><td>${esc(o.token_symbol)}</td><td>${esc(o.status)}</td><td>${fromUnits(o.raised).toFixed(0)}/${fromUnits(o.hard_cap).toFixed(0)}</td>
          <td class="muted">${o.start_date ? new Date(o.start_date).toISOString().slice(0,10) : '—'}</td>
          <td class="muted">${o.end_date ? new Date(o.end_date).toISOString().slice(0,10) : '—'}</td>
          <td>${o.status === 'active' ? `<form method="post" action="/admin/ico/${o.id}/end${t}">${tokenField}<button class="danger">End</button></form>` : ''}</td></tr>`).join('')
      }</tbody></table>`;
    res.send(adminLayout('ICO', body));
  } catch (e) { res.status(500).send(adminLayout('Error', `<p>${esc(e.message)}</p>`)); }
});

// Admin form-post handlers (redirect back to the relevant page).
app.use(express.urlencoded({ extended: false, limit: '64kb' }));

app.post('/admin/users/:id/ban', requireAdminPage, async (req, res) => {
  await pool.query('UPDATE users SET is_banned=true WHERE user_id=$1', [req.params.id]);
  await pool.query('UPDATE posts SET deleted=true WHERE user_id=$1', [req.params.id]);
  banCache.delete(parseInt(req.params.id));
  await logAdmin(req.user.id, 'ban_user', { target_user_id: parseInt(req.params.id) });
  res.redirect('/admin/users' + tok(req));
});
app.post('/admin/users/:id/unban', requireAdminPage, async (req, res) => {
  await pool.query('UPDATE users SET is_banned=false WHERE user_id=$1', [req.params.id]);
  banCache.delete(parseInt(req.params.id));
  await logAdmin(req.user.id, 'unban_user', { target_user_id: parseInt(req.params.id) });
  res.redirect('/admin/users' + tok(req));
});
app.post('/admin/users/:id/admin', requireAdminPage, async (req, res) => {
  await pool.query('UPDATE users SET is_admin=NOT is_admin WHERE user_id=$1', [req.params.id]);
  await logAdmin(req.user.id, 'toggle_admin', { target_user_id: parseInt(req.params.id) });
  res.redirect('/admin/users' + tok(req));
});
app.post('/admin/verifications/:id', requireAdminPage, async (req, res) => {
  const level = ['basic', 'social', 'premium'].includes(req.body.level) ? req.body.level : 'basic';
  await pool.query(
    "UPDATE kyc_verifications SET level=$1, status='approved', verified_at=NOW(), reviewed_by_user_id=$2 WHERE user_id=$3",
    [level, req.user.id, req.params.id]
  );
  await logAdmin(req.user.id, 'verify_override', { target_user_id: parseInt(req.params.id), reason: level });
  res.redirect('/admin/verifications' + tok(req));
});
app.post('/admin/markets', requireAdminPage, async (req, res) => {
  const { title, description, resolution_criteria } = req.body;
  if (validStr(title, 200)) {
    const { rows: [m] } = await pool.query(
      'INSERT INTO opinion_markets(title,description,resolution_criteria,created_by_user_id) VALUES($1,$2,$3,$4) RETURNING id',
      [title, (description || '').slice(0, 500), (resolution_criteria || '').slice(0, 500), req.user.id]
    );
    await logAdmin(req.user.id, 'create_market', { target_market_id: m.id });
  }
  res.redirect('/admin/markets' + tok(req));
});
app.post('/admin/markets/:id/resolve', requireAdminPage, async (req, res) => {
  const outcome = ['YES', 'NO'].includes(req.body.outcome) ? req.body.outcome : null;
  if (outcome) {
    await pool.query("UPDATE opinion_markets SET status='resolved', resolved_outcome=$1, resolved_at=NOW() WHERE id=$2", [outcome, req.params.id]);
    await logAdmin(req.user.id, 'resolve_market', { target_market_id: parseInt(req.params.id), reason: outcome });
  }
  res.redirect('/admin/markets' + tok(req));
});
app.post('/admin/ico', requireAdminPage, async (req, res) => {
  const { token_name, token_symbol, price_per_token, total_supply, hard_cap, start_date, end_date } = req.body;
  if (validStr(token_name, 100) && validStr(token_symbol, 20) &&
      [price_per_token, total_supply, hard_cap].every(v => parseAmount(v) != null)) {
    const startDateVal = start_date && String(start_date).trim() ? new Date(start_date).toISOString() : null;
    const endDateVal = end_date && String(end_date).trim() ? new Date(end_date).toISOString() : null;
    const status = startDateVal && new Date(startDateVal) > new Date() ? 'upcoming' : 'active';
    await pool.query(
      'INSERT INTO ico_offerings(token_name,token_symbol,price_per_token,total_supply,hard_cap,status,start_date,end_date,created_by_user_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)',
      [token_name, token_symbol, toUnits(price_per_token), toUnits(total_supply), toUnits(hard_cap), status, startDateVal, endDateVal, req.user.id]
    );
    await logAdmin(req.user.id, 'create_ico', { reason: token_symbol });
  }
  res.redirect('/admin/ico' + tok(req));
});
app.post('/admin/ico/:id/end', requireAdminPage, async (req, res) => {
  await pool.query("UPDATE ico_offerings SET status='ended' WHERE id=$1", [req.params.id]);
  await logAdmin(req.user.id, 'end_ico', { reason: String(req.params.id) });
  res.redirect('/admin/ico' + tok(req));
});

// ── Static + HTML shell ────────────────────────────────────────────────────────

// Browsers always request a favicon; without a file, the catch-all below would
// gate it and return 401 to unauthenticated tabs, generating a console error.
app.get('/favicon.ico', (req, res) => res.status(204).end());

app.use(express.static(path.join(__dirname, 'public')));

app.get('*', (req, res) => {
  if (!req.user) {
    return res.status(401).send(`<!doctype html><meta charset=utf-8><title>BloomMoney</title>
<body style="font-family:system-ui;background:#0a0a0b;color:#e4e4e7;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0">
  <div style="max-width:24rem;padding:2rem;text-align:center">
    <h1 style="font-size:1.25rem;margin:0 0 .5rem">Open BloomMoney inside Usernode</h1>
    <p style="color:#71717a;font-size:.9rem;margin:0 0 1.25rem">This app requires the Usernode platform.</p>
    <a href="https://social-vibecoding.usernodelabs.org" style="display:inline-block;padding:.5rem 1rem;background:#0052ff;color:white;border-radius:.5rem;text-decoration:none;font-size:.9rem">Go to Usernode</a>
  </div></body>`);
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Schema + seed ─────────────────────────────────────────────────────────────

async function start() {
  // Create all tables
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      user_id INTEGER UNIQUE NOT NULL,
      username VARCHAR(255) UNIQUE NOT NULL,
      usernode_pubkey VARCHAR(255),
      display_name VARCHAR(255),
      bio TEXT,
      avatar_url TEXT,
      is_admin BOOLEAN DEFAULT FALSE,
      is_banned BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS wallet_balances (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL,
      token_symbol VARCHAR(20) NOT NULL,
      balance BIGINT NOT NULL DEFAULT 0,
      updated_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(user_id, token_symbol)
    );
    CREATE TABLE IF NOT EXISTS posts (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL,
      username VARCHAR(255) NOT NULL,
      content TEXT NOT NULL,
      parent_id INTEGER REFERENCES posts(id),
      like_count INTEGER DEFAULT 0,
      reply_count INTEGER DEFAULT 0,
      deleted BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS post_likes (
      id SERIAL PRIMARY KEY,
      post_id INTEGER NOT NULL REFERENCES posts(id),
      user_id INTEGER NOT NULL,
      UNIQUE(post_id, user_id)
    );
    CREATE TABLE IF NOT EXISTS follows (
      follower_id INTEGER NOT NULL,
      following_id INTEGER NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      PRIMARY KEY(follower_id, following_id)
    );
    CREATE TABLE IF NOT EXISTS market_prices (
      symbol VARCHAR(20) PRIMARY KEY,
      price_usd NUMERIC(20,6) NOT NULL,
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS price_history (
      id SERIAL PRIMARY KEY,
      symbol VARCHAR(20) NOT NULL,
      price_usd NUMERIC(20,6) NOT NULL,
      recorded_at TIMESTAMPTZ NOT NULL,
      UNIQUE(symbol, recorded_at)
    );
    CREATE TABLE IF NOT EXISTS defi_swaps (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL,
      from_token VARCHAR(20) NOT NULL,
      to_token VARCHAR(20) NOT NULL,
      from_amount BIGINT NOT NULL,
      to_amount BIGINT NOT NULL,
      rate NUMERIC(20,8) NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS defi_stakes (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL,
      token VARCHAR(20) NOT NULL DEFAULT 'BLOOM',
      amount BIGINT NOT NULL,
      apy_bps INTEGER NOT NULL DEFAULT 1200,
      staked_at TIMESTAMPTZ DEFAULT NOW(),
      unstaked_at TIMESTAMPTZ
    );
    CREATE TABLE IF NOT EXISTS defi_liquidity_positions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL,
      pool_id VARCHAR(40) NOT NULL,
      token_a_amount BIGINT NOT NULL,
      token_b_amount BIGINT NOT NULL,
      shares NUMERIC(20,8) NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      removed_at TIMESTAMPTZ
    );
    CREATE TABLE IF NOT EXISTS ico_offerings (
      id SERIAL PRIMARY KEY,
      token_name VARCHAR(100) NOT NULL,
      token_symbol VARCHAR(20) NOT NULL,
      description TEXT,
      price_per_token BIGINT NOT NULL,
      total_supply BIGINT NOT NULL,
      tokens_sold BIGINT DEFAULT 0,
      hard_cap BIGINT NOT NULL,
      raised BIGINT DEFAULT 0,
      status VARCHAR(20) DEFAULT 'active',
      created_by_user_id INTEGER NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS ico_investments (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL,
      ico_id INTEGER NOT NULL REFERENCES ico_offerings(id),
      tokens_purchased BIGINT NOT NULL,
      usdc_paid BIGINT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS opinion_markets (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT,
      resolution_criteria TEXT,
      yes_pool BIGINT DEFAULT 100000000,
      no_pool BIGINT DEFAULT 100000000,
      status VARCHAR(20) DEFAULT 'open',
      resolved_outcome VARCHAR(10),
      created_by_user_id INTEGER NOT NULL,
      closes_at TIMESTAMPTZ,
      resolved_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS opinion_positions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL,
      market_id INTEGER NOT NULL REFERENCES opinion_markets(id),
      outcome VARCHAR(3) NOT NULL,
      shares NUMERIC(20,8) NOT NULL,
      cost_basis BIGINT NOT NULL,
      claimed BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS futures_markets (
      id SERIAL PRIMARY KEY,
      symbol VARCHAR(20) UNIQUE NOT NULL,
      mark_price NUMERIC(20,6) NOT NULL,
      index_price NUMERIC(20,6) NOT NULL,
      funding_rate NUMERIC(10,6) DEFAULT 0.0001,
      open_interest BIGINT DEFAULT 0,
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS futures_positions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL,
      market_id INTEGER NOT NULL REFERENCES futures_markets(id),
      mode VARCHAR(10) NOT NULL DEFAULT 'paper',
      side VARCHAR(5) NOT NULL,
      leverage INTEGER NOT NULL DEFAULT 1,
      entry_price NUMERIC(20,6) NOT NULL,
      quantity NUMERIC(20,8) NOT NULL,
      margin BIGINT NOT NULL,
      liquidation_price NUMERIC(20,6) NOT NULL,
      realized_pnl BIGINT DEFAULT 0,
      status VARCHAR(20) DEFAULT 'open',
      opened_at TIMESTAMPTZ DEFAULT NOW(),
      closed_at TIMESTAMPTZ
    );
    CREATE TABLE IF NOT EXISTS paper_balances (
      user_id INTEGER PRIMARY KEY,
      usdc_balance BIGINT NOT NULL DEFAULT 10000000000
    );
    CREATE TABLE IF NOT EXISTS nfts (
      id SERIAL PRIMARY KEY,
      owner_user_id INTEGER NOT NULL,
      owner_username VARCHAR(255) NOT NULL,
      name VARCHAR(255) NOT NULL,
      description TEXT,
      image_url TEXT NOT NULL,
      token_id VARCHAR(64) UNIQUE NOT NULL,
      collection VARCHAR(100) DEFAULT 'BloomMoney Genesis',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      burned BOOLEAN DEFAULT FALSE
    );
    CREATE TABLE IF NOT EXISTS kyc_verifications (
      id SERIAL PRIMARY KEY,
      user_id INTEGER UNIQUE NOT NULL,
      level VARCHAR(20) NOT NULL DEFAULT 'basic',
      status VARCHAR(20) NOT NULL DEFAULT 'approved',
      document_type VARCHAR(50),
      biometric_consent BOOLEAN DEFAULT FALSE,
      rejection_reason TEXT,
      submitted_at TIMESTAMPTZ DEFAULT NOW(),
      reviewed_at TIMESTAMPTZ,
      reviewed_by_user_id INTEGER
    );
    CREATE TABLE IF NOT EXISTS admin_actions (
      id SERIAL PRIMARY KEY,
      admin_user_id INTEGER NOT NULL,
      action_type VARCHAR(50) NOT NULL,
      target_user_id INTEGER,
      target_post_id INTEGER,
      target_market_id INTEGER,
      reason TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS transactions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL,
      type VARCHAR(50) NOT NULL,
      token_symbol VARCHAR(20) NOT NULL,
      amount BIGINT NOT NULL,
      description TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS investment_holdings (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL,
      asset_name VARCHAR(150) NOT NULL,
      ticker VARCHAR(20),
      asset_type VARCHAR(20) NOT NULL,
      quantity NUMERIC(24,8) NOT NULL,
      purchase_price NUMERIC(20,6) NOT NULL,
      added_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS investment_holdings_user_idx ON investment_holdings (user_id);
    CREATE TABLE IF NOT EXISTS social_accounts (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL,
      provider VARCHAR(20) NOT NULL,
      provider_user_id VARCHAR(255) NOT NULL,
      handle VARCHAR(255),
      linked_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(user_id, provider),
      UNIQUE(provider, provider_user_id)
    );
    CREATE INDEX IF NOT EXISTS social_accounts_user_idx ON social_accounts (user_id);
    CREATE TABLE IF NOT EXISTS zk_verifications (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL UNIQUE,
      nullifier TEXT NOT NULL UNIQUE,
      zk_verified_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS opinion_market_snapshots (
      id SERIAL PRIMARY KEY,
      market_id INTEGER NOT NULL,
      yes_pct NUMERIC(8,3) NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS opinion_market_snapshots_market_idx ON opinion_market_snapshots (market_id, created_at DESC);
    CREATE TABLE IF NOT EXISTS futures_price_snapshots (
      id SERIAL PRIMARY KEY,
      market_id INTEGER NOT NULL,
      mark_price NUMERIC(20,6) NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS futures_price_snapshots_market_idx ON futures_price_snapshots (market_id, created_at DESC);
  `);

  // ── Phase 1/3 migrations (idempotent) ──────────────────────────────────────
  // Standardize verification vocabulary: verified→social, elite→premium.
  await pool.query("UPDATE kyc_verifications SET level='social' WHERE level='verified'");
  await pool.query("UPDATE kyc_verifications SET level='premium' WHERE level='elite'");
  await pool.query(`
    ALTER TABLE kyc_verifications ADD COLUMN IF NOT EXISTS provider VARCHAR(20);
    ALTER TABLE kyc_verifications ADD COLUMN IF NOT EXISTS attestation_ref TEXT;
    ALTER TABLE kyc_verifications ADD COLUMN IF NOT EXISTS anti_sybil_token TEXT;
    ALTER TABLE kyc_verifications ADD COLUMN IF NOT EXISTS verified_at TIMESTAMPTZ;
    ALTER TABLE futures_markets ADD COLUMN IF NOT EXISTS next_funding_at TIMESTAMPTZ;
    ALTER TABLE futures_markets ADD COLUMN IF NOT EXISTS last_funding_at TIMESTAMPTZ;
    ALTER TABLE futures_positions ADD COLUMN IF NOT EXISTS last_funding_at TIMESTAMPTZ;
  `);
  // UNIQUE on anti_sybil_token enforces one social account per wallet.
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS kyc_anti_sybil_uniq
    ON kyc_verifications (anti_sybil_token) WHERE anti_sybil_token IS NOT NULL
  `);

  // ico_offerings — scheduling and icon fields for Live/Upcoming/Completed grouping.
  await pool.query(`
    ALTER TABLE ico_offerings ADD COLUMN IF NOT EXISTS start_date TIMESTAMPTZ;
    ALTER TABLE ico_offerings ADD COLUMN IF NOT EXISTS end_date TIMESTAMPTZ;
    ALTER TABLE ico_offerings ADD COLUMN IF NOT EXISTS icon_url TEXT;
  `);

  // funding_payments — per-position funding settlements (Phase 3, private).
  await pool.query(`
    CREATE TABLE IF NOT EXISTS funding_payments (
      id SERIAL PRIMARY KEY,
      position_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      market_id INTEGER NOT NULL,
      amount BIGINT NOT NULL,
      rate NUMERIC(12,8) NOT NULL,
      mode VARCHAR(10) NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS idempotency_keys (
      user_id INTEGER NOT NULL,
      key VARCHAR(120) NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      PRIMARY KEY(user_id, key)
    );
  `);

  // Initialize the funding schedule for any market missing it.
  await pool.query(
    `UPDATE futures_markets SET next_funding_at=NOW() + ($1 || ' milliseconds')::interval
     WHERE next_funding_at IS NULL`, [String(FUNDING_INTERVAL_MS)]
  );

  // Privacy markings
  await pool.query(`
    COMMENT ON TABLE funding_payments IS 'staging:private';
    COMMENT ON TABLE idempotency_keys IS 'staging:private';
    COMMENT ON TABLE wallet_balances IS 'staging:private';
    COMMENT ON TABLE paper_balances IS 'staging:private';
    COMMENT ON TABLE defi_swaps IS 'staging:private';
    COMMENT ON TABLE defi_stakes IS 'staging:private';
    COMMENT ON TABLE defi_liquidity_positions IS 'staging:private';
    COMMENT ON TABLE ico_investments IS 'staging:private';
    COMMENT ON TABLE opinion_positions IS 'staging:private';
    COMMENT ON TABLE futures_positions IS 'staging:private';
    COMMENT ON TABLE kyc_verifications IS 'staging:private';
    COMMENT ON TABLE admin_actions IS 'staging:private';
    COMMENT ON TABLE transactions IS 'staging:private';
    COMMENT ON TABLE investment_holdings IS 'staging:private';
    COMMENT ON TABLE social_accounts IS 'staging:private';
    COMMENT ON TABLE zk_verifications IS 'staging:private';
  `);

  // Seed initial market prices
  await pool.query(`
    INSERT INTO market_prices(symbol,price_usd) VALUES
      ('ETH',2500),('BTC',67000),('BLOOM',0.5),('USDC',1)
    ON CONFLICT(symbol) DO NOTHING
  `);

  // Seed price history — 24 hourly data points per token using deterministic wave formulas.
  // Uses DATE_TRUNC so timestamps are hour-granular; ON CONFLICT skips existing rows within
  // the same boot hour, keeping the seed idempotent.
  await pool.query(`DELETE FROM price_history WHERE recorded_at < NOW() - interval '26 hours'`);
  const historyTokenDefs = [
    { symbol: 'ETH',   fn: (i) => (2500   * (1 + Math.sin(i * 0.45)     * 0.018)).toFixed(6) },
    { symbol: 'BTC',   fn: (i) => (67000  * (1 + Math.cos(i * 0.38)     * 0.020)).toFixed(6) },
    { symbol: 'BLOOM', fn: (i) => (0.5    * (1 + Math.sin(i * 0.52 + 1) * 0.030)).toFixed(6) },
    { symbol: 'USDC',  fn: ()  => '1.000000' },
  ];
  for (const t of historyTokenDefs) {
    const vals = [], params = [];
    for (let i = 0; i < 24; i++) {
      const hoursAgo = 24 - i; // i=0 → oldest (24h ago), i=23 → newest (1h ago)
      const idx = i * 3;
      vals.push(`($${idx+1}, $${idx+2}, DATE_TRUNC('hour', NOW()) - $${idx+3} * interval '1 hour')`);
      params.push(t.symbol, t.fn(i), hoursAgo);
    }
    await pool.query(
      `INSERT INTO price_history(symbol, price_usd, recorded_at) VALUES ${vals.join(',')} ON CONFLICT(symbol, recorded_at) DO NOTHING`,
      params
    );
  }

  // Seed futures markets
  await pool.query(`
    INSERT INTO futures_markets(symbol,mark_price,index_price) VALUES
      ('ETH-PERP',2500,2500),('BTC-PERP',67000,67000),('BLOOM-PERP',0.5,0.5)
    ON CONFLICT(symbol) DO NOTHING
  `);

  // Staging seed data
  if (IS_STAGING) {
    // Seed users
    await pool.query(`
      INSERT INTO users(user_id,username,usernode_pubkey,display_name,bio,is_admin) VALUES
        (9001,'staging-alice','0xSTAGING0000000000000000000000000000000001','Alice (Staging)','DeFi enthusiast on BloomMoney',false),
        (9002,'staging-bob','0xSTAGING0000000000000000000000000000000002','Bob (Staging)','NFT collector and trader',false),
        (9003,'staging-carol','0xSTAGING0000000000000000000000000000000003','Carol (Staging)','Prediction market oracle',false),
        (9004,'staging-dave','0xSTAGING0000000000000000000000000000000004','Dave (Staging)','Futures trading enthusiast',false),
        (9005,'staging-eve','0xSTAGING0000000000000000000000000000000005','Eve (Staging)','BLOOM staker since day one',false),
        (9006,'staging-admin','0xSTAGING0000000000000000000000000000000006','Admin (Staging)','Platform administrator',true)
      ON CONFLICT(user_id) DO NOTHING
    `);

    // Seed verifications (new vocabulary + social-OAuth providers). Each social
    // identity carries a unique synthetic anti_sybil_token so seeded users never
    // false-collide on the UNIQUE index.
    await pool.query(`
      INSERT INTO kyc_verifications(user_id,level,status,provider,attestation_ref,anti_sybil_token,verified_at) VALUES
        (9001,'social','approved','x','staging-x-9001','staging-social-9001',NOW()),
        (9002,'premium','approved','zkpassport','staging-zk-9002',NULL,NOW()),
        (9003,'social','pending','instagram','staging-instagram-9003','staging-social-9003',NULL),
        (9004,'basic','approved',NULL,NULL,NULL,NULL),
        (9005,'basic','approved',NULL,NULL,NULL,NULL),
        (9006,'premium','approved','zkpassport','staging-zk-9006',NULL,NOW())
      ON CONFLICT(user_id) DO NOTHING
    `);

    // Seed wallet balances
    for (const uid of [9001,9002,9003,9004,9005,9006]) {
      await pool.query(`
        INSERT INTO wallet_balances(user_id,token_symbol,balance) VALUES
          ($1,'USDC',5000000000),($1,'BLOOM',500000000),($1,'ETH',2000000),($1,'BTC',100000)
        ON CONFLICT DO NOTHING
      `, [uid]);
      await pool.query('INSERT INTO paper_balances(user_id) VALUES($1) ON CONFLICT DO NOTHING', [uid]);
    }

    // Seed posts
    const posts = [
      [9001,'Staging demo post #1 — BloomMoney is the future of onchain finance! 🌸'],
      [9002,'Staging demo post #2 — Just minted my first NFT on BloomMoney. The UI is incredible.'],
      [9003,'Staging demo post #3 — Opinion markets are live! Betting YES on ETH to $5k before 2027.'],
      [9004,'Staging demo post #4 — Paper trading BTC-PERP with 10x leverage. Up 23% today! 📈'],
      [9005,'Staging demo post #5 — Staking 500 BLOOM at 12% APY. Passive income is the way.'],
      [9001,'Staging demo post #6 — Swapped 100 USDC for 200 BLOOM. The rate is great right now!'],
      [9002,'Staging demo post #7 — Added liquidity to BLOOM/USDC pool. Earning fees every day.'],
      [9003,'Staging demo post #8 — Invested in the SDC ICO. Early adopter advantages are real.'],
      [9006,'Staging demo post #9 — Platform stats looking healthy. 500 trades in 24 hours!'],
      [9004,'Staging demo post #10 — Closed my ETH-PERP long for +15% PnL. BloomMoney futures rule!'],
    ];
    for (let i = 0; i < posts.length; i++) {
      const uid = posts[i][0];
      const uname = ['','staging-alice','staging-bob','staging-carol','staging-dave','staging-eve','staging-admin'][uid-9000];
      await pool.query(
        'INSERT INTO posts(id,user_id,username,content) VALUES($1,$2,$3,$4) ON CONFLICT(id) DO NOTHING',
        [900001+i, uid, uname, posts[i][1]]
      );
    }
    // Seed replies
    await pool.query(`
      INSERT INTO posts(id,user_id,username,content,parent_id) VALUES
        (900011,9002,'staging-bob','Staging demo reply — Same! BLOOM is only going up from here 🚀',900001),
        (900012,9003,'staging-carol','Staging demo reply — I agree, the swap fees are super low.',900001),
        (900013,9001,'staging-alice','Staging demo reply — Which collection? I want to see!',900002),
        (900014,9004,'staging-dave','Staging demo reply — I am in on that market too!',900003),
        (900015,9005,'staging-eve','Staging demo reply — What leverage are you using?',900004)
      ON CONFLICT(id) DO NOTHING
    `);
    await pool.query(`UPDATE posts SET reply_count=2 WHERE id=900001`);

    // Seed follows
    await pool.query(`
      INSERT INTO follows(follower_id,following_id) VALUES
        (9001,9002),(9001,9003),(9002,9001),(9003,9001),(9004,9001),(9005,9002)
      ON CONFLICT DO NOTHING
    `);

    // Seed opinion markets
    await pool.query(`
      INSERT INTO opinion_markets(id,title,description,resolution_criteria,yes_pool,no_pool,status,created_by_user_id,closes_at) VALUES
        (9001,'Will ETH hit $5,000 before 2027?','Ethereum price prediction market','Resolved YES if ETH/USD closes above $5,000 on any major exchange before January 1, 2027.',500000000,300000000,'open',9006,'2026-12-31 00:00:00+00'),
        (9002,'Will BLOOM token reach $2 within 90 days?','BloomMoney native token prediction','Resolved YES if BLOOM/USDC price exceeds $2.00 on BloomMoney.',100000000,100000000,'open',9006,'2026-09-20 00:00:00+00'),
        (9003,'Did Bitcoin ETF daily volume exceed $1B on 2026-06-01?','Bitcoin ETF volume milestone','Based on publicly reported ETF volume data for June 1, 2026.',400000000,50000000,'resolved',9006,NULL)
      ON CONFLICT(id) DO NOTHING
    `);
    await pool.query("UPDATE opinion_markets SET resolved_outcome='YES', resolved_at=NOW() WHERE id=9003");

    // Seed ICO offerings — one live (SDC existing), two more live, two upcoming, two completed.
    // Amounts are stored as BIGINT micro-units (value × 1_000_000). Dates use interval arithmetic
    // so countdowns render correctly on every staging preview.
    await pool.query(`
      INSERT INTO ico_offerings(id,token_name,token_symbol,description,price_per_token,total_supply,hard_cap,raised,tokens_sold,status,start_date,end_date,created_by_user_id) VALUES
        (9001,'Staging Demo Coin','SDC','Staging demo ICO — A simulated token offering for testing the BloomMoney ICO feature.',1000000,10000000000,5000000000,0,0,'active',NOW()-INTERVAL '3 days',NOW()+INTERVAL '7 days',9006),
        (9002,'Staging AquaFi Protocol','AQF','Staging demo ICO — Cross-chain liquidity layer for DeFi aggregation.',50000,40000000000000,2000000000000,1400000000000,28000000000000,'active',NOW()-INTERVAL '5 days',NOW()+INTERVAL '9 days',9006),
        (9003,'Staging VaultX','VLX','Staging demo ICO — Automated yield optimizer with auto-compounding vaults.',120000,25000000000000,3000000000000,600000000000,5000000000000,'active',NOW()-INTERVAL '2 days',NOW()+INTERVAL '12 days',9006),
        (9004,'Staging NovaMesh','NVM','Staging demo ICO — Decentralized compute mesh for AI inference workloads.',80000,62500000000000,5000000000000,0,0,'upcoming',NOW()+INTERVAL '7 days',NOW()+INTERVAL '21 days',9006),
        (9005,'Staging ChainSpark','CSP','Staging demo ICO — Play-to-earn gaming platform with onchain asset ownership.',30000,50000000000000,1500000000000,0,0,'upcoming',NOW()+INTERVAL '14 days',NOW()+INTERVAL '28 days',9006),
        (9006,'Staging PixelDAO','PXD','Staging demo ICO — NFT governance DAO with fractionalized art vaults.',250000,4000000000000,1000000000000,1000000000000,4000000000000,'sold_out',NOW()-INTERVAL '60 days',NOW()-INTERVAL '30 days',9006),
        (9007,'Staging ZephyrNet','ZPN','Staging demo ICO — Layer 2 scaling solution for microtransactions.',100000,40000000000000,4000000000000,2700000000000,27000000000000,'ended',NOW()-INTERVAL '90 days',NOW()-INTERVAL '45 days',9006)
      ON CONFLICT(id) DO NOTHING
    `);

    // Seed NFTs
    await pool.query(`
      INSERT INTO nfts(id,owner_user_id,owner_username,name,description,image_url,token_id) VALUES
        (9001,9001,'staging-alice','Staging Genesis #1','Staging demo NFT — The first BloomMoney genesis token.','https://placehold.co/400x400/0052ff/ffffff?text=BLOOM+NFT+1','BLOOM-00002329'),
        (9002,9002,'staging-bob','Staging Genesis #2','Staging demo NFT — Second genesis token.','https://placehold.co/400x400/7c3aed/ffffff?text=BLOOM+NFT+2','BLOOM-0000232A'),
        (9003,9003,'staging-carol','Staging Rare Bloom','Staging demo NFT — A rare bloom flower.','https://placehold.co/400x400/059669/ffffff?text=RARE+BLOOM','BLOOM-0000232B'),
        (9004,9004,'staging-dave','Staging Bull Run','Staging demo NFT — Commemorating the 2026 bull run.','https://placehold.co/400x400/dc2626/ffffff?text=BULL+RUN','BLOOM-0000232C')
      ON CONFLICT(id) DO NOTHING
    `);

    // Seed investment holdings
    await pool.query(`
      INSERT INTO investment_holdings(id,user_id,asset_name,ticker,asset_type,quantity,purchase_price) VALUES
        (900101,9001,'Staging demo holding — Ethereum','ETH','crypto',2.0,2200.0),
        (900102,9001,'Staging demo holding — BloomMoney Token','BLOOM','crypto',10.0,0.40),
        (900103,9002,'Staging demo holding — Bitcoin','BTC','crypto',0.05,60000.0),
        (900104,9002,'Staging demo holding — Apple Inc.','AAPL','stock',5.0,185.0),
        (900105,9003,'Staging demo holding — BloomMoney Token','BLOOM','crypto',100.0,0.35),
        (900106,9003,'Staging demo holding — Ethereum','ETH','crypto',1.0,2100.0),
        (900107,9004,'Staging demo holding — Bitcoin','BTC','crypto',0.1,65000.0),
        (900108,9005,'Staging demo holding — BloomMoney Token','BLOOM','crypto',500.0,0.30),
        (900109,9005,'Staging demo holding — Ethereum','ETH','crypto',2.0,2300.0)
      ON CONFLICT(id) DO NOTHING
    `);

    // Seed social account links (staging-alice and staging-bob have linked accounts)
    await pool.query(`
      INSERT INTO social_accounts(user_id, provider, provider_user_id, handle) VALUES
        (9001,'twitter','staging-twitter-9001','@staging-alice'),
        (9001,'github','staging-github-9001','staging-gh-alice'),
        (9002,'google','staging-google-9002','Alice Staging'),
        (9003,'discord','staging-discord-9003','staging-carol#9003'),
        (9004,'github','staging-github-9004','staging-gh-dave')
      ON CONFLICT(user_id, provider) DO NOTHING
    `);

    // Seed zkPassport verifications (staging-bob and staging-dave are ZK verified)
    await pool.query(`
      INSERT INTO zk_verifications(user_id, nullifier) VALUES
        (9002,'staging-zk-nullifier-9002'),
        (9004,'staging-zk-nullifier-9004')
      ON CONFLICT(user_id) DO NOTHING
    `);
    // Seed premium kyc tier for staging-dave (9002 is already seeded as premium above)
    await pool.query(`
      INSERT INTO kyc_verifications(user_id,level,status,provider,attestation_ref,verified_at)
      VALUES (9004,'premium','approved','zkpassport','staging-zk-session-9004',NOW())
      ON CONFLICT(user_id) DO UPDATE SET level='premium', status='approved',
        provider='zkpassport', attestation_ref='staging-zk-session-9004', verified_at=NOW()
    `);

    // Seed open futures positions (one paper, one live) so PnL + funding
    // columns render, plus a little funding history.
    const ethFut = (await pool.query("SELECT id, mark_price FROM futures_markets WHERE symbol='ETH-PERP'")).rows[0];
    const btcFut = (await pool.query("SELECT id, mark_price FROM futures_markets WHERE symbol='BTC-PERP'")).rows[0];
    if (ethFut && btcFut) {
      await pool.query(`
        INSERT INTO futures_positions(id,user_id,market_id,mode,side,leverage,entry_price,quantity,margin,liquidation_price,status,last_funding_at) VALUES
          (900001,9001,$1,'live','long',5,2400,1.0,480000000,1968,'open',NOW()),
          (900002,9004,$2,'paper','short',10,68000,0.05,340000000,74800,'open',NOW())
        ON CONFLICT(id) DO NOTHING
      `, [ethFut.id, btcFut.id]);
      await pool.query(`
        INSERT INTO funding_payments(id,position_id,user_id,market_id,amount,rate,mode) VALUES
          (900001,900001,9001,$1,-240,0.0001,'live'),
          (900002,900002,9004,$2,170,0.0001,'paper')
        ON CONFLICT(id) DO NOTHING
      `, [ethFut.id, btcFut.id]);
      await pool.query(`
        INSERT INTO transactions(user_id,type,token_symbol,amount,description)
        SELECT * FROM (VALUES
          (9001,'funding','USDC',-240,'Staging demo funding ETH-PERP'),
          (9004,'funding','USDC',170,'Staging demo funding BTC-PERP')
        ) v(user_id,type,token_symbol,amount,description)
        WHERE NOT EXISTS (SELECT 1 FROM transactions WHERE description='Staging demo funding ETH-PERP')
      `).catch(() => {});

    // Seed activity transactions for the Activity tab (covers all types)
    {
      const { rows: [exist] } = await pool.query(
        `SELECT 1 FROM transactions WHERE description='Staging demo swap — Swap USDC to BLOOM' LIMIT 1`
      );
      if (!exist) {
        await pool.query(`
          INSERT INTO transactions(id, user_id, type, token_symbol, amount, description) VALUES
            (900201, 9001, 'swap',         'USDC', -100000000, 'Staging demo swap — Swap USDC to BLOOM'),
            (900202, 9001, 'swap',         'USDC',  -75000000, 'Staging demo swap — Swap USDC to ETH'),
            (900203, 9001, 'swap',         'BLOOM', -50000000, 'Staging demo swap — Swap BLOOM to USDC'),
            (900204, 9001, 'swap',         'USDC', -200000000, 'Staging demo swap — Swap USDC to BTC'),
            (900205, 9001, 'swap',         'ETH',     -500000, 'Staging demo swap — Swap ETH to USDC'),
            (900206, 9004, 'futures_open', 'USDC', -480000000, 'Staging demo futures — Open ETH-PERP Long 5x'),
            (900207, 9004, 'futures_pnl',  'USDC',  72000000, 'Staging demo futures — Close ETH-PERP +15% PnL'),
            (900208, 9004, 'futures_open', 'USDC', -340000000, 'Staging demo futures — Open BTC-PERP Short 10x'),
            (900209, 9003, 'market_trade', 'USDC',  -50000000, 'Staging demo prediction — Bought YES on Will ETH hit $5k'),
            (900210, 9003, 'market_trade', 'USDC',  -25000000, 'Staging demo prediction — Bought NO on Will BLOOM reach $2'),
            (900211, 9003, 'ico_invest',   'USDC', -100000000, 'Staging demo ICO — Invested in SDC ICO')
          ON CONFLICT(id) DO NOTHING
        `);
      }
    }
    }

    // Seed opinion market snapshots
    {
      const { rows: [cnt] } = await pool.query('SELECT COUNT(*)::int AS n FROM opinion_market_snapshots WHERE market_id IN (9001,9002,9003)');
      if (cnt.n === 0) {
        const opinionSeeds = [
          ...[ 62.5, 61.2, 63.1, 62.4, 64.2, 63.7, 61.9, 63.5, 62.1, 64.0, 63.2, 62.7, 61.5, 63.8, 64.5, 62.9, 63.4, 61.8, 62.6, 63.1 ].map((v,i) => `(9001,${v},NOW()-INTERVAL '${(20-i)*5} minutes')`),
          ...[ 50.0, 51.2, 49.8, 50.5, 48.9, 50.3, 51.1, 49.5, 50.8, 49.2, 50.6, 51.3, 49.7, 50.1, 48.8, 50.9, 51.5, 49.4, 50.2, 50.7 ].map((v,i) => `(9002,${v},NOW()-INTERVAL '${(20-i)*5} minutes')`),
          ...Array.from({length:10},(_,i)=>`(9003,88.9,NOW()-INTERVAL '${(10-i)*5} minutes')`),
        ];
        await pool.query(`INSERT INTO opinion_market_snapshots(market_id,yes_pct,created_at) VALUES ${opinionSeeds.join(',')}`);
      }
    }
    // Seed futures price snapshots
    {
      const { rows: [cnt] } = await pool.query(`SELECT COUNT(*)::int AS n FROM futures_price_snapshots WHERE market_id IN (SELECT id FROM futures_markets WHERE symbol IN ('ETH-PERP','BTC-PERP','BLOOM-PERP'))`);
      if (cnt.n === 0) {
        const fmkts = (await pool.query(`SELECT id, symbol FROM futures_markets WHERE symbol IN ('ETH-PERP','BTC-PERP','BLOOM-PERP')`)).rows;
        const seedRows = [];
        for (const fm of fmkts) {
          let base = fm.symbol==='ETH-PERP'?2490:fm.symbol==='BTC-PERP'?66800:0.499;
          for (let i=0;i<30;i++) {
            const t = 870-i*30;
            base = base * (i%2===0 ? 1.001 : 0.999);
            seedRows.push(`(${fm.id},${base.toFixed(6)},NOW()-INTERVAL '${t} seconds')`);
          }
        }
        if (seedRows.length) await pool.query(`INSERT INTO futures_price_snapshots(market_id,mark_price,created_at) VALUES ${seedRows.join(',')}`);
      }
    }
  }

  app.listen(port, () => console.log(`BloomMoney listening on :${port}`));
}

start().catch(err => { console.error(err); process.exit(1); });
