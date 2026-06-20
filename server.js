const express = require('express');
const path = require('path');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 3000;
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const JWT_SECRET = process.env.JWT_SECRET;
const IS_STAGING = process.env.USERNODE_ENV === 'staging';
const BLOOM_ADMIN = process.env.BLOOM_ADMIN_USERNAME || '';
const UNITS = 1_000_000;

const PUBLIC_API_PATHS = new Set(['/health']);
const PUBLIC_PREFIXES = ['/explorer-api/'];

app.use(express.json());

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

app.get('/health', (_, res) => res.json({ status: 'ok' }));

// ── Helpers ──────────────────────────────────────────────────────────────────

async function upsertUser(u) {
  const isAdmin = BLOOM_ADMIN && u.username === BLOOM_ADMIN;
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
          updated_at = NOW()
    `);
    const { rows } = await pool.query(`
      SELECT fp.id, fp.side, fp.liquidation_price::float, fp.margin, fp.user_id, fp.mode,
             fm.mark_price::float
      FROM futures_positions fp
      JOIN futures_markets fm ON fp.market_id = fm.id
      WHERE fp.status = 'open'
    `);
    for (const p of rows) {
      const liq = (p.side === 'long' && p.mark_price <= p.liquidation_price) ||
                  (p.side === 'short' && p.mark_price >= p.liquidation_price);
      if (!liq) continue;
      await pool.query(
        "UPDATE futures_positions SET status='liquidated', realized_pnl=$1, closed_at=NOW() WHERE id=$2",
        [-p.margin, p.id]
      );
      await pool.query(
        "INSERT INTO transactions(user_id,type,token_symbol,amount,description) VALUES($1,'futures_pnl','USDC',$2,'Position liquidated')",
        [p.user_id, -p.margin]
      );
    }
  } catch (e) { console.error('drift err:', e.message); }
}, 30000);

// ── /api/me ───────────────────────────────────────────────────────────────────

app.get('/api/me', async (req, res) => {
  try {
    await upsertUser(req.user);
    await ensureBalances(req.user.id, req.user.usernode_pubkey);
    const [{ rows: [user] }, { rows: bals }, { rows: [kyc] }] = await Promise.all([
      pool.query('SELECT * FROM users WHERE user_id=$1', [req.user.id]),
      pool.query('SELECT token_symbol, balance FROM wallet_balances WHERE user_id=$1', [req.user.id]),
      pool.query('SELECT * FROM kyc_verifications WHERE user_id=$1', [req.user.id]),
    ]);
    res.json({ user, balances: bals, kyc: kyc || null });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/me', async (req, res) => {
  try {
    const { display_name, bio } = req.body;
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
        SELECT p.* FROM posts p
        WHERE p.parent_id IS NULL AND p.deleted = false
          AND (p.user_id = $1 OR p.user_id IN (SELECT following_id FROM follows WHERE follower_id=$1))
          ${cursorClause}
        ORDER BY p.id DESC LIMIT $2
      `, params));
    } else {
      const params = [lim];
      const cursorClause = cursor ? `AND p.id < $${params.push(cursor)}` : '';
      ({ rows } = await pool.query(`
        SELECT p.* FROM posts p
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

// ── DeFi: Swap ────────────────────────────────────────────────────────────────

app.post('/api/defi/swap', requireWallet, async (req, res) => {
  const client = await pool.connect();
  try {
    const { from_token, to_token, from_amount } = req.body;
    const supported = ['USDC', 'BLOOM', 'ETH', 'BTC'];
    if (!supported.includes(from_token) || !supported.includes(to_token) || from_token === to_token)
      return res.status(400).json({ error: 'Invalid tokens' });

    const fromUnitsAmt = toUnits(from_amount);
    if (fromUnitsAmt <= 0) return res.status(400).json({ error: 'Invalid amount' });

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
    const usdcUnits = toUnits(usdc_amount);
    if (usdcUnits <= 0) return res.status(400).json({ error: 'Invalid amount' });
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

app.post('/api/markets/:id/trade', requireWallet, async (req, res) => {
  const client = await pool.connect();
  try {
    const { outcome, usdc_amount } = req.body;
    if (!['YES', 'NO'].includes(outcome)) return res.status(400).json({ error: 'Invalid outcome' });
    const usdcUnits = toUnits(usdc_amount);
    if (usdcUnits <= 0) return res.status(400).json({ error: 'Invalid amount' });
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
    await client.query('COMMIT');
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
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Futures ────────────────────────────────────────────────────────────────────

app.get('/api/futures/markets', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM futures_markets ORDER BY id');
    res.json({ markets: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/futures/positions', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT fp.*, fm.symbol, fm.mark_price::float
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
    const { market_id, side, leverage, quantity, mode } = req.body;
    const lev = Math.max(1, Math.min(20, parseInt(leverage) || 1));
    const qty = parseFloat(quantity);
    if (!qty || qty <= 0) return res.status(400).json({ error: 'Invalid quantity' });
    if (!['long', 'short'].includes(side)) return res.status(400).json({ error: 'Invalid side' });
    if (!['paper', 'live'].includes(mode)) return res.status(400).json({ error: 'Invalid mode' });

    if (mode === 'live') {
      const { rows: [kyc] } = await pool.query('SELECT level FROM kyc_verifications WHERE user_id=$1', [req.user.id]);
      if (!kyc || kyc.level === 'basic') return res.status(403).json({ error: 'Live trading requires Verified KYC' });
      if (lev > 5 && kyc.level !== 'elite') return res.status(403).json({ error: 'Leverage >5x requires Elite KYC' });
    }

    await client.query('BEGIN');
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
    if (!name || !image_url) return res.status(400).json({ error: 'Name and image_url required' });
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
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/users/:id/admin', requireAdmin, async (req, res) => {
  try {
    await pool.query('UPDATE users SET is_admin=NOT is_admin WHERE user_id=$1', [req.params.id]);
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
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/ico', requireAdmin, async (req, res) => {
  try {
    const { token_name, token_symbol, description, price_per_token, total_supply, hard_cap } = req.body;
    const { rows: [ico] } = await pool.query(`
      INSERT INTO ico_offerings(token_name,token_symbol,description,price_per_token,total_supply,hard_cap,created_by_user_id)
      VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *
    `, [token_name, token_symbol, description || '', toUnits(price_per_token), toUnits(total_supply), toUnits(hard_cap), req.user.id]);
    res.json({ ico });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/admin/ico/:id', requireAdmin, async (req, res) => {
  try {
    await pool.query("UPDATE ico_offerings SET status='ended' WHERE id=$1", [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/markets', requireAdmin, async (req, res) => {
  try {
    const { title, description, resolution_criteria, closes_at } = req.body;
    const { rows: [market] } = await pool.query(`
      INSERT INTO opinion_markets(title,description,resolution_criteria,closes_at,created_by_user_id)
      VALUES($1,$2,$3,$4,$5) RETURNING *
    `, [title, description || '', resolution_criteria || '', closes_at || null, req.user.id]);
    res.json({ market });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Static + HTML shell ────────────────────────────────────────────────────────

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
  `);

  // Privacy markings
  await pool.query(`
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
  `);

  // Seed initial market prices
  await pool.query(`
    INSERT INTO market_prices(symbol,price_usd) VALUES
      ('ETH',2500),('BTC',67000),('BLOOM',0.5),('USDC',1)
    ON CONFLICT(symbol) DO NOTHING
  `);

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

    // Seed KYC
    await pool.query(`
      INSERT INTO kyc_verifications(user_id,level,status) VALUES
        (9001,'verified','approved'),(9002,'elite','approved'),
        (9003,'verified','pending'),(9004,'basic','approved'),
        (9005,'basic','approved'),(9006,'elite','approved')
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
    await pool.query(`UPDATE posts SET reply_count=2 WHERE id=900001 ON CONFLICT DO NOTHING`);

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

    // Seed ICO
    await pool.query(`
      INSERT INTO ico_offerings(id,token_name,token_symbol,description,price_per_token,total_supply,hard_cap,status,created_by_user_id) VALUES
        (9001,'Staging Demo Coin','SDC','Staging demo ICO — A simulated token offering for testing the BloomMoney ICO feature.',1000000,10000000000,5000000000,'active',9006)
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
  }

  app.listen(port, () => console.log(`BloomMoney listening on :${port}`));
}

start().catch(err => { console.error(err); process.exit(1); });
