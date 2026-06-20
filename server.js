const express = require('express');
const path = require('path');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 3000;
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const JWT_SECRET = process.env.JWT_SECRET;

const IS_STAGING = process.env.USERNODE_ENV === 'staging';

// Fixed zkPassport scope for this app. The unique identifier (nullifier) a
// proof yields is bound to (ID data + verifying domain + this scope), so
// keeping it constant gives a stable one-human-one-account anchor.
const ZKP_SCOPE = 'bloommoney-verified-human';

// Paths that stay open without authentication. Add a path here (and add it
// with `app.get`/`app.post` below) if you deliberately want it public.
// Everything else requires a valid platform-issued JWT.
const PUBLIC_API_PATHS = new Set(['/health']);

app.use(express.json());

// Verify platform-issued JWT if one was passed, then enforce auth on
// anything not explicitly marked public. The iframe adds `?token=…`
// on load; the frontend script forwards the token via `x-usernode-token`
// on subsequent fetches.
app.use((req, res, next) => {
  const token = req.query.token || req.headers['x-usernode-token'];
  if (token && JWT_SECRET) {
    try { req.user = jwt.verify(token, JWT_SECRET); } catch {}
  }

  // Static assets (CSS/JS/images) are always served; the API and the HTML
  // shell are gated so direct hits to the staging/prod subdomain don't
  // leak app data to the public internet.
  if (req.method !== 'GET' || req.path.startsWith('/api/')) {
    if (PUBLIC_API_PATHS.has(req.path)) return next();
    if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
  }
  next();
});

app.get('/health', (_req, res) => res.json({ status: 'ok' }));

// Current user: username + whether they hold the verified-human badge, plus
// the staging flag so the frontend knows to offer the simulated proof path.
app.get('/api/me', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT 1 FROM human_verifications WHERE user_id = $1`,
      [req.user.id]
    );
    res.json({
      username: req.user.username,
      verified: rows.length > 0,
      staging: IS_STAGING,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Button press
app.post('/api/press', async (req, res) => {
  try {
    await pool.query(`
      INSERT INTO presses (user_id, username) VALUES ($1, $2)
    `, [req.user.id, req.user.username]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Leaderboard — press counts per user, plus a verified-human flag derived
// from the (private) human_verifications table. Only the boolean is exposed;
// the raw unique_identifier never leaves the server.
app.get('/api/leaderboard', async (_req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT p.username,
             COUNT(*) AS presses,
             BOOL_OR(hv.user_id IS NOT NULL) AS verified
      FROM presses p
      LEFT JOIN human_verifications hv ON hv.user_id = p.user_id
      GROUP BY p.username
      ORDER BY presses DESC
      LIMIT 50
    `);
    res.json({ leaderboard: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Record a verified-human proof and award the badge.
//
// Production: the client gathers a zkPassport proof on the user's phone and
// POSTs { proofs, query, queryResult }. We re-verify server-side (client
// `verified` is not trustworthy) and persist the returned uniqueIdentifier.
//
// Staging: real passport scanning is impossible, so a strictly staging-gated
// branch (`demo: true`) skips the SDK and mints a synthetic identifier so the
// badge flow is reviewable. This branch is a hard no-op in production.
app.post('/api/verify-human', async (req, res) => {
  try {
    let uniqueIdentifier;

    if (IS_STAGING && req.body && req.body.demo === true) {
      // Simulated verification — synthetic, deterministic per user so the
      // unique index still meaningfully enforces one row per identity.
      uniqueIdentifier = `staging-demo-${req.user.id}`;
    } else {
      const { proofs, query, queryResult } = req.body || {};
      if (!proofs || !query || !queryResult) {
        return res.status(400).json({ error: 'Missing proof payload.' });
      }

      let ZKPassport;
      try {
        ({ ZKPassport } = require('@zkpassport/sdk'));
      } catch (e) {
        return res.status(503).json({ error: 'Verification service unavailable.' });
      }

      // Domain must match the client-side domain and isn't auto-detected
      // server-side, so pass the request host explicitly.
      const domain = (req.headers.host || '').split(':')[0];
      const zkPassport = new ZKPassport(domain);
      const result = await zkPassport.verify({
        proofs,
        originalQuery: query,
        queryResult,
        scope: ZKP_SCOPE,
      });

      // Guard the historical "unsupported ID returns verified:true" bug:
      // require both a passing verification AND a present uniqueIdentifier.
      if (!result || !result.verified || !result.uniqueIdentifier) {
        return res.status(400).json({ error: 'Could not verify proof.' });
      }
      uniqueIdentifier = result.uniqueIdentifier;
    }

    // Sybil enforcement: if this human is already linked to a different
    // account, refuse rather than silently moving the badge.
    const owner = await pool.query(
      `SELECT user_id FROM human_verifications WHERE unique_identifier = $1`,
      [uniqueIdentifier]
    );
    if (owner.rows.length && owner.rows[0].user_id !== req.user.id) {
      return res.status(409).json({
        error: 'This identity is already linked to another BloomMoney account.',
      });
    }

    await pool.query(`
      INSERT INTO human_verifications (user_id, username, unique_identifier)
      VALUES ($1, $2, $3)
      ON CONFLICT (user_id)
      DO UPDATE SET username = EXCLUDED.username,
                    unique_identifier = EXCLUDED.unique_identifier,
                    verified_at = NOW()
    `, [req.user.id, req.user.username, uniqueIdentifier]);

    res.json({ verified: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.use(express.static(path.join(__dirname, 'public')));

// HTML shell: serve the app if authenticated, otherwise an "open in Usernode"
// landing page so stray visits to the staging URL don't reveal the app.
app.get('*', (req, res) => {
  if (!req.user) {
    return res.status(401).send(`<!doctype html><meta charset=utf-8><title>Open in Usernode</title>
<body style="font-family:system-ui;background:#f8fafc;color:#0f172a;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0">
  <div style="max-width:24rem;padding:2rem;text-align:center">
    <h1 style="font-size:1.25rem;margin:0 0 0.5rem">Open this app inside Usernode</h1>
    <p style="color:#64748b;font-size:0.9rem;margin:0 0 1.25rem">This page is served via the platform; direct visits aren't authenticated.</p>
    <a href="https://social-vibecoding.usernodelabs.org" style="display:inline-block;padding:0.5rem 1rem;background:#0052FF;color:white;border-radius:0.5rem;text-decoration:none;font-size:0.9rem">Go to Usernode</a>
  </div>
</body>`);
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

async function start() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS presses (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL,
      username VARCHAR(255) NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  // Verified-human records. Holds the zkPassport unique_identifier (a
  // privacy-relevant nullifier), so the table is marked private: staging
  // gets schema-only (no rows) and we seed fake rows below.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS human_verifications (
      user_id INTEGER PRIMARY KEY,
      username VARCHAR(255) NOT NULL,
      unique_identifier TEXT NOT NULL,
      verified_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS human_verifications_unique_identifier_idx
    ON human_verifications (unique_identifier)
  `);
  await pool.query(`COMMENT ON TABLE human_verifications IS 'staging:private'`);

  if (IS_STAGING) {
    await seedStaging();
  }

  app.listen(port, () => console.log(`Listening on :${port}`));
}

// Obviously-fake data so the redesigned leaderboard + badges render in a
// fresh staging DB. Idempotent: presses are guarded by an existence check
// (no natural conflict key), verifications use ON CONFLICT DO NOTHING.
async function seedStaging() {
  const demoUsers = [
    { id: -101, username: 'Staging demo · Ada', presses: 12, verified: true },
    { id: -102, username: 'Staging demo · Bo', presses: 7, verified: false },
    { id: -103, username: 'Staging demo · Cy', presses: 9, verified: true },
  ];

  const already = await pool.query(
    `SELECT 1 FROM presses WHERE username = $1 LIMIT 1`,
    [demoUsers[0].username]
  );
  if (!already.rows.length) {
    for (const u of demoUsers) {
      await pool.query(
        `INSERT INTO presses (user_id, username)
         SELECT $1, $2 FROM generate_series(1, $3)`,
        [u.id, u.username, u.presses]
      );
    }
  }

  for (const u of demoUsers) {
    if (!u.verified) continue;
    await pool.query(
      `INSERT INTO human_verifications (user_id, username, unique_identifier)
       VALUES ($1, $2, $3)
       ON CONFLICT (user_id) DO NOTHING`,
      [u.id, u.username, `staging-demo-${u.id}`]
    );
  }
}

start().catch(err => { console.error(err); process.exit(1); });
