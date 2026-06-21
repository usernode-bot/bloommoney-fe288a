// Verification provider adapters for BloomMoney.
//
// Social tier  -> social-media OAuth (X / Instagram / TikTok / Coinbase).
// Premium tier -> zkPassport proof (legacy) or session-based QR flow (new).
// Social linking -> link Twitter/Google/Discord/GitHub for profile badges.
//
// In staging (USERNODE_ENV=staging) we NEVER call real OAuth / external
// services — the flow is auto-approved with synthetic, per-user tokens so it
// is exercisable end-to-end against an empty DB. In production each provider
// is only "enabled" when its OAuth client credentials are present in the
// environment; absent creds degrade gracefully instead of crashing.

const crypto = require('crypto');

const IS_STAGING = process.env.USERNODE_ENV === 'staging';
const STATE_SECRET = process.env.JWT_SECRET || 'bloom-dev-state-secret';

// ── Social-tier verification providers (KYC upgrade) ─────────────────────────
const SOCIAL_PROVIDERS = ['x', 'instagram', 'tiktok', 'coinbase'];

// ── Account-linking providers (display badges, no tier change) ───────────────
const LINK_PROVIDERS = ['twitter', 'google', 'discord', 'github'];

// Per-provider OAuth config. envKey maps to {KEY}_OAUTH_CLIENT_ID / _SECRET env vars.
const PROVIDER_OAUTH = {
  // Social-tier verification providers
  x: {
    authorize: 'https://twitter.com/i/oauth2/authorize',
    token: 'https://api.twitter.com/2/oauth2/token',
    userinfo: 'https://api.twitter.com/2/users/me',
    scope: 'users.read tweet.read',
    envKey: 'X',
  },
  instagram: {
    authorize: 'https://api.instagram.com/oauth/authorize',
    scope: 'user_profile',
    envKey: 'INSTAGRAM',
  },
  tiktok: {
    authorize: 'https://www.tiktok.com/v2/auth/authorize/',
    scope: 'user.info.basic',
    envKey: 'TIKTOK',
  },
  coinbase: {
    authorize: 'https://login.coinbase.com/oauth2/auth',
    scope: 'wallet:user:read',
    envKey: 'COINBASE',
  },
  // Account-linking providers (twitter reuses X OAuth credentials)
  twitter: {
    authorize: 'https://twitter.com/i/oauth2/authorize',
    token: 'https://api.twitter.com/2/oauth2/token',
    userinfo: 'https://api.twitter.com/2/users/me',
    scope: 'users.read tweet.read',
    envKey: 'X',
  },
  google: {
    authorize: 'https://accounts.google.com/o/oauth2/v2/auth',
    token: 'https://oauth2.googleapis.com/token',
    userinfo: 'https://www.googleapis.com/oauth2/v3/userinfo',
    scope: 'openid profile',
    envKey: 'GOOGLE',
  },
  discord: {
    authorize: 'https://discord.com/api/oauth2/authorize',
    token: 'https://discord.com/api/oauth2/token',
    userinfo: 'https://discord.com/api/users/@me',
    scope: 'identify',
    envKey: 'DISCORD',
  },
  github: {
    authorize: 'https://github.com/login/oauth/authorize',
    token: 'https://github.com/login/oauth/access_token',
    userinfo: 'https://api.github.com/user',
    scope: 'read:user',
    envKey: 'GITHUB',
  },
};

function isSocialProvider(p) { return SOCIAL_PROVIDERS.includes(p); }
function isLinkProvider(p) { return LINK_PROVIDERS.includes(p); }

function providerConfigured(provider) {
  if (!isSocialProvider(provider)) return false;
  const key = provider.toUpperCase();
  return !!(process.env[`${key}_OAUTH_CLIENT_ID`] && process.env[`${key}_OAUTH_CLIENT_SECRET`]);
}

function providerLinkConfigured(provider) {
  if (!isLinkProvider(provider)) return false;
  const cfg = PROVIDER_OAUTH[provider];
  if (!cfg) return false;
  const key = cfg.envKey;
  return !!(process.env[`${key}_OAUTH_CLIENT_ID`] && process.env[`${key}_OAUTH_CLIENT_SECRET`]);
}

function configuredSocialProviders() {
  return SOCIAL_PROVIDERS.filter(providerConfigured);
}

const SOCIAL_VERIFY_ENABLED = IS_STAGING || configuredSocialProviders().length > 0;
const ZK_VERIFY_ENABLED = IS_STAGING || !!process.env.ZKPASSPORT_API_KEY;

function antiSybilToken(provider, accountId) {
  return crypto.createHash('sha256').update(`${provider}:${accountId}`).digest('hex');
}

function signState(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', STATE_SECRET).update(body).digest('base64url');
  return `${body}.${sig}`;
}

function verifyState(state) {
  if (typeof state !== 'string' || !state.includes('.')) return null;
  const [body, sig] = state.split('.');
  const expected = crypto.createHmac('sha256', STATE_SECRET).update(body).digest('base64url');
  if (sig.length !== expected.length) return null;
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  try {
    return JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
}

// ── Social-tier OAuth (KYC upgrade: x/instagram/tiktok/coinbase) ─────────────

function startSocialOAuth(provider, userId) {
  if (!isSocialProvider(provider)) return { ok: false, error: 'invalid_provider' };

  const issuedAt = Date.now();
  const nonce = crypto.randomBytes(8).toString('hex');
  const state = signState({ provider, userId, issuedAt, nonce });

  if (IS_STAGING) {
    return { ok: true, oauth_url: `bloom://verify/social/${provider}?state=${encodeURIComponent(state)}`, state, simulated: true };
  }

  if (!providerConfigured(provider)) return { ok: false, error: 'provider_unavailable' };

  const cfg = PROVIDER_OAUTH[provider];
  const clientId = process.env[`${provider.toUpperCase()}_OAUTH_CLIENT_ID`];
  const redirectUri = process.env.BLOOM_OAUTH_REDIRECT_URI || '';
  const url = new URL(cfg.authorize);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', clientId);
  if (redirectUri) url.searchParams.set('redirect_uri', redirectUri);
  url.searchParams.set('scope', cfg.scope);
  url.searchParams.set('state', state);
  return { ok: true, oauth_url: url.toString(), state };
}

async function completeSocialOAuth(provider, code, state) {
  if (!isSocialProvider(provider)) return { ok: false, error: 'invalid_provider' };

  const decoded = verifyState(state);
  if (!decoded || decoded.provider !== provider) return { ok: false, error: 'invalid_state' };

  if (IS_STAGING) {
    const accountId = `staging-${provider}-${decoded.userId}`;
    return {
      ok: true,
      account_ref: accountId,
      anti_sybil_token: `staging-social-${decoded.userId}`,
      user_id: decoded.userId,
    };
  }

  if (!providerConfigured(provider)) return { ok: false, error: 'provider_unavailable' };

  try {
    const accountId = await fetchProviderAccountId(provider, code);
    if (!accountId) return { ok: false, error: 'identity_unavailable' };
    return {
      ok: true,
      account_ref: `${provider}:${accountId}`,
      anti_sybil_token: antiSybilToken(provider, accountId),
      user_id: decoded.userId,
    };
  } catch {
    return { ok: false, error: 'oauth_failed' };
  }
}

async function fetchProviderAccountId(provider, code) {
  // Real token exchange is provider-specific; returns null to fail safe without live creds.
  return null;
}

// ── Social account linking (Twitter/Google/Discord/GitHub → badges) ───────────

function startSocialLink(provider, userId) {
  if (!isLinkProvider(provider)) return { ok: false, error: 'invalid_provider' };

  const issuedAt = Date.now();
  const nonce = crypto.randomBytes(8).toString('hex');
  const state = signState({ provider, userId, issuedAt, nonce, intent: 'link' });

  if (IS_STAGING) {
    return { ok: true, oauth_url: `bloom://link/${provider}?state=${encodeURIComponent(state)}`, state, simulated: true };
  }

  if (!providerLinkConfigured(provider)) return { ok: false, error: 'provider_unavailable' };

  const cfg = PROVIDER_OAUTH[provider];
  const clientId = process.env[`${cfg.envKey}_OAUTH_CLIENT_ID`];
  const redirectUri = process.env.BLOOM_OAUTH_REDIRECT_URI || '';
  const url = new URL(cfg.authorize);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', clientId);
  if (redirectUri) url.searchParams.set('redirect_uri', redirectUri);
  url.searchParams.set('scope', cfg.scope);
  url.searchParams.set('state', state);
  return { ok: true, oauth_url: url.toString(), state };
}

async function completeSocialLink(provider, code, state) {
  if (!isLinkProvider(provider)) return { ok: false, error: 'invalid_provider' };

  const decoded = verifyState(state);
  if (!decoded || decoded.provider !== provider || decoded.intent !== 'link') {
    return { ok: false, error: 'invalid_state' };
  }

  if (IS_STAGING) {
    const handleMap = {
      twitter: `@staging-twitter-${decoded.userId}`,
      google: `Staging User ${decoded.userId}`,
      discord: `staging#${decoded.userId}`,
      github: `staging-gh-${decoded.userId}`,
    };
    return {
      ok: true,
      provider_user_id: `staging-link-${provider}-${decoded.userId}`,
      handle: handleMap[provider] || `staging-${provider}-${decoded.userId}`,
      user_id: decoded.userId,
    };
  }

  if (!providerLinkConfigured(provider)) return { ok: false, error: 'provider_unavailable' };

  try {
    const result = await fetchLinkProviderIdentity(provider, code);
    if (!result) return { ok: false, error: 'identity_unavailable' };
    return { ok: true, provider_user_id: result.id, handle: result.handle, user_id: decoded.userId };
  } catch {
    return { ok: false, error: 'oauth_failed' };
  }
}

async function fetchLinkProviderIdentity(provider, code) {
  const cfg = PROVIDER_OAUTH[provider];
  if (!cfg || !cfg.token || !cfg.userinfo) return null;
  const clientId = process.env[`${cfg.envKey}_OAUTH_CLIENT_ID`];
  const clientSecret = process.env[`${cfg.envKey}_OAUTH_CLIENT_SECRET`];
  const redirectUri = process.env.BLOOM_OAUTH_REDIRECT_URI || '';
  if (!clientId || !clientSecret) return null;

  try {
    const tokenBody = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: redirectUri,
    });
    const tokenResp = await fetch(cfg.token, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', 'accept': 'application/json' },
      body: tokenBody.toString(),
    });
    if (!tokenResp.ok) return null;
    const tokenData = await tokenResp.json();
    const accessToken = tokenData.access_token;
    if (!accessToken) return null;

    const headers = { 'Authorization': `Bearer ${accessToken}`, 'accept': 'application/json' };
    if (provider === 'github') headers['User-Agent'] = 'BloomMoney';
    const infoResp = await fetch(cfg.userinfo, { headers });
    if (!infoResp.ok) return null;
    const info = await infoResp.json();

    if (provider === 'twitter') {
      const d = info.data || info;
      return { id: String(d.id || ''), handle: d.username ? `@${d.username}` : d.name || '' };
    }
    if (provider === 'google') {
      return { id: String(info.sub || ''), handle: info.name || info.email || '' };
    }
    if (provider === 'discord') {
      const disc = info.discriminator && info.discriminator !== '0' ? `#${info.discriminator}` : '';
      return { id: String(info.id || ''), handle: `${info.global_name || info.username || ''}${disc}` };
    }
    if (provider === 'github') {
      return { id: String(info.id || ''), handle: info.login || '' };
    }
    return null;
  } catch {
    return null;
  }
}

// ── zkPassport session-based flow (Premium badge + feature limits) ────────────

// In-memory session store: sessionId → { userId, createdAt, staging? }
const zkSessions = new Map();

async function startZkPassportSession(userId) {
  if (IS_STAGING) {
    const sessionId = `staging-zk-session-${userId}-${crypto.randomBytes(4).toString('hex')}`;
    zkSessions.set(sessionId, { userId, createdAt: Date.now(), staging: true });
    return {
      ok: true,
      sessionId,
      qrUrl: `https://placehold.co/256x256/18181b/6ee7b7?text=zkPassport%0AStaging+QR`,
      deepLinkUrl: '',
    };
  }

  if (!ZK_VERIFY_ENABLED) return { ok: false, error: 'provider_unavailable' };

  try {
    const verifierUrl = process.env.ZKPASSPORT_VERIFIER_URL;
    if (!verifierUrl) return { ok: false, error: 'provider_unavailable' };

    const resp = await fetch(`${verifierUrl}/sessions`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'authorization': `Bearer ${process.env.ZKPASSPORT_API_KEY}`,
      },
      body: JSON.stringify({ scope: 'proof_of_humanity' }),
    });
    if (!resp.ok) return { ok: false, error: 'session_create_failed' };
    const data = await resp.json().catch(() => ({}));
    const sessionId = data.session_id || data.id;
    if (!sessionId) return { ok: false, error: 'session_create_failed' };
    zkSessions.set(sessionId, { userId, createdAt: Date.now() });
    return {
      ok: true,
      sessionId,
      qrUrl: data.qr_url || data.qrUrl || '',
      deepLinkUrl: data.deep_link || data.deepLinkUrl || '',
    };
  } catch {
    return { ok: false, error: 'verifier_failed' };
  }
}

async function pollZkPassportSession(sessionId) {
  const session = zkSessions.get(sessionId);

  if (session?.staging) {
    // Auto-verify in staging on first poll
    return { status: 'verified', nullifier: `staging-raw-nullifier-${sessionId}` };
  }

  if (!ZK_VERIFY_ENABLED) return { status: 'failed' };

  try {
    const verifierUrl = process.env.ZKPASSPORT_VERIFIER_URL;
    if (!verifierUrl) return { status: 'failed' };

    const resp = await fetch(`${verifierUrl}/sessions/${sessionId}`, {
      headers: { 'authorization': `Bearer ${process.env.ZKPASSPORT_API_KEY}` },
    });
    if (!resp.ok) return { status: 'failed' };
    const data = await resp.json().catch(() => ({}));
    if (data.status === 'verified' || data.verified === true) {
      return { status: 'verified', nullifier: data.nullifier || data.null_hash || `zk-nullifier-${sessionId}` };
    }
    if (data.status === 'failed' || data.expired === true) return { status: 'failed' };
    return { status: 'pending' };
  } catch {
    return { status: 'failed' };
  }
}

// ── zkPassport legacy proof endpoint (kept for backward compatibility) ─────────

async function verifyZkPassportProof(proof, userId) {
  if (IS_STAGING) {
    return { ok: true, ref: `staging-zk-${userId}` };
  }
  if (!ZK_VERIFY_ENABLED) return { ok: false, error: 'provider_unavailable' };
  try {
    const verifierUrl = process.env.ZKPASSPORT_VERIFIER_URL;
    if (!verifierUrl || !proof) return { ok: false, error: 'invalid_proof' };
    const resp = await fetch(verifierUrl, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'authorization': `Bearer ${process.env.ZKPASSPORT_API_KEY}`,
      },
      body: JSON.stringify({ proof }),
    });
    if (!resp.ok) return { ok: false, error: 'proof_rejected' };
    const data = await resp.json().catch(() => ({}));
    if (!data || data.verified !== true) return { ok: false, error: 'proof_rejected' };
    return { ok: true, ref: data.reference || `zk-${crypto.randomBytes(6).toString('hex')}` };
  } catch {
    return { ok: false, error: 'verifier_failed' };
  }
}

module.exports = {
  IS_STAGING,
  SOCIAL_PROVIDERS,
  LINK_PROVIDERS,
  isSocialProvider,
  isLinkProvider,
  providerConfigured,
  providerLinkConfigured,
  configuredSocialProviders,
  SOCIAL_VERIFY_ENABLED,
  ZK_VERIFY_ENABLED,
  antiSybilToken,
  signState,
  verifyState,
  startSocialOAuth,
  completeSocialOAuth,
  startSocialLink,
  completeSocialLink,
  startZkPassportSession,
  pollZkPassportSession,
  verifyZkPassportProof,
};
