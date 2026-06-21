// Verification provider adapters for BloomMoney.
//
// Social tier  -> social-media OAuth (X / Instagram / TikTok / Coinbase).
// Premium tier -> zkPassport proof.
//
// In staging (USERNODE_ENV=staging) we NEVER call real OAuth / external
// services — the flow is auto-approved with synthetic, per-user tokens so it
// is exercisable end-to-end against an empty DB. In production each provider
// is only "enabled" when its OAuth client credentials are present in the
// environment (declared private in dapp.json); absent creds degrade
// gracefully instead of crashing.

const crypto = require('crypto');

const IS_STAGING = process.env.USERNODE_ENV === 'staging';
const STATE_SECRET = process.env.JWT_SECRET || 'bloom-dev-state-secret';

const SOCIAL_PROVIDERS = ['x', 'instagram', 'tiktok', 'coinbase'];

// Per-provider OAuth endpoints (used only on the configured prod path).
const PROVIDER_OAUTH = {
  x: {
    authorize: 'https://twitter.com/i/oauth2/authorize',
    scope: 'users.read tweet.read',
  },
  instagram: {
    authorize: 'https://api.instagram.com/oauth/authorize',
    scope: 'user_profile',
  },
  tiktok: {
    authorize: 'https://www.tiktok.com/v2/auth/authorize/',
    scope: 'user.info.basic',
  },
  coinbase: {
    authorize: 'https://login.coinbase.com/oauth2/auth',
    scope: 'wallet:user:read',
  },
};

function isSocialProvider(p) {
  return SOCIAL_PROVIDERS.includes(p);
}

function providerEnvKey(provider) {
  return provider.toUpperCase();
}

// A social provider is "configured" when both halves of its OAuth client
// credential are present.
function providerConfigured(provider) {
  if (!isSocialProvider(provider)) return false;
  const key = providerEnvKey(provider);
  return !!(process.env[`${key}_OAUTH_CLIENT_ID`] && process.env[`${key}_OAUTH_CLIENT_SECRET`]);
}

function configuredSocialProviders() {
  return SOCIAL_PROVIDERS.filter(providerConfigured);
}

// Social verification is "enabled" when at least one provider is configured,
// OR we are in staging (where we simulate every provider).
const SOCIAL_VERIFY_ENABLED = IS_STAGING || configuredSocialProviders().length > 0;

// Premium (zkPassport) is enabled when its verifier creds exist, or in staging.
const ZK_VERIFY_ENABLED = IS_STAGING || !!process.env.ZKPASSPORT_API_KEY;

function antiSybilToken(provider, accountId) {
  return crypto.createHash('sha256').update(`${provider}:${accountId}`).digest('hex');
}

// Sign a short-lived state blob binding the OAuth round-trip to a wallet +
// provider, so /complete can verify the round-trip was the one we started.
function signState(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', STATE_SECRET).update(body).digest('base64url');
  return `${body}.${sig}`;
}

function verifyState(state) {
  if (typeof state !== 'string' || !state.includes('.')) return null;
  const [body, sig] = state.split('.');
  const expected = crypto.createHmac('sha256', STATE_SECRET).update(body).digest('base64url');
  // constant-time compare
  if (sig.length !== expected.length) return null;
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  try {
    return JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
}

// Build the authorization URL + signed state for a provider.
// Returns { ok, oauth_url, state } or { ok:false, error }.
function startSocialOAuth(provider, userId) {
  if (!isSocialProvider(provider)) return { ok: false, error: 'invalid_provider' };

  const issuedAt = Date.now();
  const nonce = crypto.randomBytes(8).toString('hex');
  const state = signState({ provider, userId, issuedAt, nonce });

  if (IS_STAGING) {
    // Synthetic in-app marker the frontend short-circuits on.
    return { ok: true, oauth_url: `bloom://verify/social/${provider}?state=${encodeURIComponent(state)}`, state, simulated: true };
  }

  if (!providerConfigured(provider)) return { ok: false, error: 'provider_unavailable' };

  const cfg = PROVIDER_OAUTH[provider];
  const clientId = process.env[`${providerEnvKey(provider)}_OAUTH_CLIENT_ID`];
  const redirectUri = process.env.BLOOM_OAUTH_REDIRECT_URI || '';
  const url = new URL(cfg.authorize);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', clientId);
  if (redirectUri) url.searchParams.set('redirect_uri', redirectUri);
  url.searchParams.set('scope', cfg.scope);
  url.searchParams.set('state', state);
  return { ok: true, oauth_url: url.toString(), state };
}

// Finalize the OAuth round-trip. Returns
// { ok, account_ref, anti_sybil_token } or { ok:false, error }.
async function completeSocialOAuth(provider, code, state) {
  if (!isSocialProvider(provider)) return { ok: false, error: 'invalid_provider' };

  const decoded = verifyState(state);
  if (!decoded || decoded.provider !== provider) return { ok: false, error: 'invalid_state' };

  if (IS_STAGING) {
    // Auto-approve with a synthetic, per-user account id so tokens are unique
    // by construction and the seeded users never false-collide.
    const accountId = `staging-${provider}-${decoded.userId}`;
    return {
      ok: true,
      account_ref: accountId,
      anti_sybil_token: `staging-social-${decoded.userId}`,
      user_id: decoded.userId,
    };
  }

  if (!providerConfigured(provider)) return { ok: false, error: 'provider_unavailable' };

  // Production path: exchange the code for an access token, then fetch the
  // provider-scoped account id. Kept best-effort — real creds + redirect URI
  // are supplied via the Secrets UI. Any failure degrades to a clean error.
  try {
    // NOTE: token exchange + identity lookup is provider-specific. We derive
    // the anti-sybil token from the provider-scoped account id once known.
    const accountId = await fetchProviderAccountId(provider, code);
    if (!accountId) return { ok: false, error: 'identity_unavailable' };
    return {
      ok: true,
      account_ref: `${provider}:${accountId}`,
      anti_sybil_token: antiSybilToken(provider, accountId),
      user_id: decoded.userId,
    };
  } catch (e) {
    return { ok: false, error: 'oauth_failed' };
  }
}

// Placeholder identity fetch for the configured prod path. Returns null when
// it cannot resolve an account id (which surfaces as identity_unavailable).
async function fetchProviderAccountId(provider, code) {
  // Real implementations differ per provider; without live creds in this
  // environment we cannot complete a real exchange, so return null to fail
  // safe rather than fabricate an identity.
  return null;
}

// Verify a zkPassport proof. Returns { ok, ref } or { ok:false, error }.
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
  } catch (e) {
    return { ok: false, error: 'verifier_failed' };
  }
}

module.exports = {
  IS_STAGING,
  SOCIAL_PROVIDERS,
  isSocialProvider,
  providerConfigured,
  configuredSocialProviders,
  SOCIAL_VERIFY_ENABLED,
  ZK_VERIFY_ENABLED,
  antiSybilToken,
  startSocialOAuth,
  completeSocialOAuth,
  verifyZkPassportProof,
};
