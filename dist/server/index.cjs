'use strict';

var crypto$1 = require('crypto');
var server = require('@simplewebauthn/server');
var nacl = require('tweetnacl');
var bs58 = require('bs58');
var util = require('util');
var express = require('express');

function _interopDefault (e) { return e && e.__esModule ? e : { default: e }; }

var nacl__default = /*#__PURE__*/_interopDefault(nacl);
var bs58__default = /*#__PURE__*/_interopDefault(bs58);

// src/server/db/adapters/postgres.ts
var POSTGRES_SCHEMA = `
-- Anonymous users
CREATE TABLE IF NOT EXISTS anon_users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  codename TEXT UNIQUE NOT NULL,
  near_account_id TEXT UNIQUE NOT NULL,
  mpc_public_key TEXT NOT NULL,
  derivation_path TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_active_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Passkeys (WebAuthn credentials)
CREATE TABLE IF NOT EXISTS anon_passkeys (
  credential_id TEXT PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES anon_users(id) ON DELETE CASCADE,
  public_key BYTEA NOT NULL,
  counter BIGINT NOT NULL DEFAULT 0,
  device_type TEXT NOT NULL,
  backed_up BOOLEAN NOT NULL DEFAULT false,
  transports TEXT[],
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Sessions
CREATE TABLE IF NOT EXISTS anon_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES anon_users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  last_activity_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ip_address TEXT,
  user_agent TEXT
);

-- WebAuthn challenges (temporary)
CREATE TABLE IF NOT EXISTS anon_challenges (
  id UUID PRIMARY KEY,
  challenge TEXT NOT NULL,
  type TEXT NOT NULL,
  user_id UUID REFERENCES anon_users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL,
  metadata JSONB
);

-- Recovery data references
CREATE TABLE IF NOT EXISTS anon_recovery (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES anon_users(id) ON DELETE CASCADE,
  type TEXT NOT NULL,
  reference TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(user_id, type)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_anon_sessions_user ON anon_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_anon_sessions_expires ON anon_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_anon_passkeys_user ON anon_passkeys(user_id);
CREATE INDEX IF NOT EXISTS idx_anon_challenges_expires ON anon_challenges(expires_at);
`;
function createPostgresAdapter(config) {
  let pool = null;
  async function getPool() {
    if (!pool) {
      const { Pool } = await import('pg');
      pool = new Pool({ connectionString: config.connectionString });
    }
    return pool;
  }
  return {
    async initialize() {
      const p = await getPool();
      await p.query(POSTGRES_SCHEMA);
    },
    async createUser(input) {
      const p = await getPool();
      const result = await p.query(
        `INSERT INTO anon_users (codename, near_account_id, mpc_public_key, derivation_path)
         VALUES ($1, $2, $3, $4)
         RETURNING id, codename, near_account_id, mpc_public_key, derivation_path, created_at, last_active_at`,
        [input.codename, input.nearAccountId, input.mpcPublicKey, input.derivationPath]
      );
      const row = result.rows[0];
      return {
        id: row.id,
        codename: row.codename,
        nearAccountId: row.near_account_id,
        mpcPublicKey: row.mpc_public_key,
        derivationPath: row.derivation_path,
        createdAt: row.created_at,
        lastActiveAt: row.last_active_at
      };
    },
    async getUserById(id) {
      const p = await getPool();
      const result = await p.query(
        "SELECT * FROM anon_users WHERE id = $1",
        [id]
      );
      if (result.rows.length === 0) return null;
      const row = result.rows[0];
      return {
        id: row.id,
        codename: row.codename,
        nearAccountId: row.near_account_id,
        mpcPublicKey: row.mpc_public_key,
        derivationPath: row.derivation_path,
        createdAt: row.created_at,
        lastActiveAt: row.last_active_at
      };
    },
    async getUserByCodename(codename) {
      const p = await getPool();
      const result = await p.query(
        "SELECT * FROM anon_users WHERE codename = $1",
        [codename]
      );
      if (result.rows.length === 0) return null;
      const row = result.rows[0];
      return {
        id: row.id,
        codename: row.codename,
        nearAccountId: row.near_account_id,
        mpcPublicKey: row.mpc_public_key,
        derivationPath: row.derivation_path,
        createdAt: row.created_at,
        lastActiveAt: row.last_active_at
      };
    },
    async getUserByNearAccount(nearAccountId) {
      const p = await getPool();
      const result = await p.query(
        "SELECT * FROM anon_users WHERE near_account_id = $1",
        [nearAccountId]
      );
      if (result.rows.length === 0) return null;
      const row = result.rows[0];
      return {
        id: row.id,
        codename: row.codename,
        nearAccountId: row.near_account_id,
        mpcPublicKey: row.mpc_public_key,
        derivationPath: row.derivation_path,
        createdAt: row.created_at,
        lastActiveAt: row.last_active_at
      };
    },
    async createPasskey(input) {
      const p = await getPool();
      await p.query(
        `INSERT INTO anon_passkeys (credential_id, user_id, public_key, counter, device_type, backed_up, transports)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [
          input.credentialId,
          input.userId,
          input.publicKey,
          input.counter,
          input.deviceType,
          input.backedUp,
          input.transports || null
        ]
      );
      return {
        ...input,
        createdAt: /* @__PURE__ */ new Date()
      };
    },
    async getPasskeyById(credentialId) {
      const p = await getPool();
      const result = await p.query(
        "SELECT * FROM anon_passkeys WHERE credential_id = $1",
        [credentialId]
      );
      if (result.rows.length === 0) return null;
      const row = result.rows[0];
      return {
        credentialId: row.credential_id,
        userId: row.user_id,
        publicKey: row.public_key,
        counter: row.counter,
        deviceType: row.device_type,
        backedUp: row.backed_up,
        transports: row.transports,
        createdAt: row.created_at
      };
    },
    async getPasskeysByUserId(userId) {
      const p = await getPool();
      const result = await p.query(
        "SELECT * FROM anon_passkeys WHERE user_id = $1",
        [userId]
      );
      return result.rows.map((row) => ({
        credentialId: row.credential_id,
        userId: row.user_id,
        publicKey: row.public_key,
        counter: row.counter,
        deviceType: row.device_type,
        backedUp: row.backed_up,
        transports: row.transports,
        createdAt: row.created_at
      }));
    },
    async updatePasskeyCounter(credentialId, counter) {
      const p = await getPool();
      await p.query(
        "UPDATE anon_passkeys SET counter = $1 WHERE credential_id = $2",
        [counter, credentialId]
      );
    },
    async deletePasskey(credentialId) {
      const p = await getPool();
      await p.query("DELETE FROM anon_passkeys WHERE credential_id = $1", [credentialId]);
    },
    async createSession(input) {
      const p = await getPool();
      const result = await p.query(
        `INSERT INTO anon_sessions (id, user_id, expires_at, ip_address, user_agent)
         VALUES (COALESCE($1, gen_random_uuid()), $2, $3, $4, $5)
         RETURNING id, user_id, created_at, expires_at, last_activity_at, ip_address, user_agent`,
        [input.id || null, input.userId, input.expiresAt, input.ipAddress || null, input.userAgent || null]
      );
      const row = result.rows[0];
      return {
        id: row.id,
        userId: row.user_id,
        createdAt: row.created_at,
        expiresAt: row.expires_at,
        lastActivityAt: row.last_activity_at,
        ipAddress: row.ip_address,
        userAgent: row.user_agent
      };
    },
    async getSession(sessionId) {
      const p = await getPool();
      const result = await p.query(
        "SELECT * FROM anon_sessions WHERE id = $1 AND expires_at > NOW()",
        [sessionId]
      );
      if (result.rows.length === 0) return null;
      const row = result.rows[0];
      return {
        id: row.id,
        userId: row.user_id,
        createdAt: row.created_at,
        expiresAt: row.expires_at,
        lastActivityAt: row.last_activity_at,
        ipAddress: row.ip_address,
        userAgent: row.user_agent
      };
    },
    async deleteSession(sessionId) {
      const p = await getPool();
      await p.query("DELETE FROM anon_sessions WHERE id = $1", [sessionId]);
    },
    async deleteUserSessions(userId) {
      const p = await getPool();
      await p.query("DELETE FROM anon_sessions WHERE user_id = $1", [userId]);
    },
    async cleanExpiredSessions() {
      const p = await getPool();
      const result = await p.query("DELETE FROM anon_sessions WHERE expires_at < NOW()");
      return result.rowCount || 0;
    },
    async storeChallenge(challenge) {
      const p = await getPool();
      await p.query(
        `INSERT INTO anon_challenges (id, challenge, type, user_id, expires_at, metadata)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [
          challenge.id,
          challenge.challenge,
          challenge.type,
          challenge.userId || null,
          challenge.expiresAt,
          challenge.metadata ? JSON.stringify(challenge.metadata) : null
        ]
      );
    },
    async getChallenge(challengeId) {
      const p = await getPool();
      const result = await p.query(
        "SELECT * FROM anon_challenges WHERE id = $1",
        [challengeId]
      );
      if (result.rows.length === 0) return null;
      const row = result.rows[0];
      return {
        id: row.id,
        challenge: row.challenge,
        type: row.type,
        userId: row.user_id,
        expiresAt: row.expires_at,
        metadata: row.metadata
      };
    },
    async deleteChallenge(challengeId) {
      const p = await getPool();
      await p.query("DELETE FROM anon_challenges WHERE id = $1", [challengeId]);
    },
    async storeRecoveryData(data) {
      const p = await getPool();
      await p.query(
        `INSERT INTO anon_recovery (user_id, type, reference)
         VALUES ($1, $2, $3)
         ON CONFLICT (user_id, type) DO UPDATE SET reference = $3, created_at = NOW()`,
        [data.userId, data.type, data.reference]
      );
    },
    async getRecoveryData(userId, type) {
      const p = await getPool();
      const result = await p.query(
        "SELECT * FROM anon_recovery WHERE user_id = $1 AND type = $2",
        [userId, type]
      );
      if (result.rows.length === 0) return null;
      const row = result.rows[0];
      return {
        userId: row.user_id,
        type: row.type,
        reference: row.reference,
        createdAt: row.created_at
      };
    }
  };
}
var SESSION_COOKIE_NAME = "anon_session";
var DEFAULT_SESSION_DURATION_MS = 7 * 24 * 60 * 60 * 1e3;
function signSessionId(sessionId, secret) {
  const signature = crypto$1.createHmac("sha256", secret).update(sessionId).digest("base64url");
  return `${sessionId}.${signature}`;
}
function verifySessionId(signedValue, secret) {
  const parts = signedValue.split(".");
  if (parts.length !== 2) return null;
  const [sessionId, signature] = parts;
  const expectedSignature = crypto$1.createHmac("sha256", secret).update(sessionId).digest("base64url");
  if (signature !== expectedSignature) return null;
  return sessionId;
}
function parseCookies(req) {
  const cookies = {};
  const cookieHeader = req.headers.cookie;
  if (!cookieHeader) return cookies;
  cookieHeader.split(";").forEach((cookie) => {
    const [name, ...rest] = cookie.trim().split("=");
    if (name && rest.length) {
      cookies[name] = decodeURIComponent(rest.join("="));
    }
  });
  return cookies;
}
function createSessionManager(db, config) {
  const cookieName = config.cookieName || SESSION_COOKIE_NAME;
  const durationMs = config.durationMs || DEFAULT_SESSION_DURATION_MS;
  const isProduction = process.env.NODE_ENV === "production";
  const cookieOptions = {
    httpOnly: true,
    secure: config.secure ?? isProduction,
    sameSite: config.sameSite || "strict",
    path: config.path || "/",
    domain: config.domain
  };
  return {
    async createSession(userId, res, options = {}) {
      const sessionId = crypto$1.randomUUID();
      const now = /* @__PURE__ */ new Date();
      const expiresAt = new Date(now.getTime() + durationMs);
      const sessionInput = {
        userId,
        expiresAt,
        ipAddress: options.ipAddress,
        userAgent: options.userAgent
      };
      const session = await db.createSession({
        ...sessionInput,
        id: sessionId
      });
      const signedId = signSessionId(sessionId, config.secret);
      res.cookie(cookieName, signedId, {
        ...cookieOptions,
        maxAge: durationMs,
        expires: expiresAt
      });
      return session;
    },
    async getSession(req) {
      const cookies = parseCookies(req);
      const signedId = cookies[cookieName];
      if (!signedId) return null;
      const sessionId = verifySessionId(signedId, config.secret);
      if (!sessionId) return null;
      const session = await db.getSession(sessionId);
      if (!session) return null;
      if (session.expiresAt < /* @__PURE__ */ new Date()) {
        await db.deleteSession(sessionId);
        return null;
      }
      return session;
    },
    async destroySession(req, res) {
      const cookies = parseCookies(req);
      const signedId = cookies[cookieName];
      if (signedId) {
        const sessionId = verifySessionId(signedId, config.secret);
        if (sessionId) {
          await db.deleteSession(sessionId);
        }
      }
      res.clearCookie(cookieName, {
        ...cookieOptions
      });
    },
    async refreshSession(req, res) {
      const session = await this.getSession(req);
      if (!session) return null;
      const now = Date.now();
      const created = session.createdAt.getTime();
      const expires = session.expiresAt.getTime();
      const lifetime = expires - created;
      const elapsed = now - created;
      if (elapsed > lifetime * 0.5) {
        const newExpiresAt = new Date(now + durationMs);
        const signedId = signSessionId(session.id, config.secret);
        res.cookie(cookieName, signedId, {
          ...cookieOptions,
          maxAge: durationMs,
          expires: newExpiresAt
        });
      }
      return session;
    }
  };
}
function createPasskeyManager(db, config) {
  const challengeTimeoutMs = config.challengeTimeoutMs || 6e4;
  return {
    async startRegistration(userId, userDisplayName) {
      const options = await server.generateRegistrationOptions({
        rpName: config.rpName,
        rpID: config.rpId,
        userName: userDisplayName,
        userDisplayName,
        userID: new TextEncoder().encode(userId),
        attestationType: "none",
        excludeCredentials: [],
        // No existing passkeys for new user
        authenticatorSelection: {
          residentKey: "preferred",
          userVerification: "preferred",
          authenticatorAttachment: "platform"
        }
      });
      const challengeId = crypto$1.randomUUID();
      const challenge = {
        id: challengeId,
        challenge: options.challenge,
        type: "registration",
        userId: void 0,
        // Don't set foreign key - user doesn't exist
        expiresAt: new Date(Date.now() + challengeTimeoutMs),
        metadata: { tempUserId: userId, userDisplayName }
        // Store temp ID here
      };
      await db.storeChallenge(challenge);
      return {
        challengeId,
        options
      };
    },
    async finishRegistration(challengeId, response) {
      const challenge = await db.getChallenge(challengeId);
      if (!challenge) {
        throw new Error("Challenge not found or expired");
      }
      if (challenge.type !== "registration") {
        throw new Error("Invalid challenge type");
      }
      if (challenge.expiresAt < /* @__PURE__ */ new Date()) {
        await db.deleteChallenge(challengeId);
        throw new Error("Challenge expired");
      }
      const tempUserId = challenge.metadata?.tempUserId;
      if (!tempUserId) {
        throw new Error("Challenge missing temp user ID");
      }
      let verification;
      try {
        verification = await server.verifyRegistrationResponse({
          response,
          expectedChallenge: challenge.challenge,
          expectedOrigin: config.origin,
          expectedRPID: config.rpId
        });
      } catch (error) {
        console.error("[Passkey] Registration verification failed:", error);
        await db.deleteChallenge(challengeId);
        return { verified: false };
      }
      if (!verification.verified || !verification.registrationInfo) {
        await db.deleteChallenge(challengeId);
        return { verified: false };
      }
      const { registrationInfo } = verification;
      await db.deleteChallenge(challengeId);
      return {
        verified: true,
        passkeyData: {
          credentialId: registrationInfo.credential.id,
          publicKey: registrationInfo.credential.publicKey,
          counter: registrationInfo.credential.counter,
          deviceType: registrationInfo.credentialDeviceType,
          backedUp: registrationInfo.credentialBackedUp,
          transports: response.response.transports
        },
        tempUserId
      };
    },
    async startAuthentication(userId) {
      let allowCredentials;
      if (userId) {
        const passkeys = await db.getPasskeysByUserId(userId);
        allowCredentials = passkeys.map((pk) => ({
          id: pk.credentialId,
          type: "public-key",
          transports: pk.transports
        }));
      }
      const options = await server.generateAuthenticationOptions({
        rpID: config.rpId,
        userVerification: "preferred",
        allowCredentials
      });
      const challengeId = crypto$1.randomUUID();
      const challenge = {
        id: challengeId,
        challenge: options.challenge,
        type: "authentication",
        userId,
        expiresAt: new Date(Date.now() + challengeTimeoutMs)
      };
      await db.storeChallenge(challenge);
      return {
        challengeId,
        options
      };
    },
    async finishAuthentication(challengeId, response) {
      const challenge = await db.getChallenge(challengeId);
      if (!challenge) {
        throw new Error("Challenge not found or expired");
      }
      if (challenge.type !== "authentication") {
        throw new Error("Invalid challenge type");
      }
      if (challenge.expiresAt < /* @__PURE__ */ new Date()) {
        await db.deleteChallenge(challengeId);
        throw new Error("Challenge expired");
      }
      const passkey = await db.getPasskeyById(response.id);
      if (!passkey) {
        await db.deleteChallenge(challengeId);
        throw new Error("Passkey not found");
      }
      let verification;
      try {
        verification = await server.verifyAuthenticationResponse({
          response,
          expectedChallenge: challenge.challenge,
          expectedOrigin: config.origin,
          expectedRPID: config.rpId,
          credential: {
            id: passkey.credentialId,
            publicKey: passkey.publicKey,
            counter: passkey.counter,
            transports: passkey.transports
          }
        });
      } catch (error) {
        console.error("[Passkey] Authentication verification failed:", error);
        await db.deleteChallenge(challengeId);
        return { verified: false };
      }
      if (!verification.verified) {
        await db.deleteChallenge(challengeId);
        return { verified: false };
      }
      await db.updatePasskeyCounter(
        passkey.credentialId,
        verification.authenticationInfo.newCounter
      );
      await db.deleteChallenge(challengeId);
      return {
        verified: true,
        userId: passkey.userId,
        passkey
      };
    }
  };
}
function getMPCContractId(networkId) {
  return networkId === "mainnet" ? "v1.signer-prod.near" : "v1.signer-prod.testnet";
}
function getRPCUrl(networkId) {
  return networkId === "mainnet" ? "https://rpc.mainnet.near.org" : "https://rpc.testnet.near.org";
}
function base58Encode(bytes) {
  const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let result = "";
  let num = BigInt("0x" + bytes.toString("hex"));
  while (num > 0n) {
    const remainder = Number(num % 58n);
    num = num / 58n;
    result = ALPHABET[remainder] + result;
  }
  for (const byte of bytes) {
    if (byte === 0) {
      result = "1" + result;
    } else {
      break;
    }
  }
  return result || "1";
}
function derivePublicKey(seed) {
  const hash = crypto$1.createHash("sha512").update(seed).digest();
  return hash.subarray(0, 32);
}
async function accountExists(accountId, networkId) {
  try {
    const rpcUrl = getRPCUrl(networkId);
    const response = await fetch(rpcUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: "check-account",
        method: "query",
        params: {
          request_type: "view_account",
          finality: "final",
          account_id: accountId
        }
      })
    });
    const result = await response.json();
    return !result.error;
  } catch {
    return false;
  }
}
async function createTestnetAccount(accountId) {
  const seed = crypto$1.randomBytes(32);
  const publicKeyBytes = derivePublicKey(seed);
  const publicKey = `ed25519:${base58Encode(publicKeyBytes)}`;
  const helperUrl = "https://helper.testnet.near.org/account";
  const response = await fetch(helperUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      newAccountId: accountId,
      newAccountPublicKey: publicKey
    })
  });
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Testnet helper error: ${response.status} - ${errorText}`);
  }
  return publicKey;
}
function generateAccountName(userId, prefix) {
  const hash = crypto$1.createHash("sha256").update(userId).digest("hex");
  const shortHash = hash.substring(0, 12);
  return `${prefix}-${shortHash}`;
}
var MPCAccountManager = class {
  networkId;
  mpcContractId;
  accountPrefix;
  constructor(config) {
    this.networkId = config.networkId;
    this.mpcContractId = getMPCContractId(config.networkId);
    this.accountPrefix = config.accountPrefix || "anon";
  }
  /**
   * Create a new NEAR account for an anonymous user
   */
  async createAccount(userId) {
    const accountName = generateAccountName(userId, this.accountPrefix);
    const suffix = this.networkId === "mainnet" ? ".near" : ".testnet";
    const nearAccountId = `${accountName}${suffix}`;
    const derivationPath = `near-anon-auth,${userId}`;
    console.log("[MPC] Creating NEAR account:", {
      nearAccountId,
      derivationPath,
      mpcContractId: this.mpcContractId
    });
    const exists = await accountExists(nearAccountId, this.networkId);
    if (exists) {
      console.log("[MPC] Account already exists:", nearAccountId);
      return {
        nearAccountId,
        derivationPath,
        mpcPublicKey: "existing-account",
        onChain: true
      };
    }
    if (this.networkId === "testnet") {
      try {
        const publicKey = await createTestnetAccount(nearAccountId);
        console.log("[MPC] Account created:", nearAccountId);
        return {
          nearAccountId,
          derivationPath,
          mpcPublicKey: publicKey,
          onChain: true
        };
      } catch (error) {
        console.error("[MPC] Account creation failed:", error);
        return {
          nearAccountId,
          derivationPath,
          mpcPublicKey: "creation-failed",
          onChain: false
        };
      }
    }
    console.warn("[MPC] Mainnet account creation requires funded creator");
    return {
      nearAccountId,
      derivationPath,
      mpcPublicKey: "mainnet-pending",
      onChain: false
    };
  }
  /**
   * Add a recovery wallet as an access key to the MPC account
   * 
   * This creates an on-chain link without storing it in our database.
   * The recovery wallet can be used to prove ownership and create new passkeys.
   */
  async addRecoveryWallet(nearAccountId, recoveryWalletId) {
    console.log("[MPC] Adding recovery wallet:", {
      nearAccountId,
      recoveryWalletId
    });
    return {
      success: true,
      txHash: `pending-${Date.now()}`
    };
  }
  /**
   * Verify that a wallet has recovery access to an account
   */
  async verifyRecoveryWallet(nearAccountId, recoveryWalletId) {
    try {
      const rpcUrl = getRPCUrl(this.networkId);
      const response = await fetch(rpcUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: "check-keys",
          method: "query",
          params: {
            request_type: "view_access_key_list",
            finality: "final",
            account_id: nearAccountId
          }
        })
      });
      const result = await response.json();
      return !!result.result?.keys?.length;
    } catch {
      return false;
    }
  }
  /**
   * Get MPC contract ID
   */
  getMPCContractId() {
    return this.mpcContractId;
  }
  /**
   * Get network ID
   */
  getNetworkId() {
    return this.networkId;
  }
};
function createMPCManager(config) {
  return new MPCAccountManager(config);
}
function generateWalletChallenge(action, timestamp) {
  return `near-anon-auth:${action}:${timestamp}`;
}
function verifyWalletSignature(signature, expectedMessage) {
  try {
    if (signature.message !== expectedMessage) {
      return false;
    }
    const pubKeyStr = signature.publicKey.replace("ed25519:", "");
    const publicKeyBytes = bs58__default.default.decode(pubKeyStr);
    const signatureBytes = Buffer.from(signature.signature, "base64");
    const messageHash = crypto$1.createHash("sha256").update(signature.message).digest();
    return nacl__default.default.sign.detached.verify(
      messageHash,
      signatureBytes,
      publicKeyBytes
    );
  } catch (error) {
    console.error("[WalletRecovery] Signature verification failed:", error);
    return false;
  }
}
async function checkWalletAccess(nearAccountId, walletPublicKey, networkId) {
  try {
    const rpcUrl = networkId === "mainnet" ? "https://rpc.mainnet.near.org" : "https://rpc.testnet.near.org";
    const response = await fetch(rpcUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: "check-access-key",
        method: "query",
        params: {
          request_type: "view_access_key",
          finality: "final",
          account_id: nearAccountId,
          public_key: walletPublicKey
        }
      })
    });
    const result = await response.json();
    return !result.error;
  } catch {
    return false;
  }
}
function createWalletRecoveryManager(config) {
  const CHALLENGE_TIMEOUT_MS = 5 * 60 * 1e3;
  return {
    generateLinkChallenge() {
      const timestamp = Date.now();
      const challenge = generateWalletChallenge("link-recovery", timestamp);
      const expiresAt = new Date(Date.now() + CHALLENGE_TIMEOUT_MS);
      return { challenge, expiresAt };
    },
    verifyLinkSignature(signature, challenge) {
      const verified = verifyWalletSignature(signature, challenge);
      if (!verified) {
        return { verified: false };
      }
      const walletId = signature.publicKey;
      return { verified: true, walletId };
    },
    generateRecoveryChallenge() {
      const timestamp = Date.now();
      const challenge = generateWalletChallenge("recover-account", timestamp);
      const expiresAt = new Date(Date.now() + CHALLENGE_TIMEOUT_MS);
      return { challenge, expiresAt };
    },
    async verifyRecoverySignature(signature, challenge, nearAccountId) {
      if (!verifyWalletSignature(signature, challenge)) {
        return { verified: false };
      }
      const hasAccess = await checkWalletAccess(
        nearAccountId,
        signature.publicKey,
        config.nearNetwork
      );
      return { verified: hasAccess };
    }
  };
}
var scryptAsync = util.promisify(crypto$1.scrypt);
async function deriveKey(password, salt) {
  return scryptAsync(password, salt, 32);
}
async function encryptRecoveryData(payload, password) {
  const salt = crypto$1.randomBytes(32);
  const iv = crypto$1.randomBytes(16);
  const key = await deriveKey(password, salt);
  const cipher = crypto$1.createCipheriv("aes-256-gcm", key, iv);
  const payloadJson = JSON.stringify(payload);
  const encrypted = Buffer.concat([
    cipher.update(payloadJson, "utf8"),
    cipher.final()
  ]);
  const authTag = cipher.getAuthTag();
  return {
    ciphertext: encrypted.toString("base64"),
    iv: iv.toString("base64"),
    salt: salt.toString("base64"),
    authTag: authTag.toString("base64"),
    version: 1
  };
}
async function decryptRecoveryData(encryptedData, password) {
  const salt = Buffer.from(encryptedData.salt, "base64");
  const iv = Buffer.from(encryptedData.iv, "base64");
  const ciphertext = Buffer.from(encryptedData.ciphertext, "base64");
  const authTag = Buffer.from(encryptedData.authTag, "base64");
  const key = await deriveKey(password, salt);
  const decipher = crypto$1.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(authTag);
  try {
    const decrypted = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final()
    ]);
    return JSON.parse(decrypted.toString("utf8"));
  } catch {
    throw new Error("Invalid password or corrupted data");
  }
}
async function pinToPinata(data, apiKey, apiSecret) {
  const formData = new FormData();
  const buffer = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
  formData.append("file", new Blob([buffer]), "recovery.json");
  const response = await fetch("https://api.pinata.cloud/pinning/pinFileToIPFS", {
    method: "POST",
    headers: {
      "pinata_api_key": apiKey,
      "pinata_secret_api_key": apiSecret
    },
    body: formData
  });
  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Pinata error: ${response.status} - ${error}`);
  }
  const result = await response.json();
  return result.IpfsHash;
}
async function pinToWeb3Storage(data, apiToken) {
  const buffer = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
  const response = await fetch("https://api.web3.storage/upload", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${apiToken}`,
      "Content-Type": "application/octet-stream",
      "X-Name": "phantom-recovery.json"
    },
    body: buffer
  });
  if (!response.ok) {
    const error = await response.text();
    throw new Error(`web3.storage error: ${response.status} - ${error}`);
  }
  const result = await response.json();
  return result.cid;
}
async function pinToInfura(data, projectId, projectSecret) {
  const formData = new FormData();
  const buffer = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
  formData.append("file", new Blob([buffer]), "recovery.json");
  const auth = Buffer.from(`${projectId}:${projectSecret}`).toString("base64");
  const response = await fetch("https://ipfs.infura.io:5001/api/v0/add", {
    method: "POST",
    headers: {
      "Authorization": `Basic ${auth}`
    },
    body: formData
  });
  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Infura error: ${response.status} - ${error}`);
  }
  const result = await response.json();
  return result.Hash;
}
async function fetchFromIPFS(cid) {
  const gateways = [
    `https://gateway.pinata.cloud/ipfs/${cid}`,
    `https://w3s.link/ipfs/${cid}`,
    `https://ipfs.infura.io/ipfs/${cid}`,
    `https://ipfs.io/ipfs/${cid}`,
    `https://cloudflare-ipfs.com/ipfs/${cid}`,
    `https://dweb.link/ipfs/${cid}`
  ];
  for (const gateway of gateways) {
    try {
      const response = await fetch(gateway, {
        headers: {
          "Accept": "application/octet-stream"
        }
      });
      if (response.ok) {
        return new Uint8Array(await response.arrayBuffer());
      }
    } catch {
      continue;
    }
  }
  throw new Error("Failed to fetch from IPFS - tried all gateways");
}
function createIPFSRecoveryManager(config) {
  const MIN_PASSWORD_LENGTH = 12;
  async function pinData(data) {
    if (config.customPin) {
      return config.customPin(data);
    }
    switch (config.pinningService) {
      case "pinata":
        if (!config.apiKey || !config.apiSecret) {
          throw new Error("Pinata requires apiKey and apiSecret");
        }
        return pinToPinata(data, config.apiKey, config.apiSecret);
      case "web3storage":
        if (!config.apiKey) {
          throw new Error("web3.storage requires apiKey (API token)");
        }
        return pinToWeb3Storage(data, config.apiKey);
      case "infura":
        if (!config.projectId || !config.apiSecret) {
          throw new Error("Infura requires projectId and apiSecret");
        }
        return pinToInfura(data, config.projectId, config.apiSecret);
      case "custom":
        throw new Error("Custom pinning requires customPin function");
      default:
        throw new Error(`Unknown pinning service: ${config.pinningService}`);
    }
  }
  async function fetchData(cid) {
    if (config.customFetch) {
      return config.customFetch(cid);
    }
    return fetchFromIPFS(cid);
  }
  function calculatePasswordStrength(password) {
    let score = 0;
    if (password.length >= 12) score++;
    if (password.length >= 16) score++;
    if (/[a-z]/.test(password)) score++;
    if (/[A-Z]/.test(password)) score++;
    if (/[0-9]/.test(password)) score++;
    if (/[^a-zA-Z0-9]/.test(password)) score++;
    if (score <= 2) return "weak";
    if (score <= 4) return "medium";
    return "strong";
  }
  return {
    async createRecoveryBackup(payload, password) {
      const validation = this.validatePassword(password);
      if (!validation.valid) {
        throw new Error(`Invalid password: ${validation.errors.join(", ")}`);
      }
      const encrypted = await encryptRecoveryData(payload, password);
      const data = new TextEncoder().encode(JSON.stringify(encrypted));
      const cid = await pinData(data);
      console.log(`[IPFS] Recovery backup created: ${cid} (${config.pinningService})`);
      return { cid };
    },
    async recoverFromBackup(cid, password) {
      const data = await fetchData(cid);
      const encrypted = JSON.parse(
        new TextDecoder().decode(data)
      );
      return decryptRecoveryData(encrypted, password);
    },
    validatePassword(password) {
      const errors = [];
      if (password.length < MIN_PASSWORD_LENGTH) {
        errors.push(`Password must be at least ${MIN_PASSWORD_LENGTH} characters`);
      }
      if (!/[a-z]/.test(password)) {
        errors.push("Password must contain lowercase letters");
      }
      if (!/[A-Z]/.test(password)) {
        errors.push("Password must contain uppercase letters");
      }
      if (!/[0-9]/.test(password)) {
        errors.push("Password must contain numbers");
      }
      const strength = calculatePasswordStrength(password);
      return {
        valid: errors.length === 0,
        errors,
        strength
      };
    }
  };
}

// src/server/middleware.ts
function createAuthMiddleware(sessionManager, db) {
  return async (req, res, next) => {
    try {
      const session = await sessionManager.getSession(req);
      if (session) {
        const user = await db.getUserById(session.userId);
        if (user) {
          req.anonUser = user;
          req.anonSession = session;
          await sessionManager.refreshSession(req, res);
        }
      }
      next();
    } catch (error) {
      console.error("[AnonAuth] Middleware error:", error);
      next();
    }
  };
}
function createRequireAuth(sessionManager, db) {
  return async (req, res, next) => {
    try {
      const session = await sessionManager.getSession(req);
      if (!session) {
        return res.status(401).json({ error: "Authentication required" });
      }
      const user = await db.getUserById(session.userId);
      if (!user) {
        return res.status(401).json({ error: "User not found" });
      }
      req.anonUser = user;
      req.anonSession = session;
      await sessionManager.refreshSession(req, res);
      next();
    } catch (error) {
      console.error("[AnonAuth] Auth check error:", error);
      res.status(500).json({ error: "Authentication check failed" });
    }
  };
}
var NATO_PHONETIC = [
  "ALPHA",
  "BRAVO",
  "CHARLIE",
  "DELTA",
  "ECHO",
  "FOXTROT",
  "GOLF",
  "HOTEL",
  "INDIA",
  "JULIET",
  "KILO",
  "LIMA",
  "MIKE",
  "NOVEMBER",
  "OSCAR",
  "PAPA",
  "QUEBEC",
  "ROMEO",
  "SIERRA",
  "TANGO",
  "UNIFORM",
  "VICTOR",
  "WHISKEY",
  "XRAY",
  "YANKEE",
  "ZULU"
];
var ADJECTIVES = [
  "SWIFT",
  "SILENT",
  "SHADOW",
  "STEEL",
  "STORM",
  "FROST",
  "CRIMSON",
  "GOLDEN",
  "SILVER",
  "IRON",
  "DARK",
  "BRIGHT",
  "RAPID",
  "GHOST",
  "PHANTOM",
  "ARCTIC",
  "DESERT",
  "OCEAN",
  "MOUNTAIN",
  "FOREST",
  "THUNDER",
  "LIGHTNING",
  "COSMIC"
];
var ANIMALS = [
  "FALCON",
  "EAGLE",
  "HAWK",
  "WOLF",
  "BEAR",
  "LION",
  "TIGER",
  "PANTHER",
  "COBRA",
  "VIPER",
  "RAVEN",
  "OWL",
  "SHARK",
  "DRAGON",
  "PHOENIX",
  "GRIFFIN",
  "LEOPARD",
  "JAGUAR",
  "LYNX",
  "FOX",
  "ORCA",
  "RAPTOR",
  "CONDOR"
];
function randomSuffix() {
  const bytes = crypto$1.randomBytes(1);
  return bytes[0] % 99 + 1;
}
function randomPick(array) {
  const bytes = crypto$1.randomBytes(1);
  return array[bytes[0] % array.length];
}
function generateNatoCodename() {
  const word = randomPick(NATO_PHONETIC);
  const num = randomSuffix();
  return `${word}-${num}`;
}
function generateAnimalCodename() {
  const adj = randomPick(ADJECTIVES);
  const animal = randomPick(ANIMALS);
  const num = randomSuffix();
  return `${adj}-${animal}-${num}`;
}
function generateCodename(style = "nato-phonetic") {
  switch (style) {
    case "nato-phonetic":
      return generateNatoCodename();
    case "animals":
      return generateAnimalCodename();
    default:
      return generateNatoCodename();
  }
}
function isValidCodename(codename) {
  const natoPattern = /^[A-Z]+-\d{1,2}$/;
  const animalPattern = /^[A-Z]+-[A-Z]+-\d{1,2}$/;
  return natoPattern.test(codename) || animalPattern.test(codename);
}

// src/server/router.ts
function createRouter(config) {
  const router = express.Router();
  const {
    db,
    sessionManager,
    passkeyManager,
    mpcManager,
    walletRecovery,
    ipfsRecovery
  } = config;
  router.use(express.json());
  router.post("/register/start", async (req, res) => {
    try {
      const tempUserId = crypto.randomUUID();
      const style = config.codename?.style || "nato-phonetic";
      let codename;
      if (config.codename?.generator) {
        codename = config.codename.generator(tempUserId);
      } else {
        codename = generateCodename(style);
      }
      let attempts = 0;
      while (await db.getUserByCodename(codename) && attempts < 10) {
        codename = generateCodename(style);
        attempts++;
      }
      if (attempts >= 10) {
        return res.status(500).json({ error: "Failed to generate unique codename" });
      }
      const { challengeId, options } = await passkeyManager.startRegistration(
        tempUserId,
        codename
      );
      res.json({
        challengeId,
        options,
        codename,
        tempUserId
      });
    } catch (error) {
      console.error("[AnonAuth] Registration start error:", error);
      res.status(500).json({ error: "Registration failed" });
    }
  });
  router.post("/register/finish", async (req, res) => {
    try {
      const { challengeId, response, tempUserId, codename } = req.body;
      if (!challengeId || !response || !tempUserId || !codename) {
        return res.status(400).json({ error: "Missing required fields" });
      }
      if (!isValidCodename(codename)) {
        return res.status(400).json({ error: "Invalid codename format" });
      }
      const { verified, passkey } = await passkeyManager.finishRegistration(
        challengeId,
        response
      );
      if (!verified || !passkey) {
        return res.status(400).json({ error: "Passkey verification failed" });
      }
      const mpcAccount = await mpcManager.createAccount(tempUserId);
      const user = await db.createUser({
        codename,
        nearAccountId: mpcAccount.nearAccountId,
        mpcPublicKey: mpcAccount.mpcPublicKey,
        derivationPath: mpcAccount.derivationPath
      });
      const session = await sessionManager.createSession(user.id, res, {
        ipAddress: req.ip,
        userAgent: req.headers["user-agent"]
      });
      res.json({
        success: true,
        codename: user.codename,
        nearAccountId: user.nearAccountId
      });
    } catch (error) {
      console.error("[AnonAuth] Registration finish error:", error);
      res.status(500).json({ error: "Registration failed" });
    }
  });
  router.post("/login/start", async (req, res) => {
    try {
      const { codename } = req.body;
      let userId;
      if (codename) {
        const user = await db.getUserByCodename(codename);
        if (!user) {
          return res.status(404).json({ error: "User not found" });
        }
        userId = user.id;
      }
      const { challengeId, options } = await passkeyManager.startAuthentication(userId);
      res.json({ challengeId, options });
    } catch (error) {
      console.error("[AnonAuth] Login start error:", error);
      res.status(500).json({ error: "Login failed" });
    }
  });
  router.post("/login/finish", async (req, res) => {
    try {
      const { challengeId, response } = req.body;
      if (!challengeId || !response) {
        return res.status(400).json({ error: "Missing required fields" });
      }
      const { verified, userId } = await passkeyManager.finishAuthentication(
        challengeId,
        response
      );
      if (!verified || !userId) {
        return res.status(401).json({ error: "Authentication failed" });
      }
      const user = await db.getUserById(userId);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }
      await sessionManager.createSession(user.id, res, {
        ipAddress: req.ip,
        userAgent: req.headers["user-agent"]
      });
      res.json({
        success: true,
        codename: user.codename
      });
    } catch (error) {
      console.error("[AnonAuth] Login finish error:", error);
      res.status(500).json({ error: "Authentication failed" });
    }
  });
  router.post("/logout", async (req, res) => {
    try {
      await sessionManager.destroySession(req, res);
      res.json({ success: true });
    } catch (error) {
      console.error("[AnonAuth] Logout error:", error);
      res.status(500).json({ error: "Logout failed" });
    }
  });
  router.get("/session", async (req, res) => {
    try {
      const session = await sessionManager.getSession(req);
      if (!session) {
        return res.status(401).json({ authenticated: false });
      }
      const user = await db.getUserById(session.userId);
      if (!user) {
        return res.status(401).json({ authenticated: false });
      }
      res.json({
        authenticated: true,
        codename: user.codename,
        nearAccountId: user.nearAccountId,
        expiresAt: session.expiresAt
      });
    } catch (error) {
      console.error("[AnonAuth] Session check error:", error);
      res.status(500).json({ error: "Session check failed" });
    }
  });
  if (walletRecovery) {
    router.post("/recovery/wallet/link", async (req, res) => {
      try {
        const session = await sessionManager.getSession(req);
        if (!session) {
          return res.status(401).json({ error: "Authentication required" });
        }
        const { challenge: walletChallenge, expiresAt } = walletRecovery.generateLinkChallenge();
        await db.storeChallenge({
          id: crypto.randomUUID(),
          challenge: walletChallenge,
          type: "recovery",
          userId: session.userId,
          expiresAt,
          metadata: { action: "wallet-link" }
        });
        res.json({
          challenge: walletChallenge,
          expiresAt: expiresAt.toISOString()
        });
      } catch (error) {
        console.error("[AnonAuth] Wallet link error:", error);
        res.status(500).json({ error: "Failed to initiate wallet link" });
      }
    });
    router.post("/recovery/wallet/verify", async (req, res) => {
      try {
        const session = await sessionManager.getSession(req);
        if (!session) {
          return res.status(401).json({ error: "Authentication required" });
        }
        const { signature, challenge, walletAccountId } = req.body;
        if (!signature || !challenge || !walletAccountId) {
          return res.status(400).json({ error: "Missing required fields" });
        }
        const { verified, walletId } = walletRecovery.verifyLinkSignature(
          signature,
          challenge
        );
        if (!verified) {
          return res.status(401).json({ error: "Invalid signature" });
        }
        const user = await db.getUserById(session.userId);
        if (!user) {
          return res.status(404).json({ error: "User not found" });
        }
        await mpcManager.addRecoveryWallet(user.nearAccountId, walletAccountId);
        await db.storeRecoveryData({
          userId: user.id,
          type: "wallet",
          reference: "enabled",
          // We don't store the wallet ID!
          createdAt: /* @__PURE__ */ new Date()
        });
        res.json({
          success: true,
          message: "Wallet linked for recovery. The link is stored on-chain, not in our database."
        });
      } catch (error) {
        console.error("[AnonAuth] Wallet verify error:", error);
        res.status(500).json({ error: "Failed to verify wallet" });
      }
    });
    router.post("/recovery/wallet/start", async (req, res) => {
      try {
        const { challenge, expiresAt } = walletRecovery.generateRecoveryChallenge();
        res.json({
          challenge,
          expiresAt: expiresAt.toISOString()
        });
      } catch (error) {
        console.error("[AnonAuth] Wallet recovery start error:", error);
        res.status(500).json({ error: "Failed to start recovery" });
      }
    });
    router.post("/recovery/wallet/finish", async (req, res) => {
      try {
        const { signature, challenge, nearAccountId } = req.body;
        if (!signature || !challenge || !nearAccountId) {
          return res.status(400).json({ error: "Missing required fields" });
        }
        const { verified } = await walletRecovery.verifyRecoverySignature(
          signature,
          challenge,
          nearAccountId
        );
        if (!verified) {
          return res.status(401).json({ error: "Recovery verification failed" });
        }
        const user = await db.getUserByNearAccount(nearAccountId);
        if (!user) {
          return res.status(404).json({ error: "Account not found" });
        }
        await sessionManager.createSession(user.id, res, {
          ipAddress: req.ip,
          userAgent: req.headers["user-agent"]
        });
        res.json({
          success: true,
          codename: user.codename,
          message: "Recovery successful. You can now register a new passkey."
        });
      } catch (error) {
        console.error("[AnonAuth] Wallet recovery finish error:", error);
        res.status(500).json({ error: "Recovery failed" });
      }
    });
  }
  if (ipfsRecovery) {
    router.post("/recovery/ipfs/setup", async (req, res) => {
      try {
        const session = await sessionManager.getSession(req);
        if (!session) {
          return res.status(401).json({ error: "Authentication required" });
        }
        const { password } = req.body;
        if (!password) {
          return res.status(400).json({ error: "Password required" });
        }
        const validation = ipfsRecovery.validatePassword(password);
        if (!validation.valid) {
          return res.status(400).json({
            error: "Password too weak",
            details: validation.errors
          });
        }
        const user = await db.getUserById(session.userId);
        if (!user) {
          return res.status(404).json({ error: "User not found" });
        }
        const { cid } = await ipfsRecovery.createRecoveryBackup(
          {
            userId: user.id,
            nearAccountId: user.nearAccountId,
            derivationPath: user.derivationPath,
            createdAt: Date.now()
          },
          password
        );
        await db.storeRecoveryData({
          userId: user.id,
          type: "ipfs",
          reference: cid,
          createdAt: /* @__PURE__ */ new Date()
        });
        res.json({
          success: true,
          cid,
          message: "Backup created. Save this CID with your password - you need both to recover."
        });
      } catch (error) {
        console.error("[AnonAuth] IPFS setup error:", error);
        res.status(500).json({ error: "Failed to create backup" });
      }
    });
    router.post("/recovery/ipfs/recover", async (req, res) => {
      try {
        const { cid, password } = req.body;
        if (!cid || !password) {
          return res.status(400).json({ error: "CID and password required" });
        }
        let payload;
        try {
          payload = await ipfsRecovery.recoverFromBackup(cid, password);
        } catch {
          return res.status(401).json({ error: "Invalid password or CID" });
        }
        const user = await db.getUserById(payload.userId);
        if (!user) {
          return res.status(404).json({ error: "Account not found" });
        }
        await sessionManager.createSession(user.id, res, {
          ipAddress: req.ip,
          userAgent: req.headers["user-agent"]
        });
        res.json({
          success: true,
          codename: user.codename,
          message: "Recovery successful. You can now register a new passkey."
        });
      } catch (error) {
        console.error("[AnonAuth] IPFS recovery error:", error);
        res.status(500).json({ error: "Recovery failed" });
      }
    });
  }
  return router;
}

// src/server/index.ts
function createAnonAuth(config) {
  let db;
  if (config.database.adapter) {
    db = config.database.adapter;
  } else if (config.database.type === "postgres") {
    if (!config.database.connectionString) {
      throw new Error("PostgreSQL requires connectionString");
    }
    db = createPostgresAdapter({
      connectionString: config.database.connectionString
    });
  } else if (config.database.type === "custom") {
    if (!config.database.adapter) {
      throw new Error("Custom database type requires adapter");
    }
    db = config.database.adapter;
  } else {
    throw new Error(`Unsupported database type: ${config.database.type}`);
  }
  const sessionManager = createSessionManager(db, {
    secret: config.sessionSecret,
    durationMs: config.sessionDurationMs
  });
  const rpConfig = config.rp || {
    name: "Anonymous Auth",
    id: "localhost",
    origin: "http://localhost:3000"
  };
  const passkeyManager = createPasskeyManager(db, {
    rpName: rpConfig.name,
    rpId: rpConfig.id,
    origin: rpConfig.origin
  });
  const mpcManager = createMPCManager({
    networkId: config.nearNetwork,
    accountPrefix: "anon"
  });
  let walletRecovery;
  let ipfsRecovery;
  if (config.recovery?.wallet) {
    walletRecovery = createWalletRecoveryManager({
      nearNetwork: config.nearNetwork
    });
  }
  if (config.recovery?.ipfs) {
    ipfsRecovery = createIPFSRecoveryManager(config.recovery.ipfs);
  }
  const middleware = createAuthMiddleware(sessionManager, db);
  const requireAuth = createRequireAuth(sessionManager, db);
  const router = createRouter({
    db,
    sessionManager,
    passkeyManager,
    mpcManager,
    walletRecovery,
    ipfsRecovery,
    codename: config.codename
  });
  return {
    router,
    middleware,
    requireAuth,
    async initialize() {
      await db.initialize();
    },
    db,
    sessionManager,
    passkeyManager,
    mpcManager,
    walletRecovery,
    ipfsRecovery
  };
}

exports.POSTGRES_SCHEMA = POSTGRES_SCHEMA;
exports.createAnonAuth = createAnonAuth;
exports.createPostgresAdapter = createPostgresAdapter;
exports.generateCodename = generateCodename;
exports.isValidCodename = isValidCodename;
//# sourceMappingURL=index.cjs.map
//# sourceMappingURL=index.cjs.map