/**
 * Server SDK Entry Point
 * 
 * @example
 * ```typescript
 * import { createAnonAuth } from '@vitalpoint/near-anon-auth/server';
 * 
 * const anonAuth = createAnonAuth({
 *   nearNetwork: 'testnet',
 *   sessionSecret: process.env.SESSION_SECRET,
 *   database: {
 *     type: 'postgres',
 *     connectionString: process.env.DATABASE_URL,
 *   },
 *   rp: {
 *     name: 'My App',
 *     id: 'myapp.com',
 *     origin: 'https://myapp.com',
 *   },
 * });
 * 
 * app.use('/auth', anonAuth.router);
 * app.get('/protected', anonAuth.requireAuth, handler);
 * ```
 */

import type { Router, RequestHandler } from 'express';
import type { AnonAuthConfig, DatabaseAdapter } from '../types/index.js';
import { createPostgresAdapter } from './db/adapters/postgres.js';
import { createSessionManager, type SessionManager } from './session.js';
import { createPasskeyManager, type PasskeyManager } from './passkey.js';
import { createMPCManager, type MPCAccountManager } from './mpc.js';
import { createWalletRecoveryManager, type WalletRecoveryManager } from './recovery/wallet.js';
import { createIPFSRecoveryManager, type IPFSRecoveryManager } from './recovery/ipfs.js';
import { createAuthMiddleware, createRequireAuth } from './middleware.js';
import { createRouter } from './router.js';

export interface AnonAuthInstance {
  /** Express router with all auth endpoints */
  router: Router;
  
  /** Middleware that attaches user to request if authenticated */
  middleware: RequestHandler;
  
  /** Middleware that requires authentication (401 if not) */
  requireAuth: RequestHandler;
  
  /** Initialize database schema */
  initialize(): Promise<void>;
  
  /** Database adapter */
  db: DatabaseAdapter;
  
  /** Session manager */
  sessionManager: SessionManager;
  
  /** Passkey manager */
  passkeyManager: PasskeyManager;
  
  /** MPC account manager */
  mpcManager: MPCAccountManager;
  
  /** Wallet recovery manager (if enabled) */
  walletRecovery?: WalletRecoveryManager;
  
  /** IPFS recovery manager (if enabled) */
  ipfsRecovery?: IPFSRecoveryManager;
}

/**
 * Create anonymous authentication instance
 */
export function createAnonAuth(config: AnonAuthConfig): AnonAuthInstance {
  // Create database adapter
  let db: DatabaseAdapter;
  
  if (config.database.adapter) {
    db = config.database.adapter;
  } else if (config.database.type === 'postgres') {
    if (!config.database.connectionString) {
      throw new Error('PostgreSQL requires connectionString');
    }
    db = createPostgresAdapter({
      connectionString: config.database.connectionString,
    });
  } else if (config.database.type === 'custom') {
    if (!config.database.adapter) {
      throw new Error('Custom database type requires adapter');
    }
    db = config.database.adapter;
  } else {
    throw new Error(`Unsupported database type: ${config.database.type}`);
  }

  // Create session manager
  const sessionManager = createSessionManager(db, {
    secret: config.sessionSecret,
    durationMs: config.sessionDurationMs,
  });

  // Create passkey manager
  const rpConfig = config.rp || {
    name: 'Anonymous Auth',
    id: 'localhost',
    origin: 'http://localhost:3000',
  };

  const passkeyManager = createPasskeyManager(db, {
    rpName: rpConfig.name,
    rpId: rpConfig.id,
    origin: rpConfig.origin,
  });

  // Create MPC manager
  const mpcManager = createMPCManager({
    networkId: config.nearNetwork,
    accountPrefix: 'anon',
  });

  // Create recovery managers
  let walletRecovery: WalletRecoveryManager | undefined;
  let ipfsRecovery: IPFSRecoveryManager | undefined;

  if (config.recovery?.wallet) {
    walletRecovery = createWalletRecoveryManager({
      nearNetwork: config.nearNetwork,
    });
  }

  if (config.recovery?.ipfs) {
    ipfsRecovery = createIPFSRecoveryManager(config.recovery.ipfs);
  }

  // Create middleware
  const middleware = createAuthMiddleware(sessionManager, db);
  const requireAuth = createRequireAuth(sessionManager, db);

  // Create router
  const router = createRouter({
    db,
    sessionManager,
    passkeyManager,
    mpcManager,
    walletRecovery,
    ipfsRecovery,
    codename: config.codename,
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
    ipfsRecovery,
  };
}

// Re-export types and utilities
export type { AnonAuthConfig, DatabaseAdapter, AnonUser, Session } from '../types/index.js';
export type { SessionManager, SessionConfig } from './session.js';
export type { PasskeyManager, PasskeyConfig } from './passkey.js';
export type { MPCAccountManager, MPCConfig, MPCAccount } from './mpc.js';
export type { WalletRecoveryManager } from './recovery/wallet.js';
export type { IPFSRecoveryManager, IPFSRecoveryConfig } from './recovery/ipfs.js';
export { generateCodename, isValidCodename } from './codename.js';
export { createPostgresAdapter, POSTGRES_SCHEMA } from './db/adapters/postgres.js';
