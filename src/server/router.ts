/**
 * Express Router
 * 
 * API routes for registration, authentication, and recovery.
 */

import { Router, json } from 'express';
import type { Request, Response } from 'express';
import type { SessionManager } from './session.js';
import type { PasskeyManager } from './passkey.js';
import type { MPCAccountManager } from './mpc.js';
import type { WalletRecoveryManager } from './recovery/wallet.js';
import type { IPFSRecoveryManager } from './recovery/ipfs.js';
import type { DatabaseAdapter, CodenameConfig } from '../types/index.js';
import { generateCodename, isValidCodename } from './codename.js';

export interface RouterConfig {
  db: DatabaseAdapter;
  sessionManager: SessionManager;
  passkeyManager: PasskeyManager;
  mpcManager: MPCAccountManager;
  walletRecovery?: WalletRecoveryManager;
  ipfsRecovery?: IPFSRecoveryManager;
  codename?: CodenameConfig;
}

export function createRouter(config: RouterConfig): Router {
  const router = Router();
  const {
    db,
    sessionManager,
    passkeyManager,
    mpcManager,
    walletRecovery,
    ipfsRecovery,
  } = config;

  // Parse JSON bodies
  router.use(json());

  // ============================================
  // Registration
  // ============================================

  /**
   * POST /register/start
   * Start passkey registration
   */
  router.post('/register/start', async (req: Request, res: Response) => {
    try {
      // Generate temporary user ID for registration
      const tempUserId = crypto.randomUUID();
      
      // Generate codename
      const style = config.codename?.style || 'nato-phonetic';
      let codename: string;
      
      if (config.codename?.generator) {
        codename = config.codename.generator(tempUserId);
      } else {
        codename = generateCodename(style);
      }
      
      // Ensure codename is unique
      let attempts = 0;
      while (await db.getUserByCodename(codename) && attempts < 10) {
        codename = generateCodename(style);
        attempts++;
      }
      
      if (attempts >= 10) {
        return res.status(500).json({ error: 'Failed to generate unique codename' });
      }
      
      const { challengeId, options } = await passkeyManager.startRegistration(
        tempUserId,
        codename
      );
      
      res.json({
        challengeId,
        options,
        codename,
        tempUserId,
      });
    } catch (error) {
      console.error('[AnonAuth] Registration start error:', error);
      res.status(500).json({ error: 'Registration failed' });
    }
  });

  /**
   * POST /register/finish
   * Complete passkey registration
   */
  router.post('/register/finish', async (req: Request, res: Response) => {
    try {
      const { challengeId, response, tempUserId, codename } = req.body;
      
      if (!challengeId || !response || !tempUserId || !codename) {
        return res.status(400).json({ error: 'Missing required fields' });
      }
      
      if (!isValidCodename(codename)) {
        return res.status(400).json({ error: 'Invalid codename format' });
      }
      
      // Verify passkey registration
      const { verified, passkey } = await passkeyManager.finishRegistration(
        challengeId,
        response
      );
      
      if (!verified || !passkey) {
        return res.status(400).json({ error: 'Passkey verification failed' });
      }
      
      // Create NEAR account via MPC
      const mpcAccount = await mpcManager.createAccount(tempUserId);
      
      // Create user
      const user = await db.createUser({
        codename,
        nearAccountId: mpcAccount.nearAccountId,
        mpcPublicKey: mpcAccount.mpcPublicKey,
        derivationPath: mpcAccount.derivationPath,
      });
      
      // Update passkey with real user ID
      // (In a real implementation, we'd update the passkey record)
      
      // Create session
      const session = await sessionManager.createSession(user.id, res, {
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
      });
      
      res.json({
        success: true,
        codename: user.codename,
        nearAccountId: user.nearAccountId,
      });
    } catch (error) {
      console.error('[AnonAuth] Registration finish error:', error);
      res.status(500).json({ error: 'Registration failed' });
    }
  });

  // ============================================
  // Authentication
  // ============================================

  /**
   * POST /login/start
   * Start passkey authentication
   */
  router.post('/login/start', async (req: Request, res: Response) => {
    try {
      const { codename } = req.body;
      
      let userId: string | undefined;
      
      if (codename) {
        const user = await db.getUserByCodename(codename);
        if (!user) {
          return res.status(404).json({ error: 'User not found' });
        }
        userId = user.id;
      }
      
      const { challengeId, options } = await passkeyManager.startAuthentication(userId);
      
      res.json({ challengeId, options });
    } catch (error) {
      console.error('[AnonAuth] Login start error:', error);
      res.status(500).json({ error: 'Login failed' });
    }
  });

  /**
   * POST /login/finish
   * Complete passkey authentication
   */
  router.post('/login/finish', async (req: Request, res: Response) => {
    try {
      const { challengeId, response } = req.body;
      
      if (!challengeId || !response) {
        return res.status(400).json({ error: 'Missing required fields' });
      }
      
      const { verified, userId } = await passkeyManager.finishAuthentication(
        challengeId,
        response
      );
      
      if (!verified || !userId) {
        return res.status(401).json({ error: 'Authentication failed' });
      }
      
      const user = await db.getUserById(userId);
      
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }
      
      // Create session
      await sessionManager.createSession(user.id, res, {
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
      });
      
      res.json({
        success: true,
        codename: user.codename,
      });
    } catch (error) {
      console.error('[AnonAuth] Login finish error:', error);
      res.status(500).json({ error: 'Authentication failed' });
    }
  });

  /**
   * POST /logout
   * End session
   */
  router.post('/logout', async (req: Request, res: Response) => {
    try {
      await sessionManager.destroySession(req, res);
      res.json({ success: true });
    } catch (error) {
      console.error('[AnonAuth] Logout error:', error);
      res.status(500).json({ error: 'Logout failed' });
    }
  });

  /**
   * GET /session
   * Get current session
   */
  router.get('/session', async (req: Request, res: Response) => {
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
        expiresAt: session.expiresAt,
      });
    } catch (error) {
      console.error('[AnonAuth] Session check error:', error);
      res.status(500).json({ error: 'Session check failed' });
    }
  });

  // ============================================
  // Wallet Recovery
  // ============================================

  if (walletRecovery) {
    /**
     * POST /recovery/wallet/link
     * Link a NEAR wallet for recovery
     */
    router.post('/recovery/wallet/link', async (req: Request, res: Response) => {
      try {
        const session = await sessionManager.getSession(req);
        
        if (!session) {
          return res.status(401).json({ error: 'Authentication required' });
        }
        
        const { challenge: walletChallenge, expiresAt } = walletRecovery.generateLinkChallenge();
        
        // Store challenge for verification
        await db.storeChallenge({
          id: crypto.randomUUID(),
          challenge: walletChallenge,
          type: 'recovery',
          userId: session.userId,
          expiresAt,
          metadata: { action: 'wallet-link' },
        });
        
        res.json({
          challenge: walletChallenge,
          expiresAt: expiresAt.toISOString(),
        });
      } catch (error) {
        console.error('[AnonAuth] Wallet link error:', error);
        res.status(500).json({ error: 'Failed to initiate wallet link' });
      }
    });

    /**
     * POST /recovery/wallet/verify
     * Verify wallet signature and complete linking
     */
    router.post('/recovery/wallet/verify', async (req: Request, res: Response) => {
      try {
        const session = await sessionManager.getSession(req);
        
        if (!session) {
          return res.status(401).json({ error: 'Authentication required' });
        }
        
        const { signature, challenge, walletAccountId } = req.body;
        
        if (!signature || !challenge || !walletAccountId) {
          return res.status(400).json({ error: 'Missing required fields' });
        }
        
        const { verified, walletId } = walletRecovery.verifyLinkSignature(
          signature,
          challenge
        );
        
        if (!verified) {
          return res.status(401).json({ error: 'Invalid signature' });
        }
        
        const user = await db.getUserById(session.userId);
        
        if (!user) {
          return res.status(404).json({ error: 'User not found' });
        }
        
        // Add wallet as access key on-chain (no DB storage)
        await mpcManager.addRecoveryWallet(user.nearAccountId, walletAccountId);
        
        // Store reference for our records (just the fact that wallet recovery is enabled)
        await db.storeRecoveryData({
          userId: user.id,
          type: 'wallet',
          reference: 'enabled', // We don't store the wallet ID!
          createdAt: new Date(),
        });
        
        res.json({
          success: true,
          message: 'Wallet linked for recovery. The link is stored on-chain, not in our database.',
        });
      } catch (error) {
        console.error('[AnonAuth] Wallet verify error:', error);
        res.status(500).json({ error: 'Failed to verify wallet' });
      }
    });

    /**
     * POST /recovery/wallet/start
     * Start wallet-based recovery
     */
    router.post('/recovery/wallet/start', async (req: Request, res: Response) => {
      try {
        const { challenge, expiresAt } = walletRecovery.generateRecoveryChallenge();
        
        res.json({
          challenge,
          expiresAt: expiresAt.toISOString(),
        });
      } catch (error) {
        console.error('[AnonAuth] Wallet recovery start error:', error);
        res.status(500).json({ error: 'Failed to start recovery' });
      }
    });

    /**
     * POST /recovery/wallet/finish
     * Complete wallet-based recovery
     */
    router.post('/recovery/wallet/finish', async (req: Request, res: Response) => {
      try {
        const { signature, challenge, nearAccountId } = req.body;
        
        if (!signature || !challenge || !nearAccountId) {
          return res.status(400).json({ error: 'Missing required fields' });
        }
        
        const { verified } = await walletRecovery.verifyRecoverySignature(
          signature,
          challenge,
          nearAccountId
        );
        
        if (!verified) {
          return res.status(401).json({ error: 'Recovery verification failed' });
        }
        
        // Find user by NEAR account
        const user = await db.getUserByNearAccount(nearAccountId);
        
        if (!user) {
          return res.status(404).json({ error: 'Account not found' });
        }
        
        // Create session for recovered user
        await sessionManager.createSession(user.id, res, {
          ipAddress: req.ip,
          userAgent: req.headers['user-agent'],
        });
        
        res.json({
          success: true,
          codename: user.codename,
          message: 'Recovery successful. You can now register a new passkey.',
        });
      } catch (error) {
        console.error('[AnonAuth] Wallet recovery finish error:', error);
        res.status(500).json({ error: 'Recovery failed' });
      }
    });
  }

  // ============================================
  // IPFS Recovery
  // ============================================

  if (ipfsRecovery) {
    /**
     * POST /recovery/ipfs/setup
     * Create encrypted backup on IPFS
     */
    router.post('/recovery/ipfs/setup', async (req: Request, res: Response) => {
      try {
        const session = await sessionManager.getSession(req);
        
        if (!session) {
          return res.status(401).json({ error: 'Authentication required' });
        }
        
        const { password } = req.body;
        
        if (!password) {
          return res.status(400).json({ error: 'Password required' });
        }
        
        // Validate password
        const validation = ipfsRecovery.validatePassword(password);
        if (!validation.valid) {
          return res.status(400).json({
            error: 'Password too weak',
            details: validation.errors,
          });
        }
        
        const user = await db.getUserById(session.userId);
        
        if (!user) {
          return res.status(404).json({ error: 'User not found' });
        }
        
        // Create and pin backup
        const { cid } = await ipfsRecovery.createRecoveryBackup(
          {
            userId: user.id,
            nearAccountId: user.nearAccountId,
            derivationPath: user.derivationPath,
            createdAt: Date.now(),
          },
          password
        );
        
        // Store CID reference
        await db.storeRecoveryData({
          userId: user.id,
          type: 'ipfs',
          reference: cid,
          createdAt: new Date(),
        });
        
        res.json({
          success: true,
          cid,
          message: 'Backup created. Save this CID with your password - you need both to recover.',
        });
      } catch (error) {
        console.error('[AnonAuth] IPFS setup error:', error);
        res.status(500).json({ error: 'Failed to create backup' });
      }
    });

    /**
     * POST /recovery/ipfs/recover
     * Recover using IPFS backup
     */
    router.post('/recovery/ipfs/recover', async (req: Request, res: Response) => {
      try {
        const { cid, password } = req.body;
        
        if (!cid || !password) {
          return res.status(400).json({ error: 'CID and password required' });
        }
        
        // Decrypt backup
        let payload;
        try {
          payload = await ipfsRecovery.recoverFromBackup(cid, password);
        } catch {
          return res.status(401).json({ error: 'Invalid password or CID' });
        }
        
        // Find user
        const user = await db.getUserById(payload.userId);
        
        if (!user) {
          return res.status(404).json({ error: 'Account not found' });
        }
        
        // Create session
        await sessionManager.createSession(user.id, res, {
          ipAddress: req.ip,
          userAgent: req.headers['user-agent'],
        });
        
        res.json({
          success: true,
          codename: user.codename,
          message: 'Recovery successful. You can now register a new passkey.',
        });
      } catch (error) {
        console.error('[AnonAuth] IPFS recovery error:', error);
        res.status(500).json({ error: 'Recovery failed' });
      }
    });
  }

  return router;
}
