/**
 * OAuth Router
 * 
 * API routes for OAuth authentication.
 */

import { Router, json } from 'express';
import type { Request, Response } from 'express';
import type { SessionManager } from '../session.js';
import type { MPCAccountManager } from '../mpc.js';
import type { IPFSRecoveryManager } from '../recovery/ipfs.js';
import type { DatabaseAdapter, OAuthConfig, OAuthProvider } from '../../types/index.js';
import { createOAuthManager, type OAuthManager, type OAuthProfile } from './index.js';

export interface OAuthRouterConfig {
  db: DatabaseAdapter;
  sessionManager: SessionManager;
  mpcManager: MPCAccountManager;
  oauthConfig: OAuthConfig;
  ipfsRecovery?: IPFSRecoveryManager;
}

export function createOAuthRouter(config: OAuthRouterConfig): Router {
  const router = Router();
  const {
    db,
    sessionManager,
    mpcManager,
    oauthConfig,
    ipfsRecovery,
  } = config;

  // Create OAuth manager
  const oauthManager = createOAuthManager(
    {
      google: oauthConfig.google,
      github: oauthConfig.github,
      twitter: oauthConfig.twitter,
    },
    db
  );

  router.use(json());

  // ============================================
  // OAuth Provider Info
  // ============================================

  /**
   * GET /oauth/providers
   * Get available OAuth providers
   */
  router.get('/providers', (_req: Request, res: Response) => {
    res.json({
      providers: {
        google: oauthManager.isConfigured('google'),
        github: oauthManager.isConfigured('github'),
        twitter: oauthManager.isConfigured('twitter'),
      },
    });
  });

  // ============================================
  // OAuth Flow Start
  // ============================================

  /**
   * GET /oauth/:provider/start
   * Start OAuth flow for a provider
   */
  router.get('/:provider/start', async (req: Request, res: Response) => {
    try {
      const provider = req.params.provider as 'google' | 'github' | 'twitter';
      
      if (!['google', 'github', 'twitter'].includes(provider)) {
        return res.status(400).json({ error: 'Invalid provider' });
      }

      if (!oauthManager.isConfigured(provider)) {
        return res.status(400).json({ error: `${provider} OAuth not configured` });
      }

      const redirectUri = `${oauthConfig.callbackBaseUrl}/${provider}`;
      const { url, state, codeVerifier } = await oauthManager.getAuthUrl(provider, redirectUri);

      // Store code verifier in session/cookie for PKCE
      if (codeVerifier) {
        res.cookie('oauth_code_verifier', codeVerifier, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'lax',
          maxAge: 10 * 60 * 1000, // 10 minutes
        });
      }

      res.cookie('oauth_state', state, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 10 * 60 * 1000,
      });

      res.json({ url, state });
    } catch (error) {
      console.error('[OAuth] Start error:', error);
      res.status(500).json({ error: 'Failed to start OAuth flow' });
    }
  });

  // ============================================
  // OAuth Callback
  // ============================================

  /**
   * POST /oauth/:provider/callback
   * Handle OAuth callback
   */
  router.post('/:provider/callback', async (req: Request, res: Response) => {
    try {
      const provider = req.params.provider as 'google' | 'github' | 'twitter';
      const { code, state } = req.body;

      if (!code || !state) {
        return res.status(400).json({ error: 'Missing code or state' });
      }

      // Validate state
      const storedState = req.cookies?.oauth_state;
      if (state !== storedState) {
        return res.status(400).json({ error: 'Invalid state' });
      }

      // Get code verifier for PKCE
      const codeVerifier = req.cookies?.oauth_code_verifier;

      // Clear OAuth cookies
      res.clearCookie('oauth_state');
      res.clearCookie('oauth_code_verifier');

      // Exchange code for tokens
      const redirectUri = `${oauthConfig.callbackBaseUrl}/${provider}`;
      const tokens = await oauthManager.exchangeCode(provider, code, redirectUri, codeVerifier);

      // Get user profile
      const profile = await oauthManager.getProfile(provider, tokens.accessToken);

      // Check if user exists with this provider
      let user = await db.getOAuthUserByProvider(provider, profile.providerId);

      if (user) {
        // Existing user - update last active and create session
        await sessionManager.createSession(user.id, res, {
          ipAddress: req.ip,
          userAgent: req.headers['user-agent'],
        });

        return res.json({
          success: true,
          user: {
            id: user.id,
            email: user.email,
            name: user.name,
            avatarUrl: user.avatarUrl,
            nearAccountId: user.nearAccountId,
            type: 'standard',
          },
          isNewUser: false,
        });
      }

      // Check if user exists with this email (link accounts)
      if (profile.email) {
        user = await db.getOAuthUserByEmail(profile.email);
        if (user) {
          // Link this provider to existing account
          const providerData: OAuthProvider = {
            provider,
            providerId: profile.providerId,
            email: profile.email,
            name: profile.name,
            avatarUrl: profile.avatarUrl,
            connectedAt: new Date(),
          };
          await db.linkOAuthProvider(user.id, providerData);

          await sessionManager.createSession(user.id, res, {
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
          });

          return res.json({
            success: true,
            user: {
              id: user.id,
              email: user.email,
              name: user.name,
              avatarUrl: user.avatarUrl,
              nearAccountId: user.nearAccountId,
              type: 'standard',
            },
            isNewUser: false,
            linkedProvider: provider,
          });
        }
      }

      // New user - create account with MPC
      const tempUserId = crypto.randomUUID();
      const mpcAccount = await mpcManager.createAccount(tempUserId);

      const providerData: OAuthProvider = {
        provider,
        providerId: profile.providerId,
        email: profile.email,
        name: profile.name,
        avatarUrl: profile.avatarUrl,
        connectedAt: new Date(),
      };

      const newUser = await db.createOAuthUser({
        email: profile.email || `${profile.providerId}@${provider}.oauth`,
        name: profile.name,
        avatarUrl: profile.avatarUrl,
        nearAccountId: mpcAccount.nearAccountId,
        mpcPublicKey: mpcAccount.mpcPublicKey,
        derivationPath: mpcAccount.derivationPath,
        provider: providerData,
      });

      // Create IPFS recovery backup automatically for OAuth users
      if (ipfsRecovery && profile.email) {
        try {
          const recoveryPassword = crypto.randomUUID(); // Auto-generated, sent to email
          const { cid } = await ipfsRecovery.createRecoveryBackup(
            {
              userId: newUser.id,
              nearAccountId: newUser.nearAccountId,
              derivationPath: newUser.derivationPath,
              createdAt: Date.now(),
            },
            recoveryPassword
          );

          await db.storeRecoveryData({
            userId: newUser.id,
            type: 'ipfs',
            reference: cid,
            createdAt: new Date(),
          });

          // TODO: Send recovery info to user's email
          console.log('[OAuth] Recovery backup created for new user:', cid);
        } catch (error) {
          console.error('[OAuth] Failed to create recovery backup:', error);
        }
      }

      // Create session
      await sessionManager.createSession(newUser.id, res, {
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
      });

      res.json({
        success: true,
        user: {
          id: newUser.id,
          email: newUser.email,
          name: newUser.name,
          avatarUrl: newUser.avatarUrl,
          nearAccountId: newUser.nearAccountId,
          type: 'standard',
        },
        isNewUser: true,
      });
    } catch (error) {
      console.error('[OAuth] Callback error:', error);
      res.status(500).json({ error: 'OAuth authentication failed' });
    }
  });

  // ============================================
  // Link Additional Provider
  // ============================================

  /**
   * POST /oauth/:provider/link
   * Link additional OAuth provider to existing account
   */
  router.post('/:provider/link', async (req: Request, res: Response) => {
    try {
      const session = await sessionManager.getSession(req);
      if (!session) {
        return res.status(401).json({ error: 'Authentication required' });
      }

      const provider = req.params.provider as 'google' | 'github' | 'twitter';
      const { code, state, codeVerifier } = req.body;

      if (!code) {
        return res.status(400).json({ error: 'Missing code' });
      }

      // Exchange code for tokens
      const redirectUri = `${oauthConfig.callbackBaseUrl}/${provider}`;
      const tokens = await oauthManager.exchangeCode(provider, code, redirectUri, codeVerifier);

      // Get user profile
      const profile = await oauthManager.getProfile(provider, tokens.accessToken);

      // Check if this provider is already linked to another account
      const existingUser = await db.getOAuthUserByProvider(provider, profile.providerId);
      if (existingUser && existingUser.id !== session.userId) {
        return res.status(400).json({ error: 'This account is already linked to another user' });
      }

      // Link provider to current user
      const providerData: OAuthProvider = {
        provider,
        providerId: profile.providerId,
        email: profile.email,
        name: profile.name,
        avatarUrl: profile.avatarUrl,
        connectedAt: new Date(),
      };

      await db.linkOAuthProvider(session.userId, providerData);

      res.json({
        success: true,
        message: `${provider} account linked successfully`,
      });
    } catch (error) {
      console.error('[OAuth] Link error:', error);
      res.status(500).json({ error: 'Failed to link provider' });
    }
  });

  return router;
}
