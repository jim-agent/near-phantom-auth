/**
 * Session Management
 * 
 * HttpOnly cookie-based sessions for XSS protection.
 * Sessions are stored server-side (database) with secure cookie reference.
 */

import { randomUUID, createHmac } from 'crypto';
import type { Response, Request } from 'express';
import type { Session, CreateSessionInput, DatabaseAdapter } from '../types/index.js';

const SESSION_COOKIE_NAME = 'anon_session';
const DEFAULT_SESSION_DURATION_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

export interface SessionConfig {
  /** Secret for signing session cookies */
  secret: string;
  /** Cookie name (default: anon_session) */
  cookieName?: string;
  /** Session duration in ms (default: 7 days) */
  durationMs?: number;
  /** Cookie domain (optional) */
  domain?: string;
  /** Cookie path (default: /) */
  path?: string;
  /** Secure flag (default: true in production) */
  secure?: boolean;
  /** SameSite setting (default: strict) */
  sameSite?: 'strict' | 'lax' | 'none';
}

export interface SessionManager {
  createSession(
    userId: string,
    res: Response,
    options?: { ipAddress?: string; userAgent?: string }
  ): Promise<Session>;
  
  getSession(req: Request): Promise<Session | null>;
  
  destroySession(req: Request, res: Response): Promise<void>;
  
  refreshSession(req: Request, res: Response): Promise<Session | null>;
}

/**
 * Sign a session ID with HMAC
 */
function signSessionId(sessionId: string, secret: string): string {
  const signature = createHmac('sha256', secret)
    .update(sessionId)
    .digest('base64url');
  return `${sessionId}.${signature}`;
}

/**
 * Verify and extract session ID from signed value
 */
function verifySessionId(signedValue: string, secret: string): string | null {
  const parts = signedValue.split('.');
  if (parts.length !== 2) return null;
  
  const [sessionId, signature] = parts;
  const expectedSignature = createHmac('sha256', secret)
    .update(sessionId)
    .digest('base64url');
  
  if (signature !== expectedSignature) return null;
  return sessionId;
}

/**
 * Parse cookies from request
 */
function parseCookies(req: Request): Record<string, string> {
  const cookies: Record<string, string> = {};
  const cookieHeader = req.headers.cookie;
  
  if (!cookieHeader) return cookies;
  
  cookieHeader.split(';').forEach((cookie) => {
    const [name, ...rest] = cookie.trim().split('=');
    if (name && rest.length) {
      cookies[name] = decodeURIComponent(rest.join('='));
    }
  });
  
  return cookies;
}

/**
 * Create session manager
 */
export function createSessionManager(
  db: DatabaseAdapter,
  config: SessionConfig
): SessionManager {
  const cookieName = config.cookieName || SESSION_COOKIE_NAME;
  const durationMs = config.durationMs || DEFAULT_SESSION_DURATION_MS;
  const isProduction = process.env.NODE_ENV === 'production';
  
  const cookieOptions = {
    httpOnly: true,
    secure: config.secure ?? isProduction,
    sameSite: config.sameSite || 'strict',
    path: config.path || '/',
    domain: config.domain,
  };

  return {
    async createSession(userId, res, options = {}) {
      const sessionId = randomUUID();
      const now = new Date();
      const expiresAt = new Date(now.getTime() + durationMs);
      
      const sessionInput: CreateSessionInput = {
        userId,
        expiresAt,
        ipAddress: options.ipAddress,
        userAgent: options.userAgent,
      };
      
      const session = await db.createSession({
        ...sessionInput,
        id: sessionId,
      } as Session);
      
      // Sign and set cookie
      const signedId = signSessionId(sessionId, config.secret);
      
      res.cookie(cookieName, signedId, {
        ...cookieOptions,
        maxAge: durationMs,
        expires: expiresAt,
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
      
      // Check if expired
      if (session.expiresAt < new Date()) {
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
      
      // Clear cookie
      res.clearCookie(cookieName, {
        ...cookieOptions,
      });
    },
    
    async refreshSession(req, res) {
      const session = await this.getSession(req);
      
      if (!session) return null;
      
      // Check if session is past 50% of its lifetime (sliding window)
      const now = Date.now();
      const created = session.createdAt.getTime();
      const expires = session.expiresAt.getTime();
      const lifetime = expires - created;
      const elapsed = now - created;
      
      if (elapsed > lifetime * 0.5) {
        // Extend session
        const newExpiresAt = new Date(now + durationMs);
        
        // Update in database would happen here
        // For now, just update cookie
        const signedId = signSessionId(session.id, config.secret);
        
        res.cookie(cookieName, signedId, {
          ...cookieOptions,
          maxAge: durationMs,
          expires: newExpiresAt,
        });
      }
      
      return session;
    },
  };
}
