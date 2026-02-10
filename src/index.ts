/**
 * near-phantom-auth
 * 
 * Anonymous passkey authentication with NEAR MPC accounts, OAuth providers, and decentralized recovery.
 * 
 * @example Server usage:
 * ```typescript
 * import { createAnonAuth } from '@vitalpoint/near-phantom-auth/server';
 * 
 * const auth = createAnonAuth({
 *   nearNetwork: 'testnet',
 *   sessionSecret: process.env.SESSION_SECRET,
 *   database: { type: 'postgres', connectionString: process.env.DATABASE_URL },
 *   rp: { name: 'My App', id: 'myapp.com', origin: 'https://myapp.com' },
 *   oauth: {
 *     callbackBaseUrl: 'https://myapp.com/auth/callback',
 *     google: { clientId: '...', clientSecret: '...' },
 *     github: { clientId: '...', clientSecret: '...' },
 *     twitter: { clientId: '...', clientSecret: '...' },
 *   },
 * });
 * 
 * app.use('/auth', auth.router);
 * app.use('/auth/oauth', auth.oauthRouter);
 * app.get('/protected', auth.requireAuth, handler);
 * ```
 * 
 * @example Client usage:
 * ```tsx
 * import { AnonAuthProvider, useAnonAuth, useOAuth } from '@vitalpoint/near-phantom-auth/client';
 * 
 * function App() {
 *   return (
 *     <AnonAuthProvider apiUrl="/auth">
 *       <MyComponent />
 *     </AnonAuthProvider>
 *   );
 * }
 * 
 * function LoginButtons() {
 *   const { loginWithGoogle, loginWithGithub, loginWithTwitter } = useOAuth();
 *   return (
 *     <>
 *       <button onClick={loginWithGoogle}>Sign in with Google</button>
 *       <button onClick={loginWithGithub}>Sign in with GitHub</button>
 *       <button onClick={loginWithTwitter}>Sign in with X</button>
 *     </>
 *   );
 * }
 * ```
 * 
 * @packageDocumentation
 */

// Re-export types that are commonly needed
export type {
  AnonAuthConfig,
  DatabaseAdapter,
  AnonUser,
  OAuthUser,
  User,
  UserType,
  OAuthProvider,
  OAuthConfig,
  Session,
  Passkey,
  RecoveryType,
  RecoveryData,
  CodenameConfig,
  RecoveryConfig,
} from './types/index.js';
