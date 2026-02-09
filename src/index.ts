/**
 * near-anon-auth
 * 
 * Anonymous passkey authentication with NEAR MPC accounts and decentralized recovery.
 * 
 * @example Server usage:
 * ```typescript
 * import { createAnonAuth } from '@vitalpoint/near-anon-auth/server';
 * 
 * const auth = createAnonAuth({
 *   nearNetwork: 'testnet',
 *   sessionSecret: process.env.SESSION_SECRET,
 *   database: { type: 'postgres', connectionString: process.env.DATABASE_URL },
 *   rp: { name: 'My App', id: 'myapp.com', origin: 'https://myapp.com' },
 * });
 * 
 * app.use('/auth', auth.router);
 * app.get('/protected', auth.requireAuth, handler);
 * ```
 * 
 * @example Client usage:
 * ```tsx
 * import { AnonAuthProvider, useAnonAuth } from '@vitalpoint/near-anon-auth/client';
 * 
 * function App() {
 *   return (
 *     <AnonAuthProvider apiUrl="/auth">
 *       <MyComponent />
 *     </AnonAuthProvider>
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
  Session,
  Passkey,
  RecoveryType,
  RecoveryData,
  CodenameConfig,
  RecoveryConfig,
} from './types/index.js';
