# near-phantom-auth

Anonymous passkey authentication with NEAR MPC accounts and decentralized recovery.

> 🔒 **Privacy-first**: No email, no phone, no PII. Just biometrics and blockchain.

## Features

- **Passkey Authentication**: Face ID, Touch ID, Windows Hello - no passwords
- **NEAR MPC Accounts**: User-owned accounts via Chain Signatures (8-node threshold MPC)
- **Anonymous Identity**: Codename-based (ALPHA-7, BRAVO-12) - we never know who you are
- **Decentralized Recovery**: 
  - Link a NEAR wallet (on-chain access key, not stored in our DB)
  - Password + IPFS backup (encrypted, you hold the keys)
- **HttpOnly Sessions**: XSS-proof cookie-based sessions

## Installation

```bash
npm install @vitalpoint/near-phantom-auth
```

The package provides both server and client exports:
- `@vitalpoint/near-phantom-auth/server` - Express router, session management, MPC accounts
- `@vitalpoint/near-phantom-auth/client` - React hooks, WebAuthn helpers, API client

Both are included in the single package - no separate installs needed.

## Quick Start

### Server (Express)

```typescript
import express from 'express';
import { createAnonAuth } from '@vitalpoint/near-phantom-auth/server';

const app = express();

const auth = createAnonAuth({
  nearNetwork: 'testnet',
  sessionSecret: process.env.SESSION_SECRET!,
  database: {
    type: 'postgres',
    connectionString: process.env.DATABASE_URL!,
  },
  rp: {
    name: 'My App',
    id: 'myapp.com',
    origin: 'https://myapp.com',
  },
  recovery: {
    wallet: true,
    ipfs: {
      pinningService: 'pinata',
      apiKey: process.env.PINATA_API_KEY,
      apiSecret: process.env.PINATA_API_SECRET,
    },
  },
});

// Initialize database schema
await auth.initialize();

// Mount auth routes
app.use('/auth', auth.router);

// Protect routes
app.get('/api/me', auth.requireAuth, (req, res) => {
  res.json({
    codename: req.anonUser!.codename,
    nearAccountId: req.anonUser!.nearAccountId,
  });
});

app.listen(3000);
```

### Client (React)

```tsx
import { AnonAuthProvider, useAnonAuth } from '@vitalpoint/near-phantom-auth/client';

function App() {
  return (
    <AnonAuthProvider apiUrl="/auth">
      <AuthDemo />
    </AnonAuthProvider>
  );
}

function AuthDemo() {
  const { 
    isLoading, 
    isAuthenticated, 
    codename, 
    nearAccountId,
    webAuthnSupported,
    register, 
    login, 
    logout,
    error,
    clearError,
  } = useAnonAuth();

  if (isLoading) return <div>Loading...</div>;

  if (!webAuthnSupported) {
    return <div>Your browser doesn't support passkeys.</div>;
  }

  if (!isAuthenticated) {
    return (
      <div>
        <h1>Anonymous Auth Demo</h1>
        {error && (
          <p style={{ color: 'red' }}>
            {error} <button onClick={clearError}>×</button>
          </p>
        )}
        <button onClick={register}>Register (Create Identity)</button>
        <button onClick={() => login()}>Sign In (Existing Identity)</button>
      </div>
    );
  }

  return (
    <div>
      <h1>Welcome, {codename}</h1>
      <p>NEAR Account: {nearAccountId}</p>
      <button onClick={logout}>Sign Out</button>
    </div>
  );
}
```

> ⚠️ **Important**: Always use the client library's `register` and `login` functions rather than implementing WebAuthn manually. WebAuthn uses base64url encoding (not standard base64), and the client library handles this correctly.

### Client (Vanilla JS / Non-React)

For non-React applications, use the lower-level functions:

```typescript
import { 
  createApiClient, 
  createPasskey, 
  authenticateWithPasskey,
  isWebAuthnSupported 
} from '@vitalpoint/near-phantom-auth/client';

const api = createApiClient({ baseUrl: '/auth' });

// Check support
if (!isWebAuthnSupported()) {
  console.error('WebAuthn not supported');
}

// Register
async function register() {
  const { challengeId, options, tempUserId, codename } = await api.startRegistration();
  const credential = await createPasskey(options); // Handles base64url encoding
  const result = await api.finishRegistration(challengeId, credential, tempUserId, codename);
  console.log('Registered as:', result.codename);
}

// Login
async function login() {
  const { challengeId, options } = await api.startAuthentication();
  const credential = await authenticateWithPasskey(options); // Handles base64url encoding
  const result = await api.finishAuthentication(challengeId, credential);
  console.log('Logged in as:', result.codename);
}
```

## How It Works

### Registration Flow

```
1. User clicks "Register"
2. Browser creates passkey (biometric prompt)
3. Server creates NEAR account via MPC
4. User gets codename (e.g., ALPHA-7)
5. Session cookie set (HttpOnly, Secure, SameSite=Strict)
```

### Authentication Flow

```
1. User clicks "Sign In"
2. Browser prompts for passkey (biometric)
3. Server verifies signature
4. Session cookie set
```

### Recovery Options

#### Wallet Recovery
- User links existing NEAR wallet
- Wallet added as on-chain access key (NOT stored in our database)
- Recovery: Sign with wallet → Create new passkey

#### Password + IPFS Recovery
- User sets strong password
- Recovery data encrypted with password
- Encrypted blob stored on IPFS
- User saves: password + IPFS CID
- Recovery: Provide password + CID → Decrypt → Create new passkey

## API Routes

| Method | Route | Description |
|--------|-------|-------------|
| POST | `/register/start` | Start passkey registration |
| POST | `/register/finish` | Complete registration |
| POST | `/login/start` | Start authentication |
| POST | `/login/finish` | Complete authentication |
| POST | `/logout` | End session |
| GET | `/session` | Get current session |
| POST | `/recovery/wallet/link` | Start wallet linking |
| POST | `/recovery/wallet/verify` | Complete wallet linking |
| POST | `/recovery/wallet/start` | Start wallet recovery |
| POST | `/recovery/wallet/finish` | Complete wallet recovery |
| POST | `/recovery/ipfs/setup` | Create IPFS backup |
| POST | `/recovery/ipfs/recover` | Recover from IPFS |

## Configuration

### Environment Variables

```bash
# Required
SESSION_SECRET=your-secure-session-secret
DATABASE_URL=postgresql://user:pass@localhost:5432/mydb

# NEAR Network ('testnet' or 'mainnet')
NEAR_NETWORK=mainnet

# Mainnet: Treasury for auto-funding new accounts
NEAR_TREASURY_ACCOUNT=your-treasury.near
NEAR_TREASURY_PRIVATE_KEY=ed25519:5abc123...
NEAR_FUNDING_AMOUNT=0.01  # optional, default 0.01

# Optional: Recovery via IPFS (Pinata)
PINATA_API_KEY=your-pinata-key
PINATA_API_SECRET=your-pinata-secret

# Optional: Recovery via IPFS (Web3.Storage)
WEB3_STORAGE_TOKEN=your-web3storage-token

# Optional: Recovery via IPFS (Infura)
INFURA_IPFS_PROJECT_ID=your-project-id
INFURA_IPFS_PROJECT_SECRET=your-project-secret
```

### Database Adapters

Currently supports PostgreSQL. SQLite and custom adapters coming soon.

```typescript
// PostgreSQL
database: {
  type: 'postgres',
  connectionString: 'postgresql://...',
}

// Custom adapter
database: {
  type: 'custom',
  adapter: myCustomAdapter,
}
```

### Codename Styles

```typescript
codename: {
  style: 'nato-phonetic', // ALPHA-7, BRAVO-12
  // or
  style: 'animals', // SWIFT-FALCON-42
  // or
  generator: (userId) => `SOURCE-${userId.slice(0, 8)}`,
}
```

### Recovery Options

```typescript
recovery: {
  // On-chain wallet recovery
  wallet: true,
  
  // IPFS + password recovery
  ipfs: {
    pinningService: 'pinata', // or 'web3storage', 'infura'
    apiKey: '...',
    apiSecret: '...',
    // or custom functions
    customPin: async (data) => cidString,
    customFetch: async (cid) => Uint8Array,
  },
}
```

### MPC Account Funding (Mainnet)

On NEAR mainnet, implicit accounts (64-char hex addresses) need initial funding to become active on-chain. Configure a treasury account to auto-fund new user accounts:

```typescript
const auth = createAnonAuth({
  nearNetwork: 'mainnet',
  // ... other config
  
  mpc: {
    // Treasury account that funds new users
    treasuryAccount: 'your-treasury.near',
    
    // Private key (ed25519:BASE58...) - keep secret!
    treasuryPrivateKey: process.env.NEAR_TREASURY_PRIVATE_KEY,
    
    // Amount to send to each new account (default: 0.01 NEAR)
    fundingAmount: '0.01',
    
    // Optional: custom account prefix (default: 'anon')
    accountPrefix: 'myapp',
  },
});
```

**Environment variables:**

```bash
# Required for mainnet auto-funding
NEAR_TREASURY_ACCOUNT=your-treasury.near
NEAR_TREASURY_PRIVATE_KEY=ed25519:5abc123...

# Optional
NEAR_FUNDING_AMOUNT=0.01
```

**How it works:**
1. New user registers with passkey
2. System derives deterministic implicit account ID (64-char hex)
3. Treasury sends 0.01 NEAR to activate the account
4. User can now receive/send NEAR immediately

**Cost estimation:**
- ~0.01 NEAR per new user
- 1 NEAR funds ~100 new accounts
- Treasury account needs ~0.00182 NEAR minimum balance to stay active

> ⚠️ **Testnet**: On testnet, accounts are auto-created via the NEAR testnet helper API with test tokens. No treasury needed.

## Security Model

### What We Store

| Data | Stored? | Location |
|------|---------|----------|
| Email | ❌ | - |
| Phone | ❌ | - |
| Real name | ❌ | - |
| IP address | ❌ | - |
| Codename | ✅ | Database |
| NEAR account | ✅ | Database + Blockchain |
| Passkey public key | ✅ | Database |
| Recovery wallet link | ❌ | On-chain only |
| IPFS CID | ✅ | Database (encrypted content on IPFS) |

### What We Cannot Know

- Real identity of users
- Link between codename and recovery wallet (it's on-chain, not in our DB)
- Contents of IPFS backup (encrypted with user's password)

## License

MIT

## Contributing

Contributions welcome! Please read our contributing guidelines first.
