# near-anon-auth

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
npm install @vitalpoint/near-anon-auth
```

## Quick Start

### Server (Express)

```typescript
import express from 'express';
import { createAnonAuth } from '@vitalpoint/near-anon-auth/server';

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
import { AnonAuthProvider, useAnonAuth } from '@vitalpoint/near-anon-auth/client';

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
    register, 
    login, 
    logout,
    error,
  } = useAnonAuth();

  if (isLoading) return <div>Loading...</div>;

  if (!isAuthenticated) {
    return (
      <div>
        <h1>Anonymous Auth Demo</h1>
        {error && <p style={{ color: 'red' }}>{error}</p>}
        <button onClick={register}>Register (Create Identity)</button>
        <button onClick={() => login()}>Sign In (Existing Identity)</button>
      </div>
    );
  }

  return (
    <div>
      <h1>Welcome, {codename}</h1>
      <p>You are authenticated anonymously.</p>
      <button onClick={logout}>Sign Out</button>
    </div>
  );
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
