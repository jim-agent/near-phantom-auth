/**
 * Wallet Recovery
 * 
 * Allows users to link a NEAR wallet as a recovery method.
 * The wallet is added as an on-chain access key - no mapping stored in our DB.
 */

import { createHash } from 'crypto';
import nacl from 'tweetnacl';
import bs58 from 'bs58';

export interface WalletRecoveryConfig {
  nearNetwork: 'testnet' | 'mainnet';
}

export interface WalletSignature {
  signature: string;  // Base64 or hex encoded
  publicKey: string;  // ed25519:... format
  message: string;    // The signed message
}

/**
 * Generate a challenge message for wallet signing
 */
export function generateWalletChallenge(action: string, timestamp: number): string {
  return `near-anon-auth:${action}:${timestamp}`;
}

/**
 * Verify a NEAR wallet signature
 */
export function verifyWalletSignature(
  signature: WalletSignature,
  expectedMessage: string
): boolean {
  try {
    if (signature.message !== expectedMessage) {
      return false;
    }
    
    // Extract public key bytes
    const pubKeyStr = signature.publicKey.replace('ed25519:', '');
    const publicKeyBytes = bs58.decode(pubKeyStr);
    
    // Decode signature
    const signatureBytes = Buffer.from(signature.signature, 'base64');
    
    // Hash the message (NEAR signs SHA256 hash)
    const messageHash = createHash('sha256')
      .update(signature.message)
      .digest();
    
    // Verify using nacl
    return nacl.sign.detached.verify(
      messageHash,
      signatureBytes,
      publicKeyBytes
    );
  } catch (error) {
    console.error('[WalletRecovery] Signature verification failed:', error);
    return false;
  }
}

/**
 * Extract account ID from public key (for implicit accounts)
 */
export function publicKeyToImplicitAccount(publicKey: string): string {
  const pubKeyStr = publicKey.replace('ed25519:', '');
  const publicKeyBytes = bs58.decode(pubKeyStr);
  return Buffer.from(publicKeyBytes).toString('hex');
}

/**
 * Check if a wallet has access key on a NEAR account
 */
export async function checkWalletAccess(
  nearAccountId: string,
  walletPublicKey: string,
  networkId: 'testnet' | 'mainnet'
): Promise<boolean> {
  try {
    const rpcUrl = networkId === 'mainnet'
      ? 'https://rpc.mainnet.near.org'
      : 'https://rpc.testnet.near.org';

    const response = await fetch(rpcUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 'check-access-key',
        method: 'query',
        params: {
          request_type: 'view_access_key',
          finality: 'final',
          account_id: nearAccountId,
          public_key: walletPublicKey,
        },
      }),
    });

    const result = await response.json() as { error?: unknown };
    return !result.error;
  } catch {
    return false;
  }
}

/**
 * Wallet Recovery Manager
 */
export interface WalletRecoveryManager {
  /**
   * Generate challenge for linking a wallet
   */
  generateLinkChallenge(): { challenge: string; expiresAt: Date };
  
  /**
   * Verify wallet signature and prepare for linking
   */
  verifyLinkSignature(
    signature: WalletSignature,
    challenge: string
  ): { verified: boolean; walletId?: string };
  
  /**
   * Generate challenge for recovery
   */
  generateRecoveryChallenge(): { challenge: string; expiresAt: Date };
  
  /**
   * Verify recovery signature
   */
  verifyRecoverySignature(
    signature: WalletSignature,
    challenge: string,
    nearAccountId: string
  ): Promise<{ verified: boolean }>;
}

export function createWalletRecoveryManager(
  config: WalletRecoveryConfig
): WalletRecoveryManager {
  const CHALLENGE_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes

  return {
    generateLinkChallenge() {
      const timestamp = Date.now();
      const challenge = generateWalletChallenge('link-recovery', timestamp);
      const expiresAt = new Date(Date.now() + CHALLENGE_TIMEOUT_MS);
      return { challenge, expiresAt };
    },

    verifyLinkSignature(signature, challenge) {
      const verified = verifyWalletSignature(signature, challenge);
      
      if (!verified) {
        return { verified: false };
      }
      
      // Extract wallet ID from signature's public key
      // For named accounts, we'll need the account ID from the request
      // For implicit accounts, we derive from public key
      const walletId = signature.publicKey;
      
      return { verified: true, walletId };
    },

    generateRecoveryChallenge() {
      const timestamp = Date.now();
      const challenge = generateWalletChallenge('recover-account', timestamp);
      const expiresAt = new Date(Date.now() + CHALLENGE_TIMEOUT_MS);
      return { challenge, expiresAt };
    },

    async verifyRecoverySignature(signature, challenge, nearAccountId) {
      // First verify the signature itself
      if (!verifyWalletSignature(signature, challenge)) {
        return { verified: false };
      }
      
      // Then verify this wallet has access to the NEAR account
      const hasAccess = await checkWalletAccess(
        nearAccountId,
        signature.publicKey,
        config.nearNetwork
      );
      
      return { verified: hasAccess };
    },
  };
}
