/**
 * IPFS + Password Recovery
 * 
 * Encrypts recovery data with user's password and stores on IPFS.
 * User needs password + CID to recover.
 */

import { randomBytes, createCipheriv, createDecipheriv, scrypt } from 'crypto';
import { promisify } from 'util';

const scryptAsync = promisify(scrypt);

export interface IPFSRecoveryConfig {
  pinningService: 'pinata' | 'web3storage' | 'infura' | 'custom';
  apiKey?: string;
  apiSecret?: string;
  customPin?: (data: Uint8Array) => Promise<string>;
  customFetch?: (cid: string) => Promise<Uint8Array>;
}

export interface EncryptedRecoveryData {
  /** Encrypted payload (base64) */
  ciphertext: string;
  /** Initialization vector (base64) */
  iv: string;
  /** Salt for key derivation (base64) */
  salt: string;
  /** Auth tag for GCM (base64) */
  authTag: string;
  /** Version for future compatibility */
  version: 1;
}

export interface RecoveryPayload {
  userId: string;
  nearAccountId: string;
  derivationPath: string;
  createdAt: number;
}

/**
 * Derive encryption key from password
 */
async function deriveKey(password: string, salt: Buffer): Promise<Buffer> {
  return scryptAsync(password, salt, 32) as Promise<Buffer>;
}

/**
 * Encrypt recovery data
 */
export async function encryptRecoveryData(
  payload: RecoveryPayload,
  password: string
): Promise<EncryptedRecoveryData> {
  const salt = randomBytes(32);
  const iv = randomBytes(16);
  const key = await deriveKey(password, salt);
  
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  
  const payloadJson = JSON.stringify(payload);
  const encrypted = Buffer.concat([
    cipher.update(payloadJson, 'utf8'),
    cipher.final(),
  ]);
  
  const authTag = cipher.getAuthTag();
  
  return {
    ciphertext: encrypted.toString('base64'),
    iv: iv.toString('base64'),
    salt: salt.toString('base64'),
    authTag: authTag.toString('base64'),
    version: 1,
  };
}

/**
 * Decrypt recovery data
 */
export async function decryptRecoveryData(
  encryptedData: EncryptedRecoveryData,
  password: string
): Promise<RecoveryPayload> {
  const salt = Buffer.from(encryptedData.salt, 'base64');
  const iv = Buffer.from(encryptedData.iv, 'base64');
  const ciphertext = Buffer.from(encryptedData.ciphertext, 'base64');
  const authTag = Buffer.from(encryptedData.authTag, 'base64');
  
  const key = await deriveKey(password, salt);
  
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);
  
  try {
    const decrypted = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]);
    
    return JSON.parse(decrypted.toString('utf8'));
  } catch {
    throw new Error('Invalid password or corrupted data');
  }
}

/**
 * Pin data to IPFS using Pinata
 */
async function pinToPinata(
  data: Uint8Array,
  apiKey: string,
  apiSecret: string
): Promise<string> {
  const formData = new FormData();
  formData.append('file', new Blob([data]), 'recovery.json');
  
  const response = await fetch('https://api.pinata.cloud/pinning/pinFileToIPFS', {
    method: 'POST',
    headers: {
      'pinata_api_key': apiKey,
      'pinata_secret_api_key': apiSecret,
    },
    body: formData,
  });
  
  if (!response.ok) {
    throw new Error(`Pinata error: ${response.status}`);
  }
  
  const result = await response.json() as { IpfsHash: string };
  return result.IpfsHash;
}

/**
 * Fetch data from IPFS gateway
 */
async function fetchFromIPFS(cid: string): Promise<Uint8Array> {
  // Try multiple gateways
  const gateways = [
    `https://gateway.pinata.cloud/ipfs/${cid}`,
    `https://ipfs.io/ipfs/${cid}`,
    `https://cloudflare-ipfs.com/ipfs/${cid}`,
  ];
  
  for (const gateway of gateways) {
    try {
      const response = await fetch(gateway);
      if (response.ok) {
        return new Uint8Array(await response.arrayBuffer());
      }
    } catch {
      continue;
    }
  }
  
  throw new Error('Failed to fetch from IPFS');
}

/**
 * IPFS Recovery Manager
 */
export interface IPFSRecoveryManager {
  /**
   * Create and pin encrypted recovery data
   */
  createRecoveryBackup(
    payload: RecoveryPayload,
    password: string
  ): Promise<{ cid: string }>;
  
  /**
   * Recover data from IPFS
   */
  recoverFromBackup(
    cid: string,
    password: string
  ): Promise<RecoveryPayload>;
  
  /**
   * Validate password strength
   */
  validatePassword(password: string): {
    valid: boolean;
    errors: string[];
  };
}

export function createIPFSRecoveryManager(
  config: IPFSRecoveryConfig
): IPFSRecoveryManager {
  const MIN_PASSWORD_LENGTH = 12;

  async function pinData(data: Uint8Array): Promise<string> {
    if (config.customPin) {
      return config.customPin(data);
    }
    
    switch (config.pinningService) {
      case 'pinata':
        if (!config.apiKey || !config.apiSecret) {
          throw new Error('Pinata requires apiKey and apiSecret');
        }
        return pinToPinata(data, config.apiKey, config.apiSecret);
      
      case 'web3storage':
      case 'infura':
        throw new Error(`${config.pinningService} not yet implemented`);
      
      default:
        throw new Error('No pinning service configured');
    }
  }

  async function fetchData(cid: string): Promise<Uint8Array> {
    if (config.customFetch) {
      return config.customFetch(cid);
    }
    return fetchFromIPFS(cid);
  }

  return {
    async createRecoveryBackup(payload, password) {
      // Validate password
      const validation = this.validatePassword(password);
      if (!validation.valid) {
        throw new Error(`Invalid password: ${validation.errors.join(', ')}`);
      }
      
      // Encrypt payload
      const encrypted = await encryptRecoveryData(payload, password);
      
      // Convert to bytes
      const data = new TextEncoder().encode(JSON.stringify(encrypted));
      
      // Pin to IPFS
      const cid = await pinData(data);
      
      return { cid };
    },

    async recoverFromBackup(cid, password) {
      // Fetch from IPFS
      const data = await fetchData(cid);
      
      // Parse encrypted data
      const encrypted: EncryptedRecoveryData = JSON.parse(
        new TextDecoder().decode(data)
      );
      
      // Decrypt
      return decryptRecoveryData(encrypted, password);
    },

    validatePassword(password) {
      const errors: string[] = [];
      
      if (password.length < MIN_PASSWORD_LENGTH) {
        errors.push(`Password must be at least ${MIN_PASSWORD_LENGTH} characters`);
      }
      
      if (!/[a-z]/.test(password)) {
        errors.push('Password must contain lowercase letters');
      }
      
      if (!/[A-Z]/.test(password)) {
        errors.push('Password must contain uppercase letters');
      }
      
      if (!/[0-9]/.test(password)) {
        errors.push('Password must contain numbers');
      }
      
      return {
        valid: errors.length === 0,
        errors,
      };
    },
  };
}
