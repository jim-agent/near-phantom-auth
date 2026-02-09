/**
 * IPFS + Password Recovery
 * 
 * Encrypts recovery data with user's password and stores on IPFS.
 * User needs password + CID to recover.
 * 
 * Supported pinning services:
 * - Pinata (https://pinata.cloud)
 * - web3.storage (https://web3.storage)
 * - Infura (https://infura.io)
 */

import { randomBytes, createCipheriv, createDecipheriv, scrypt } from 'crypto';
import { promisify } from 'util';

const scryptAsync = promisify(scrypt);

export interface IPFSRecoveryConfig {
  pinningService: 'pinata' | 'web3storage' | 'infura' | 'custom';
  /** API key (required for pinata, web3storage, infura) */
  apiKey?: string;
  /** API secret (required for pinata, infura) */
  apiSecret?: string;
  /** Project ID (required for infura) */
  projectId?: string;
  /** Custom pinning function */
  customPin?: (data: Uint8Array) => Promise<string>;
  /** Custom fetch function */
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

// ============================================
// Pinning Services
// ============================================

/**
 * Pin data to IPFS using Pinata
 * https://docs.pinata.cloud/api-reference/endpoint/pin-file-to-ipfs
 */
async function pinToPinata(
  data: Uint8Array,
  apiKey: string,
  apiSecret: string
): Promise<string> {
  const formData = new FormData();
  const buffer = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer;
  formData.append('file', new Blob([buffer]), 'recovery.json');
  
  const response = await fetch('https://api.pinata.cloud/pinning/pinFileToIPFS', {
    method: 'POST',
    headers: {
      'pinata_api_key': apiKey,
      'pinata_secret_api_key': apiSecret,
    },
    body: formData,
  });
  
  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Pinata error: ${response.status} - ${error}`);
  }
  
  const result = await response.json() as { IpfsHash: string };
  return result.IpfsHash;
}

/**
 * Pin data to IPFS using web3.storage
 * https://web3.storage/docs/how-to/upload/
 */
async function pinToWeb3Storage(
  data: Uint8Array,
  apiToken: string
): Promise<string> {
  const buffer = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer;
  
  const response = await fetch('https://api.web3.storage/upload', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${apiToken}`,
      'Content-Type': 'application/octet-stream',
      'X-Name': 'phantom-recovery.json',
    },
    body: buffer,
  });
  
  if (!response.ok) {
    const error = await response.text();
    throw new Error(`web3.storage error: ${response.status} - ${error}`);
  }
  
  const result = await response.json() as { cid: string };
  return result.cid;
}

/**
 * Pin data to IPFS using Infura
 * https://docs.infura.io/infura/networks/ipfs/http-api-methods/add
 */
async function pinToInfura(
  data: Uint8Array,
  projectId: string,
  projectSecret: string
): Promise<string> {
  const formData = new FormData();
  const buffer = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer;
  formData.append('file', new Blob([buffer]), 'recovery.json');
  
  const auth = Buffer.from(`${projectId}:${projectSecret}`).toString('base64');
  
  const response = await fetch('https://ipfs.infura.io:5001/api/v0/add', {
    method: 'POST',
    headers: {
      'Authorization': `Basic ${auth}`,
    },
    body: formData,
  });
  
  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Infura error: ${response.status} - ${error}`);
  }
  
  const result = await response.json() as { Hash: string };
  return result.Hash;
}

/**
 * Fetch data from IPFS gateway
 */
async function fetchFromIPFS(cid: string): Promise<Uint8Array> {
  // Try multiple gateways for reliability
  const gateways = [
    `https://gateway.pinata.cloud/ipfs/${cid}`,
    `https://w3s.link/ipfs/${cid}`,
    `https://ipfs.infura.io/ipfs/${cid}`,
    `https://ipfs.io/ipfs/${cid}`,
    `https://cloudflare-ipfs.com/ipfs/${cid}`,
    `https://dweb.link/ipfs/${cid}`,
  ];
  
  for (const gateway of gateways) {
    try {
      const response = await fetch(gateway, {
        headers: {
          'Accept': 'application/octet-stream',
        },
      });
      if (response.ok) {
        return new Uint8Array(await response.arrayBuffer());
      }
    } catch {
      continue;
    }
  }
  
  throw new Error('Failed to fetch from IPFS - tried all gateways');
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
    strength: 'weak' | 'medium' | 'strong';
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
        if (!config.apiKey) {
          throw new Error('web3.storage requires apiKey (API token)');
        }
        return pinToWeb3Storage(data, config.apiKey);
      
      case 'infura':
        if (!config.projectId || !config.apiSecret) {
          throw new Error('Infura requires projectId and apiSecret');
        }
        return pinToInfura(data, config.projectId, config.apiSecret);
      
      case 'custom':
        throw new Error('Custom pinning requires customPin function');
      
      default:
        throw new Error(`Unknown pinning service: ${config.pinningService}`);
    }
  }

  async function fetchData(cid: string): Promise<Uint8Array> {
    if (config.customFetch) {
      return config.customFetch(cid);
    }
    return fetchFromIPFS(cid);
  }

  function calculatePasswordStrength(password: string): 'weak' | 'medium' | 'strong' {
    let score = 0;
    
    if (password.length >= 12) score++;
    if (password.length >= 16) score++;
    if (/[a-z]/.test(password)) score++;
    if (/[A-Z]/.test(password)) score++;
    if (/[0-9]/.test(password)) score++;
    if (/[^a-zA-Z0-9]/.test(password)) score++;
    
    if (score <= 2) return 'weak';
    if (score <= 4) return 'medium';
    return 'strong';
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
      
      console.log(`[IPFS] Recovery backup created: ${cid} (${config.pinningService})`);
      
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
      
      const strength = calculatePasswordStrength(password);
      
      return {
        valid: errors.length === 0,
        errors,
        strength,
      };
    },
  };
}
