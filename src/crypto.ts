import crypto from 'crypto';

// Base58btc alphabet for did:key multicodec representation
const B58_CHARS = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function encodeBase58(buffer: Uint8Array): string {
  const digits: number[] = [0];
  for (let i = 0; i < buffer.length; i++) {
    for (let j = 0; j < digits.length; j++) digits[j] <<= 8;
    digits[0] += buffer[i];
    let carry = 0;
    for (let j = 0; j < digits.length; j++) {
      digits[j] += carry;
      carry = (digits[j] / 58) | 0;
      digits[j] %= 58;
    }
    while (carry) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  for (let i = 0; i < buffer.length && buffer[i] === 0; i++) {
    digits.push(0);
  }
  return digits.reverse().map(digit => B58_CHARS[digit]).join('');
}

export function decodeBase58(str: string): Uint8Array {
  const bytes = [0];
  for (let i = 0; i < str.length; i++) {
    const c = str[i];
    const value = B58_CHARS.indexOf(c);
    if (value === -1) throw new Error(`Invalid base58 character '${c}'`);
    for (let j = 0; j < bytes.length; j++) bytes[j] *= 58;
    bytes[0] += value;
    let carry = 0;
    for (let j = 0; j < bytes.length; j++) {
      bytes[j] += carry;
      carry = bytes[j] >> 8;
      bytes[j] &= 0xff;
    }
    while (carry) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  for (let i = 0; i < str.length && str[i] === '1'; i++) {
    bytes.push(0);
  }
  return new Uint8Array(bytes.reverse());
}

export interface KeyPair {
  publicKey: crypto.KeyObject;
  privateKey: crypto.KeyObject;
  publicKeyRaw: Uint8Array;
  did: string;
}

// Generate an Ed25519 DID key (did:key:z6M...)
export function generateEd25519Key(): KeyPair {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  
  // Export raw 32-byte public key
  const exported = publicKey.export({ type: 'spki', format: 'der' });
  // SPKI for Ed25519 has a fixed 12-byte header, followed by 32 bytes raw key
  const rawPub = new Uint8Array(exported.subarray(exported.length - 32));

  // Multicodec prefix for ed25519-pub is 0xed, 0x01
  const multicodec = new Uint8Array(2 + rawPub.length);
  multicodec[0] = 0xed;
  multicodec[1] = 0x01;
  multicodec.set(rawPub, 2);

  const did = `did:key:z${encodeBase58(multicodec)}`;

  return {
    publicKey,
    privateKey,
    publicKeyRaw: rawPub,
    did
  };
}

export function exportRawPublicKey(publicKey: crypto.KeyObject): Uint8Array {
  const der = publicKey.export({ type: 'spki', format: 'der' });
  return new Uint8Array(der.subarray(der.length - 32));
}

export function importEd25519PublicKey(raw: Uint8Array): crypto.KeyObject {
  // Construct standard SPKI header for Ed25519 (12 bytes)
  const spkiPrefix = Buffer.from('302a300506032b6570032100', 'hex');
  const spki = Buffer.concat([spkiPrefix, Buffer.from(raw)]);
  return crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
}

export function resolveDidKey(did: string): Uint8Array {
  if (!did.startsWith('did:key:z')) {
    throw new Error(`Invalid did:key format: ${did}`);
  }
  const multicodec = decodeBase58(did.slice(9));
  if (multicodec[0] !== 0xed || multicodec[1] !== 0x01) {
    throw new Error('Unsupported multicodec type, expected Ed25519 (0xed01)');
  }
  return multicodec.subarray(2);
}

// Deterministic canonical JSON stringify
export function canonicalize(obj: any): string {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return '[' + obj.map(canonicalize).join(',') + ']';
  }
  const keys = Object.keys(obj).sort();
  return '{' + keys.map(k => `${JSON.stringify(k)}:${canonicalize(obj[k])}`).join(',') + '}';
}

// Sign payload with Ed25519 private key
export function signPayload(privateKey: crypto.KeyObject, payload: any): string {
  const message = Buffer.from(canonicalize(payload), 'utf8');
  const signature = crypto.sign(null, message, privateKey);
  return signature.toString('base64url');
}

// Verify payload signature with Ed25519 public key
export function verifyPayload(publicKey: crypto.KeyObject, payload: any, signatureBase64Url: string): boolean {
  try {
    const message = Buffer.from(canonicalize(payload), 'utf8');
    const signature = Buffer.from(signatureBase64Url, 'base64url');
    return crypto.verify(null, message, publicKey, signature);
  } catch {
    return false;
  }
}
