import crypto from 'crypto';
import { 
  KeyPair, 
  signPayload, 
  verifyPayload, 
  importEd25519PublicKey, 
  resolveDidKey 
} from './crypto.js';

export interface VerifiableCredentialProof {
  type: string;
  created: string;
  verificationMethod: string;
  proofPurpose: string;
  jws: string;
}

export interface AgentCapabilityCredential {
  '@context': string[];
  id: string;
  type: string[];
  issuer: string;
  issuanceDate: string;
  expirationDate: string;
  credentialSubject: {
    id: string; // Delegatee DID
    allowedActions: string[];
    maxBudgetSats: number;
    maxDelegationDepth: number;
    parentCredentialHash?: string;
  };
  proof?: VerifiableCredentialProof;
}

export interface ExecutionReceiptCredential {
  '@context': string[];
  id: string;
  type: string[];
  issuer: string;
  issuanceDate: string;
  credentialSubject: {
    taskId: string;
    capabilityCredentialId: string;
    executorDid: string;
    callerDid: string;
    action: string;
    inputHash: string;
    outputHash: string;
    latencyMs: number;
    status: 'COMPLETED' | 'FAILED' | 'SLA_VIOLATED';
    slaPreimage?: string;
    settlementHashLock?: string;
  };
  proof?: VerifiableCredentialProof;
}

// Issue a root or attenuated AgentCapabilityCredential
export function issueCapabilityCredential(
  issuerKeyPair: KeyPair,
  params: {
    subjectDid: string;
    allowedActions: string[];
    maxBudgetSats: number;
    maxDelegationDepth: number;
    validitySeconds?: number;
    parentCredential?: AgentCapabilityCredential;
  }
): AgentCapabilityCredential {
  // If delegating from parent credential, enforce strict attenuation
  if (params.parentCredential) {
    const parent = params.parentCredential.credentialSubject;
    if (parent.maxDelegationDepth <= 0) {
      throw new Error('Delegation depth exceeded: parent has maxDelegationDepth = 0');
    }
    if (params.maxDelegationDepth >= parent.maxDelegationDepth) {
      throw new Error(`Attenuated delegation depth must be strictly less than parent (${parent.maxDelegationDepth})`);
    }
    if (params.maxBudgetSats > parent.maxBudgetSats) {
      throw new Error(`Attenuated budget (${params.maxBudgetSats}) cannot exceed parent budget (${parent.maxBudgetSats})`);
    }
    // Scope attenuation: actions must be subset of parent actions
    for (const action of params.allowedActions) {
      if (!parent.allowedActions.includes(action) && !parent.allowedActions.includes('*')) {
        throw new Error(`Scope violation: action '${action}' not authorized in parent credential`);
      }
    }
  }

  const now = new Date();
  const validitySec = params.validitySeconds || 86400; // 24h default
  const expiration = new Date(now.getTime() + validitySec * 1000);

  const unsigned: Omit<AgentCapabilityCredential, 'proof'> = {
    '@context': [
      'https://www.w3.org/2018/credentials/v1',
      'https://agentic-web.org/ns/agent-credentials/v1'
    ],
    id: `urn:uuid:${crypto.randomUUID()}`,
    type: ['VerifiableCredential', 'AgentCapabilityCredential'],
    issuer: issuerKeyPair.did,
    issuanceDate: now.toISOString(),
    expirationDate: expiration.toISOString(),
    credentialSubject: {
      id: params.subjectDid,
      allowedActions: params.allowedActions,
      maxBudgetSats: params.maxBudgetSats,
      maxDelegationDepth: params.maxDelegationDepth,
      parentCredentialHash: params.parentCredential?.id
    }
  };

  const jws = signPayload(issuerKeyPair.privateKey, unsigned);
  return {
    ...unsigned,
    proof: {
      type: 'Ed25519Signature2020',
      created: now.toISOString(),
      verificationMethod: `${issuerKeyPair.did}#key-1`,
      proofPurpose: 'assertionMethod',
      jws
    }
  };
}

// Verify a capability credential signature and temporal validity
export function verifyCapabilityCredential(credential: AgentCapabilityCredential): { valid: boolean; reason?: string } {
  if (!credential.proof) {
    return { valid: false, reason: 'Missing cryptographic proof in credential' };
  }

  // Check temporal validity
  const now = new Date();
  if (now > new Date(credential.expirationDate)) {
    return { valid: false, reason: 'Credential expired' };
  }
  if (now < new Date(credential.issuanceDate)) {
    return { valid: false, reason: 'Credential not yet valid (future issuanceDate)' };
  }

  const { proof, ...unsigned } = credential;
  const rawIssuerPub = resolveDidKey(credential.issuer);
  const issuerKey = importEd25519PublicKey(rawIssuerPub);

  const isValidSig = verifyPayload(issuerKey, unsigned, proof.jws);
  if (!isValidSig) {
    return { valid: false, reason: 'Cryptographic Ed25519 signature invalid or forged' };
  }

  return { valid: true };
}

// Issue Execution Receipt Credential
export function issueExecutionReceipt(
  executorKeyPair: KeyPair,
  params: {
    taskId: string;
    capabilityCredentialId: string;
    callerDid: string;
    action: string;
    inputData: any;
    outputData: any;
    latencyMs: number;
    slaSecretPreimage?: string;
  }
): ExecutionReceiptCredential {
  const inputHash = crypto.createHash('sha256').update(JSON.stringify(params.inputData)).digest('hex');
  const outputHash = crypto.createHash('sha256').update(JSON.stringify(params.outputData)).digest('hex');

  let settlementHashLock: string | undefined;
  if (params.slaSecretPreimage) {
    settlementHashLock = crypto.createHash('sha256').update(params.slaSecretPreimage).digest('hex');
  }

  const now = new Date();
  const unsigned: Omit<ExecutionReceiptCredential, 'proof'> = {
    '@context': [
      'https://www.w3.org/2018/credentials/v1',
      'https://agentic-web.org/ns/execution-receipt/v1'
    ],
    id: `urn:uuid:${crypto.randomUUID()}`,
    type: ['VerifiableCredential', 'ExecutionReceiptCredential'],
    issuer: executorKeyPair.did,
    issuanceDate: now.toISOString(),
    credentialSubject: {
      taskId: params.taskId,
      capabilityCredentialId: params.capabilityCredentialId,
      executorDid: executorKeyPair.did,
      callerDid: params.callerDid,
      action: params.action,
      inputHash,
      outputHash,
      latencyMs: params.latencyMs,
      status: 'COMPLETED',
      slaPreimage: params.slaSecretPreimage,
      settlementHashLock
    }
  };

  const jws = signPayload(executorKeyPair.privateKey, unsigned);
  return {
    ...unsigned,
    proof: {
      type: 'Ed25519Signature2020',
      created: now.toISOString(),
      verificationMethod: `${executorKeyPair.did}#key-1`,
      proofPurpose: 'assertionMethod',
      jws
    }
  };
}

// Verify execution receipt
export function verifyExecutionReceipt(receipt: ExecutionReceiptCredential): { valid: boolean; reason?: string } {
  if (!receipt.proof) {
    return { valid: false, reason: 'Missing cryptographic proof in receipt' };
  }

  const { proof, ...unsigned } = receipt;
  const rawIssuerPub = resolveDidKey(receipt.issuer);
  const issuerKey = importEd25519PublicKey(rawIssuerPub);

  const isValidSig = verifyPayload(issuerKey, unsigned, proof.jws);
  if (!isValidSig) {
    return { valid: false, reason: 'Receipt cryptographic signature is invalid' };
  }

  // Verify hashlock preimage integrity if present
  if (receipt.credentialSubject.slaPreimage && receipt.credentialSubject.settlementHashLock) {
    const computedHash = crypto.createHash('sha256').update(receipt.credentialSubject.slaPreimage).digest('hex');
    if (computedHash !== receipt.credentialSubject.settlementHashLock) {
      return { valid: false, reason: 'SLA hashlock preimage mismatch' };
    }
  }

  return { valid: true };
}
