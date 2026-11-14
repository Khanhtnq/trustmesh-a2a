import crypto from 'crypto';
import { describe, it, expect } from 'vitest';
import {
  generateEd25519Key,
  resolveDidKey,
  importEd25519PublicKey,
  canonicalize,
  signPayload,
  verifyPayload,
  encodeBase58,
  decodeBase58
} from '../src/crypto.js';
import {
  createAgentCard,
  validateAgentCard
} from '../src/agentCard.js';
import {
  issueCapabilityCredential,
  verifyCapabilityCredential,
  issueExecutionReceipt,
  verifyExecutionReceipt
} from '../src/credentials.js';
import {
  createSlaEscrow,
  claimSlaSettlement,
  refundExpiredEscrow
} from '../src/settlement.js';

describe('TrustMesh Agentic Web Protocol Suite', () => {

  describe('1. Cryptographic Primitive & DID Key Generation', () => {
    it('generates compliant Ed25519 did:key with z-base58 multicodec prefix', () => {
      const key = generateEd25519Key();
      expect(key.did).toMatch(/^did:key:z[1-9A-HJ-NP-Za-km-z]+$/);
      expect(key.publicKeyRaw.length).toBe(32);
    });

    it('resolves did:key string back to 32-byte raw Ed25519 public key', () => {
      const key = generateEd25519Key();
      const raw = resolveDidKey(key.did);
      expect(raw).toEqual(key.publicKeyRaw);
    });

    it('encodes and decodes base58 roundtrip without data corruption', () => {
      const payload = new Uint8Array([0xed, 0x01, 10, 20, 30, 40, 50, 255]);
      const encoded = encodeBase58(payload);
      const decoded = decodeBase58(encoded);
      expect(decoded).toEqual(payload);
    });

    it('produces deterministic canonical JSON regardless of key ordering', () => {
      const obj1 = { z: 1, a: 2, m: { nestedB: true, nestedA: 'hello' } };
      const obj2 = { a: 2, m: { nestedA: 'hello', nestedB: true }, z: 1 };
      expect(canonicalize(obj1)).toBe(canonicalize(obj2));
    });

    it('verifies valid cryptographic signatures on payloads', () => {
      const key = generateEd25519Key();
      const payload = { action: 'execute_contract', target: '0x123', amount: 5000 };
      const sig = signPayload(key.privateKey, payload);
      expect(typeof sig).toBe('string');
      expect(verifyPayload(key.publicKey, payload, sig)).toBe(true);
    });

    it('fails verification if payload is altered (tamper resistance)', () => {
      const key = generateEd25519Key();
      const payload = { action: 'execute_contract', amount: 5000 };
      const sig = signPayload(key.privateKey, payload);
      const tampered = { action: 'execute_contract', amount: 5000000 };
      expect(verifyPayload(key.publicKey, tampered, sig)).toBe(false);
    });
  });

  describe('2. Agent Discovery Card RFC Specification', () => {
    it('creates a compliant /.well-known/agent-card.json structure', () => {
      const key = generateEd25519Key();
      const card = createAgentCard({
        did: key.did,
        name: 'Nexus Oracle Agent',
        description: 'Decentralized price feed and settlement validator',
        serviceEndpoint: 'https://agent.nexus.network',
        publicKeyMultibase: key.did.replace('did:key:', ''),
        skills: [{ id: 'oracle:query', name: 'Price Feed Query', description: 'Real-time FX rates' }]
      });

      expect(card['@context']).toContain('https://agentic-web.org/ns/agent-card/v1');
      expect(card.skills.length).toBe(1);
      const validation = validateAgentCard(card);
      expect(validation.valid).toBe(true);
      expect(validation.errors).toHaveLength(0);
    });

    it('rejects agent card missing mandatory fields or invalid did identifier', () => {
      const invalidCard: any = {
        id: 'invalid-id-format',
        serviceEndpoint: 'not-a-url',
        skills: []
      };
      const validation = validateAgentCard(invalidCard);
      expect(validation.valid).toBe(false);
      expect(validation.errors.length).toBeGreaterThanOrEqual(2);
    });
  });

  describe('3. W3C Verifiable Capability Credentials & Delegation Attenuation', () => {
    it('issues and verifies a valid root AgentCapabilityCredential', () => {
      const issuer = generateEd25519Key();
      const delegatee = generateEd25519Key();

      const cred = issueCapabilityCredential(issuer, {
        subjectDid: delegatee.did,
        allowedActions: ['data:fetch', 'crypto:sign'],
        maxBudgetSats: 1000000,
        maxDelegationDepth: 3,
        validitySeconds: 7200
      });

      expect(cred.issuer).toBe(issuer.did);
      expect(cred.proof?.jws).toBeDefined();

      const result = verifyCapabilityCredential(cred);
      expect(result.valid).toBe(true);
    });

    it('rejects credential with forged or manipulated issuer signature', () => {
      const issuer = generateEd25519Key();
      const delegatee = generateEd25519Key();

      const cred = issueCapabilityCredential(issuer, {
        subjectDid: delegatee.did,
        allowedActions: ['data:fetch'],
        maxBudgetSats: 100000,
        maxDelegationDepth: 1
      });

      // Adversarial manipulation of budget
      cred.credentialSubject.maxBudgetSats = 99999999;
      const result = verifyCapabilityCredential(cred);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('invalid or forged');
    });

    it('rejects expired credential', () => {
      const issuer = generateEd25519Key();
      const delegatee = generateEd25519Key();

      const cred = issueCapabilityCredential(issuer, {
        subjectDid: delegatee.did,
        allowedActions: ['data:fetch'],
        maxBudgetSats: 100000,
        maxDelegationDepth: 1,
        validitySeconds: -3600 // Expired 1 hour ago
      });

      const result = verifyCapabilityCredential(cred);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('expired');
    });

    it('allows valid delegation attenuation when child respects parent limits', () => {
      const rootIssuer = generateEd25519Key();
      const subAgentA = generateEd25519Key();
      const subAgentB = generateEd25519Key();

      const rootCred = issueCapabilityCredential(rootIssuer, {
        subjectDid: subAgentA.did,
        allowedActions: ['storage:read', 'storage:write', 'network:call'],
        maxBudgetSats: 1000000,
        maxDelegationDepth: 2
      });

      // Sub-agent A delegates to Sub-agent B with attenuated depth & scope
      const delegatedCred = issueCapabilityCredential(subAgentA, {
        subjectDid: subAgentB.did,
        allowedActions: ['storage:read'],
        maxBudgetSats: 250000,
        maxDelegationDepth: 1,
        parentCredential: rootCred
      });

      expect(delegatedCred.credentialSubject.parentCredentialHash).toBe(rootCred.id);
      expect(verifyCapabilityCredential(delegatedCred).valid).toBe(true);
    });

    it('rejects delegation depth escalation beyond parent allowance', () => {
      const rootIssuer = generateEd25519Key();
      const subAgentA = generateEd25519Key();
      const subAgentB = generateEd25519Key();

      const rootCred = issueCapabilityCredential(rootIssuer, {
        subjectDid: subAgentA.did,
        allowedActions: ['storage:read'],
        maxBudgetSats: 1000000,
        maxDelegationDepth: 1
      });

      // Trying to delegate with depth >= parent depth
      expect(() => {
        issueCapabilityCredential(subAgentA, {
          subjectDid: subAgentB.did,
          allowedActions: ['storage:read'],
          maxBudgetSats: 500000,
          maxDelegationDepth: 1,
          parentCredential: rootCred
        });
      }).toThrow('Attenuated delegation depth must be strictly less than parent');
    });

    it('rejects delegation scope expansion beyond parent authorized actions', () => {
      const rootIssuer = generateEd25519Key();
      const subAgentA = generateEd25519Key();
      const subAgentB = generateEd25519Key();

      const rootCred = issueCapabilityCredential(rootIssuer, {
        subjectDid: subAgentA.did,
        allowedActions: ['storage:read'],
        maxBudgetSats: 500000,
        maxDelegationDepth: 2
      });

      // Trying to grant unauthorized action
      expect(() => {
        issueCapabilityCredential(subAgentA, {
          subjectDid: subAgentB.did,
          allowedActions: ['storage:read', 'admin:delete_all'],
          maxBudgetSats: 100000,
          maxDelegationDepth: 1,
          parentCredential: rootCred
        });
      }).toThrow(/Scope violation/);
    });
  });

  describe('4. Execution Receipts & SLA Settlement Protocol', () => {
    it('issues and cryptographically verifies ExecutionReceiptCredential', () => {
      const executor = generateEd25519Key();
      const caller = generateEd25519Key();
      const preimage = 'secret_proof_preimage_789xyz';

      const receipt = issueExecutionReceipt(executor, {
        taskId: 'task_001',
        capabilityCredentialId: 'urn:uuid:123',
        callerDid: caller.did,
        action: 'compute:matrix_factorization',
        inputData: { matrixSize: [100, 100] },
        outputData: { status: 'converged', iterations: 42 },
        latencyMs: 120,
        slaSecretPreimage: preimage
      });

      expect(receipt.credentialSubject.status).toBe('COMPLETED');
      expect(receipt.credentialSubject.settlementHashLock).toBeDefined();

      const result = verifyExecutionReceipt(receipt);
      expect(result.valid).toBe(true);
    });

    it('settles SLA escrow in full when SLA latency and preimage are valid', () => {
      const preimage = 'settle_token_alpha_99';
      const hashLock = crypto.createHash('sha256').update(preimage).digest('hex');

      const escrow = createSlaEscrow({
        callerDid: 'did:key:zCaller',
        executorDid: 'did:key:zExecutor',
        escrowSatoshis: 100000,
        hashLock: hashLock,
        maxLatencyMs: 500,
        timeoutSeconds: 3600
      });

      const outcome = claimSlaSettlement(escrow, preimage, 350);
      expect(outcome.success).toBe(true);
      expect(outcome.payoutSatoshis).toBe(100000);
      expect(outcome.slashSatoshis).toBe(0);
      expect(escrow.status).toBe('SETTLED');
    });

    it('penalizes executor with slash when SLA latency is violated', () => {
      const preimage = 'settle_token_beta_88';
      const crypto = require('crypto');
      const hashLock = crypto.createHash('sha256').update(preimage).digest('hex');

      const escrow = createSlaEscrow({
        callerDid: 'did:key:zCaller',
        executorDid: 'did:key:zExecutor',
        escrowSatoshis: 100000,
        hashLock: hashLock,
        maxLatencyMs: 300,
        timeoutSeconds: 3600
      });

      // Actual latency 800ms > 300ms limit
      const outcome = claimSlaSettlement(escrow, preimage, 800);
      expect(outcome.success).toBe(true);
      expect(outcome.slashSatoshis).toBe(50000); // 50% penalty
      expect(outcome.payoutSatoshis).toBe(50000);
      expect(escrow.status).toBe('SLASHED');
    });

    it('prevents replay attack or double claiming of settled escrow', () => {
      const preimage = 'settle_token_gamma_77';
      const crypto = require('crypto');
      const hashLock = crypto.createHash('sha256').update(preimage).digest('hex');

      const escrow = createSlaEscrow({
        callerDid: 'did:key:zCaller',
        executorDid: 'did:key:zExecutor',
        escrowSatoshis: 50000,
        hashLock: hashLock,
        maxLatencyMs: 500,
        timeoutSeconds: 3600
      });

      claimSlaSettlement(escrow, preimage, 200);
      const replayAttempt = claimSlaSettlement(escrow, preimage, 200);
      expect(replayAttempt.success).toBe(false);
      expect(replayAttempt.reason).toContain('already in state SETTLED');
    });

    it('rejects refund if escrow timeout has not elapsed', () => {
      const escrow = createSlaEscrow({
        callerDid: 'did:key:zCaller',
        executorDid: 'did:key:zExecutor',
        escrowSatoshis: 50000,
        hashLock: 'hash123',
        maxLatencyMs: 500,
        timeoutSeconds: 3600 // Expiry in 1h
      });

      const refundResult = refundExpiredEscrow(escrow);
      expect(refundResult.refunded).toBe(false);
      expect(refundResult.reason).toContain('not reached timeout');
    });
  });
});
