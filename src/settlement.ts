import crypto from 'crypto';

export interface SlaEscrowState {
  escrowId: string;
  callerDid: string;
  executorDid: string;
  escrowSatoshis: number;
  hashLock: string;
  maxLatencyMs: number;
  expiryTimestamp: number;
  status: 'PENDING' | 'SETTLED' | 'REFUNDED' | 'SLASHED';
  preimage?: string;
}

export function createSlaEscrow(params: {
  callerDid: string;
  executorDid: string;
  escrowSatoshis: number;
  hashLock: string;
  maxLatencyMs: number;
  timeoutSeconds: number;
}): SlaEscrowState {
  const escrowId = `escrow_${crypto.randomBytes(8).toString('hex')}`;
  return {
    escrowId,
    callerDid: params.callerDid,
    executorDid: params.executorDid,
    escrowSatoshis: params.escrowSatoshis,
    hashLock: params.hashLock,
    maxLatencyMs: params.maxLatencyMs,
    expiryTimestamp: Date.now() + params.timeoutSeconds * 1000,
    status: 'PENDING'
  };
}

export function claimSlaSettlement(
  escrow: SlaEscrowState,
  preimage: string,
  actualLatencyMs: number
): { success: boolean; payoutSatoshis: number; slashSatoshis: number; reason?: string } {
  if (escrow.status !== 'PENDING') {
    return { success: false, payoutSatoshis: 0, slashSatoshis: 0, reason: `Escrow already in state ${escrow.status}` };
  }

  // Verify hashlock
  const hash = crypto.createHash('sha256').update(preimage).digest('hex');
  if (hash !== escrow.hashLock) {
    return { success: false, payoutSatoshis: 0, slashSatoshis: 0, reason: 'Invalid hashlock preimage provided' };
  }

  // Check SLA latency
  if (actualLatencyMs > escrow.maxLatencyMs) {
    // SLA breached! Executor penalized, partial slash
    const slash = Math.floor(escrow.escrowSatoshis * 0.5);
    const payout = escrow.escrowSatoshis - slash;
    escrow.status = 'SLASHED';
    escrow.preimage = preimage;
    return {
      success: true,
      payoutSatoshis: payout,
      slashSatoshis: slash,
      reason: `SLA Latency breached (${actualLatencyMs}ms > ${escrow.maxLatencyMs}ms limit). 50% penalty applied.`
    };
  }

  // Full settlement
  escrow.status = 'SETTLED';
  escrow.preimage = preimage;
  return {
    success: true,
    payoutSatoshis: escrow.escrowSatoshis,
    slashSatoshis: 0
  };
}

export function refundExpiredEscrow(
  escrow: SlaEscrowState
): { refunded: boolean; refundSatoshis: number; reason?: string } {
  if (escrow.status !== 'PENDING') {
    return { refunded: false, refundSatoshis: 0, reason: `Cannot refund escrow in state ${escrow.status}` };
  }
  if (Date.now() < escrow.expiryTimestamp) {
    return { refunded: false, refundSatoshis: 0, reason: 'Escrow has not reached timeout expiry' };
  }

  escrow.status = 'REFUNDED';
  return { refunded: true, refundSatoshis: escrow.escrowSatoshis };
}
