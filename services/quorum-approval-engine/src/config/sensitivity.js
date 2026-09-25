/**
 * Sensitivity Tiers Configuration for M-of-N Quorum Approval Engine
 * SecureChain DMS (SIH26190)
 */

const SENSITIVITY_TIERS = {
  LOW: {
    tier: 'LOW',
    threshold_m: 2,
    pool_size_n: 3,
    description: '2-of-3 threshold configuration (Demo)'
  },
  MEDIUM: {
    tier: 'MEDIUM',
    threshold_m: 2,
    pool_size_n: 3,
    description: '2-of-3 threshold configuration (Demo)'
  },
  HIGH: {
    tier: 'HIGH',
    threshold_m: 2,
    pool_size_n: 3,
    description: '2-of-3 threshold configuration (Demo)'
  }
};

function getTierConfig(tier) {
  const normalized = (tier || '').toUpperCase();
  if (!SENSITIVITY_TIERS[normalized]) {
    throw new Error(`Invalid sensitivity tier: '${tier}'. Must be one of LOW, MEDIUM, HIGH.`);
  }
  return SENSITIVITY_TIERS[normalized];
}

module.exports = {
  SENSITIVITY_TIERS,
  getTierConfig
};
