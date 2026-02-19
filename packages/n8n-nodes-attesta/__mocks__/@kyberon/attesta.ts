export const Attesta = jest.fn().mockImplementation(() => ({
  evaluate: jest.fn(),
}));

export const createActionContext = jest.fn((opts: any) => ({
  functionName: opts.functionName,
  args: opts.args || [],
  kwargs: opts.kwargs || {},
  hints: opts.hints || {},
  environment: opts.environment || 'development',
  timestamp: new Date(),
  metadata: opts.metadata || {},
}));

export const Verdict = {
  APPROVED: 'approved',
  DENIED: 'denied',
  MODIFIED: 'modified',
  TIMED_OUT: 'timed_out',
  ESCALATED: 'escalated',
} as const;

export const RiskLevel = {
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical',
} as const;
