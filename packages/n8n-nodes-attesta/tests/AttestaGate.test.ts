jest.mock('n8n-workflow', () => ({
  NodeOperationError: class NodeOperationError extends Error {
    constructor(node: any, message: string, options?: any) {
      super(message);
      this.name = 'NodeOperationError';
    }
  },
}));

import { Attesta, createActionContext, Verdict, RiskLevel } from '@kyberon/attesta';
import { AttestaGate } from '../nodes/AttestaGate/AttestaGate.node';

const MockAttesta = Attesta as jest.MockedClass<typeof Attesta>;

function createMockExecuteFunctions(overrides: Record<string, any> = {}) {
  const params: Record<string, any> = {
    functionName: 'send_email',
    riskLevel: 'auto',
    riskHints: '{}',
    onDenied: 'error',
    ...overrides,
  };

  return {
    getInputData: jest.fn().mockReturnValue([
      { json: { to: 'user@example.com', subject: 'Hello' } },
    ]),
    getNodeParameter: jest.fn((name: string) => params[name]),
    getNode: jest.fn().mockReturnValue({ id: 'test-node-id', name: 'Attesta Approval' }),
  };
}

describe('AttestaGate', () => {
  let node: AttestaGate;

  beforeEach(() => {
    node = new AttestaGate();
    jest.clearAllMocks();
  });

  it('should have correct description', () => {
    expect(node.description.displayName).toBe('Attesta Approval');
    expect(node.description.name).toBe('attestaGate');
    expect(node.description.group).toContain('transform');
  });

  it('should pass approved items with _attesta metadata', async () => {
    const mockResult = {
      verdict: Verdict.APPROVED,
      riskAssessment: { score: 0.2, level: 'low' },
      auditEntryId: 'audit-123',
    };
    MockAttesta.mockImplementation(() => ({
      evaluate: jest.fn().mockResolvedValue(mockResult),
    }) as any);

    const mockFns = createMockExecuteFunctions();
    const execute = node.execute.bind(mockFns);
    const result = await execute();

    expect(result[0]).toHaveLength(1);
    expect(result[0][0].json._attesta).toEqual({
      verdict: 'approved',
      riskScore: 0.2,
      riskLevel: 'low',
      auditEntryId: 'audit-123',
      denied: false,
    });
  });

  it('should throw on denied when onDenied=error', async () => {
    const mockResult = {
      verdict: Verdict.DENIED,
      riskAssessment: { score: 0.8, level: 'high' },
      auditEntryId: 'audit-456',
    };
    MockAttesta.mockImplementation(() => ({
      evaluate: jest.fn().mockResolvedValue(mockResult),
    }) as any);

    const mockFns = createMockExecuteFunctions({ onDenied: 'error' });
    const execute = node.execute.bind(mockFns);

    await expect(execute()).rejects.toThrow('denied by Attesta');
  });

  it('should passthrough denied items with metadata when onDenied=passthrough', async () => {
    const mockResult = {
      verdict: Verdict.DENIED,
      riskAssessment: { score: 0.8, level: 'high' },
      auditEntryId: 'audit-789',
    };
    MockAttesta.mockImplementation(() => ({
      evaluate: jest.fn().mockResolvedValue(mockResult),
    }) as any);

    const mockFns = createMockExecuteFunctions({ onDenied: 'passthrough' });
    const execute = node.execute.bind(mockFns);
    const result = await execute();

    expect(result[0]).toHaveLength(1);
    expect(result[0][0].json._attesta).toEqual({
      verdict: 'denied',
      riskScore: 0.8,
      riskLevel: 'high',
      auditEntryId: 'audit-789',
      denied: true,
    });
  });

  it('should throw on invalid riskHints JSON', async () => {
    const mockFns = createMockExecuteFunctions({ riskHints: '{invalid' });
    const execute = node.execute.bind(mockFns);

    await expect(execute()).rejects.toThrow('Risk Hints must be valid JSON');
  });
});
