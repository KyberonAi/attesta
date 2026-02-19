jest.mock('flowise-components', () => ({}), { virtual: true });

import { Attesta, Verdict } from '@kyberon/attesta';
import { DynamicTool } from '@langchain/core/tools';

const MockAttesta = Attesta as jest.MockedClass<typeof Attesta>;

const { nodeClass: AttestaGateClass } = require('../src/AttestaGate');

describe('AttestaGate (Flowise)', () => {
  let node: any;

  beforeEach(() => {
    node = new AttestaGateClass();
    jest.clearAllMocks();
  });

  it('should have correct metadata', () => {
    expect(node.label).toBe('Attesta Approval');
    expect(node.name).toBe('attestaGate');
    expect(node.type).toBe('Tool');
    expect(node.category).toBe('Tools');
    expect(node.baseClasses).toContain('Tool');
  });

  it('should create a DynamicTool on init', async () => {
    MockAttesta.mockImplementation(() => ({
      evaluate: jest.fn().mockResolvedValue({
        verdict: Verdict.APPROVED,
        riskAssessment: { score: 0.1, level: 'low' },
      }),
    }) as any);

    const tool = await node.init({
      inputs: {
        functionName: 'test_action',
        riskLevel: 'auto',
        riskHints: '{}',
        toolDescription: 'A test tool',
      },
    });

    expect(tool).toBeInstanceOf(DynamicTool);
    expect(tool.name).toBe('test_action');
    expect(tool.description).toBe('A test tool');
  });

  it('should return approved result', async () => {
    MockAttesta.mockImplementation(() => ({
      evaluate: jest.fn().mockResolvedValue({
        verdict: Verdict.APPROVED,
        riskAssessment: { score: 0.1, level: 'low' },
        auditEntryId: 'audit-123',
      }),
    }) as any);

    const tool = await node.init({
      inputs: {
        functionName: 'send_email',
        riskLevel: 'auto',
        riskHints: '{}',
        toolDescription: 'Send email',
      },
    });

    const result = JSON.parse(await tool.func('{"to": "user@example.com"}'));
    expect(result.status).toBe('approved');
    expect(result.auditEntryId).toBe('audit-123');
  });

  it('should return denied result', async () => {
    MockAttesta.mockImplementation(() => ({
      evaluate: jest.fn().mockResolvedValue({
        verdict: Verdict.DENIED,
        riskAssessment: { score: 0.9, level: 'critical' },
      }),
    }) as any);

    const tool = await node.init({
      inputs: {
        functionName: 'delete_all',
        riskLevel: 'critical',
        riskHints: '{"destructive": true}',
        toolDescription: 'Delete all records',
      },
    });

    const result = JSON.parse(await tool.func('{}'));
    expect(result.status).toBe('denied');
    expect(result.riskLevel).toBe('critical');
  });

  it('should handle invalid riskHints JSON gracefully', async () => {
    MockAttesta.mockImplementation(() => ({
      evaluate: jest.fn().mockResolvedValue({
        verdict: Verdict.APPROVED,
        riskAssessment: { score: 0.2, level: 'low' },
        auditEntryId: 'audit-456',
      }),
    }) as any);

    const tool = await node.init({
      inputs: {
        functionName: 'safe_action',
        riskLevel: 'auto',
        riskHints: 'not valid json{{{',
        toolDescription: 'A safe action',
      },
    });

    const result = JSON.parse(await tool.func('{"key": "value"}'));
    expect(result.status).toBe('approved');
  });
});
