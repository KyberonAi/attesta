import { INode, INodeData, INodeParams } from 'flowise-components';
import { DynamicTool } from '@langchain/core/tools';
import { Attesta, createActionContext, Verdict, RiskLevel } from '@attesta/core';
import type { ApprovalResult } from '@attesta/core';

class AttestaGate implements INode {
  label: string;
  name: string;
  version: number;
  type: string;
  icon: string;
  category: string;
  description: string;
  baseClasses: string[];
  inputs: INodeParams[];

  constructor() {
    this.label = 'Attesta Approval';
    this.name = 'attestaGate';
    this.version = 1.0;
    this.type = 'Tool';
    this.icon = 'attesta.svg';
    this.category = 'Tools';
    this.description = 'Human-in-the-loop approval for AI agent actions';
    this.baseClasses = ['Tool'];
    this.inputs = [
      {
        label: 'Function Name',
        name: 'functionName',
        type: 'string',
        placeholder: 'e.g. send_email, delete_record',
        description: 'Name of the action being gated',
      },
      {
        label: 'Risk Level',
        name: 'riskLevel',
        type: 'options',
        options: [
          { label: 'Auto (Score-based)', name: 'auto' },
          { label: 'Low', name: 'low' },
          { label: 'Medium', name: 'medium' },
          { label: 'High', name: 'high' },
          { label: 'Critical', name: 'critical' },
        ],
        default: 'auto',
        description: 'Risk level override. "Auto" uses the built-in risk scorer.',
      },
      {
        label: 'Risk Hints',
        name: 'riskHints',
        type: 'json',
        optional: true,
        additionalParams: true,
        default: '{}',
        description: 'JSON object of risk hints (e.g. {"destructive": true, "pii": true})',
      },
      {
        label: 'Tool Description',
        name: 'toolDescription',
        type: 'string',
        default: 'A gated action that requires approval before execution',
        description: 'Description shown to the LLM for this tool',
      },
    ];
  }

  async init(nodeData: INodeData): Promise<DynamicTool> {
    const functionName = (nodeData.inputs?.functionName as string) || 'gated_action';
    const riskLevelParam = (nodeData.inputs?.riskLevel as string) || 'auto';
    const riskHintsRaw = (nodeData.inputs?.riskHints as string) || '{}';
    const toolDescription = (nodeData.inputs?.toolDescription as string) || 'A gated action that requires approval before execution';

    let riskHints: Record<string, unknown> = {};
    try {
      riskHints = JSON.parse(riskHintsRaw);
    } catch {
      riskHints = {};
    }

    const riskOverride = riskLevelParam !== 'auto'
      ? riskLevelParam as typeof RiskLevel[keyof typeof RiskLevel]
      : undefined;

    const attesta = new Attesta({
      riskOverride,
      riskHints,
    });

    return new DynamicTool({
      name: functionName,
      description: toolDescription,
      func: async (input: string): Promise<string> => {
        let parsedInput: Record<string, unknown> = {};
        try {
          parsedInput = JSON.parse(input);
        } catch {
          parsedInput = { input };
        }

        const ctx = createActionContext({
          functionName,
          args: [],
          kwargs: parsedInput,
          hints: { ...riskHints },
          environment: 'production',
          metadata: { source: 'flowise' },
        });

        const result: ApprovalResult = await attesta.evaluate(ctx);

        if (
          result.verdict === Verdict.DENIED ||
          result.verdict === Verdict.TIMED_OUT ||
          result.verdict === Verdict.ESCALATED
        ) {
          return JSON.stringify({
            status: 'denied',
            verdict: result.verdict,
            riskScore: result.riskAssessment.score,
            riskLevel: result.riskAssessment.level,
            message: `Action "${functionName}" was denied by Attesta (risk: ${result.riskAssessment.level})`,
          });
        }

        return JSON.stringify({
          status: 'approved',
          verdict: result.verdict,
          riskScore: result.riskAssessment.score,
          riskLevel: result.riskAssessment.level,
          auditEntryId: result.auditEntryId,
          input: parsedInput,
        });
      },
    });
  }
}

module.exports = { nodeClass: AttestaGate };
