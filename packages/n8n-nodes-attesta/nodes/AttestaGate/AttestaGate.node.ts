import type {
  IExecuteFunctions,
  INodeExecutionData,
  INodeType,
  INodeTypeDescription,
} from 'n8n-workflow';
import { NodeOperationError } from 'n8n-workflow';
import { Attesta, createActionContext, Verdict, RiskLevel } from '@attesta/core';
import type { ApprovalResult } from '@attesta/core';

export class AttestaGate implements INodeType {
  description: INodeTypeDescription = {
    displayName: 'Attesta Approval',
    name: 'attestaGate',
    group: ['transform'],
    version: 1,
    subtitle: '={{$parameter["functionName"]}}',
    description: 'Human-in-the-loop approval for AI agent actions',
    defaults: {
      name: 'Attesta Approval',
    },
    inputs: ['main'],
    outputs: ['main'],
    credentials: [
      {
        name: 'attestaApi',
        required: false,
      },
    ],
    properties: [
      {
        displayName: 'Function Name',
        name: 'functionName',
        type: 'string',
        default: '',
        required: true,
        placeholder: 'e.g. send_email, delete_record',
        description: 'Name of the action being gated',
      },
      {
        displayName: 'Risk Level',
        name: 'riskLevel',
        type: 'options',
        options: [
          { name: 'Auto (Score-based)', value: 'auto' },
          { name: 'Low', value: 'low' },
          { name: 'Medium', value: 'medium' },
          { name: 'High', value: 'high' },
          { name: 'Critical', value: 'critical' },
        ],
        default: 'auto',
        description: 'Risk level override. "Auto" uses the built-in risk scorer.',
      },
      {
        displayName: 'Risk Hints',
        name: 'riskHints',
        type: 'json',
        default: '{}',
        description: 'JSON object of risk hints (e.g. {"destructive": true, "pii": true})',
      },
      {
        displayName: 'On Denied',
        name: 'onDenied',
        type: 'options',
        options: [
          { name: 'Error', value: 'error' },
          { name: 'Passthrough', value: 'passthrough' },
        ],
        default: 'error',
        description:
          'What to do when the action is denied. "Error" stops the workflow; "Passthrough" adds denial metadata and continues.',
      },
    ],
  };

  async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
    const items = this.getInputData();
    const returnData: INodeExecutionData[] = [];

    const functionName = this.getNodeParameter('functionName', 0) as string;
    const riskLevelParam = this.getNodeParameter('riskLevel', 0) as string;
    const riskHintsRaw = this.getNodeParameter('riskHints', 0) as string;
    const onDenied = this.getNodeParameter('onDenied', 0) as string;

    let riskHints: Record<string, unknown> = {};
    try {
      riskHints = JSON.parse(riskHintsRaw || '{}');
    } catch {
      throw new NodeOperationError(this.getNode(), 'Risk Hints must be valid JSON');
    }

    const riskOverride =
      riskLevelParam !== 'auto'
        ? (riskLevelParam as (typeof RiskLevel)[keyof typeof RiskLevel])
        : undefined;

    const attesta = new Attesta({
      riskOverride,
      riskHints,
    });

    for (let i = 0; i < items.length; i++) {
      const item = items[i];
      const ctx = createActionContext({
        functionName,
        args: [],
        kwargs: item.json as Record<string, unknown>,
        hints: { ...riskHints },
        environment: 'production',
        metadata: { source: 'n8n', nodeId: this.getNode().id },
      });

      let result: ApprovalResult;
      try {
        result = await attesta.evaluate(ctx);
      } catch (error) {
        throw new NodeOperationError(
          this.getNode(),
          `Attesta evaluation failed: ${error}`,
          { itemIndex: i },
        );
      }

      if (
        result.verdict === Verdict.DENIED ||
        result.verdict === Verdict.TIMED_OUT ||
        result.verdict === Verdict.ESCALATED
      ) {
        if (onDenied === 'error') {
          throw new NodeOperationError(
            this.getNode(),
            `Action "${functionName}" denied by Attesta (risk: ${result.riskAssessment.level}, score: ${result.riskAssessment.score.toFixed(2)})`,
            { itemIndex: i },
          );
        }
        // passthrough: attach denial metadata
        returnData.push({
          json: {
            ...item.json,
            _attesta: {
              verdict: result.verdict,
              riskScore: result.riskAssessment.score,
              riskLevel: result.riskAssessment.level,
              auditEntryId: result.auditEntryId,
              denied: true,
            },
          },
          pairedItem: { item: i },
        });
      } else {
        // approved
        returnData.push({
          json: {
            ...item.json,
            _attesta: {
              verdict: result.verdict,
              riskScore: result.riskAssessment.score,
              riskLevel: result.riskAssessment.level,
              auditEntryId: result.auditEntryId,
              denied: false,
            },
          },
          pairedItem: { item: i },
        });
      }
    }

    return [returnData];
  }
}
