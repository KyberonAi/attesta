import type { ICredentialType, INodeProperties } from 'n8n-workflow';

export class AttestaApi implements ICredentialType {
  name = 'attestaApi';
  displayName = 'Attesta';
  documentationUrl = 'https://attesta.dev';
  properties: INodeProperties[] = [
    {
      displayName: 'Risk Threshold',
      name: 'riskThreshold',
      type: 'number',
      default: 0.5,
      description: 'Default risk threshold (0-1). Actions scoring above this are flagged for review.',
      typeOptions: {
        minValue: 0,
        maxValue: 1,
        numberStepSize: 0.1,
      },
    },
  ];
}
