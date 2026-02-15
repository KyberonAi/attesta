export class DynamicTool {
  name: string;
  description: string;
  func: (input: string) => Promise<string>;

  constructor(config: { name: string; description: string; func: (input: string) => Promise<string> }) {
    this.name = config.name;
    this.description = config.description;
    this.func = config.func;
  }

  async invoke(input: any): Promise<string> {
    return this.func(typeof input === 'string' ? input : JSON.stringify(input));
  }
}
