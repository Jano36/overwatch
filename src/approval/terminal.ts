import * as readline from 'readline';
import type { ApprovalHandler, ApprovalRequest, ApprovalResponse } from './types.js';

export class TerminalApprovalHandler implements ApprovalHandler {
  private rl: readline.Interface | null = null;
  private timeout: number;

  constructor(timeout: number = 60000) {
    this.timeout = timeout;
  }

  async requestApproval(request: ApprovalRequest): Promise<ApprovalResponse> {
    this.rl = readline.createInterface({
      input: process.stdin,
      output: process.stderr,
      terminal: true,
    });

    return new Promise((resolve) => {
      const timeoutId = setTimeout(() => {
        this.cleanup();
        resolve({ approved: false, reason: 'Approval timeout' });
      }, this.timeout);

      this.printRequest(request);
      this.prompt(resolve, timeoutId);
    });
  }

  private printRequest(request: ApprovalRequest): void {
    const riskColors: Record<string, string> = {
      safe: '\x1b[32m',      // Green
      read: '\x1b[36m',      // Cyan
      write: '\x1b[33m',     // Yellow
      destructive: '\x1b[31m', // Red
      dangerous: '\x1b[35m',  // Magenta
    };
    const reset = '\x1b[0m';
    const bold = '\x1b[1m';
    const dim = '\x1b[2m';

    const color = riskColors[request.riskLevel] || '';

    console.error('\n' + '─'.repeat(50));
    console.error(`${bold}🔒 Overwatch: Approval Required${reset}`);
    console.error('─'.repeat(50));

    if (request.server) {
      console.error(`${dim}Server:${reset}  ${request.server}`);
    }
    console.error(`${dim}Tool:${reset}    ${request.tool}`);
    console.error(`${dim}Risk:${reset}    ${color}${request.riskLevel.toUpperCase()}${reset}`);

    if (request.args && Object.keys(request.args).length > 0) {
      console.error(`${dim}Args:${reset}`);
      for (const [key, value] of Object.entries(request.args)) {
        const valueStr = typeof value === 'string' ? value : JSON.stringify(value);
        const truncated = valueStr.length > 60 ? valueStr.slice(0, 57) + '...' : valueStr;
        console.error(`  ${key}: ${truncated}`);
      }
    }

    if (request.reason) {
      console.error(`${dim}Reason:${reset}  ${request.reason}`);
    }

    console.error('─'.repeat(50));
    console.error(`${dim}Options:${reset}`);
    console.error(`  ${bold}[A]${reset}llow once`);
    console.error(`  ${bold}[5]${reset} Allow for 5 minutes`);
    console.error(`  ${bold}[S]${reset}ession (until restart)`);
    console.error(`  ${bold}[D]${reset}eny`);
    console.error('─'.repeat(50));
  }

  private prompt(
    resolve: (response: ApprovalResponse) => void,
    timeoutId: NodeJS.Timeout
  ): void {
    this.rl?.question('Choice [A/5/S/D]: ', (answer) => {
      clearTimeout(timeoutId);

      const response = this.parseAnswer(answer);
      this.cleanup();
      resolve(response);
    });
  }

  private parseAnswer(answer: string): ApprovalResponse {
    const normalized = answer.trim().toLowerCase();

    switch (normalized) {
      case 'a':
      case 'allow':
      case 'y':
      case 'yes':
        return { approved: true, sessionDuration: 'once' };

      case '5':
      case '5m':
      case '5min':
        return { approved: true, sessionDuration: '5min' };

      case '15':
      case '15m':
      case '15min':
        return { approved: true, sessionDuration: '15min' };

      case 's':
      case 'session':
        return { approved: true, sessionDuration: 'session' };

      case 'd':
      case 'deny':
      case 'n':
      case 'no':
      default:
        return { approved: false, reason: 'User denied' };
    }
  }

  private cleanup(): void {
    if (this.rl) {
      this.rl.close();
      this.rl = null;
    }
  }

  async close(): Promise<void> {
    this.cleanup();
  }
}

export function createTerminalApprovalHandler(timeout?: number): TerminalApprovalHandler {
  return new TerminalApprovalHandler(timeout);
}
