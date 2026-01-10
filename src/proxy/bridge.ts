import type { OverwatchConfig, ServerConfig } from '../config/types.js';
import type { ApprovalHandler } from '../approval/types.js';
import type { AuditEntry } from '../audit/logger.js';
import { MCPProxy } from './mcp-proxy.js';

export interface BridgeOptions {
  serverName: string;
  serverConfig: ServerConfig;
  config: OverwatchConfig;
  approvalHandler: ApprovalHandler;
  onAuditEntry?: (entry: AuditEntry) => void;
  failMode?: 'open' | 'closed' | 'readonly';
}

export class TollgateBridge {
  private proxy: MCPProxy | null = null;
  private running = false;

  constructor(private options: BridgeOptions) {}

  async start(): Promise<void> {
    this.running = true;

    console.error(`[Overwatch] Starting bridge for server: ${this.options.serverName}`);
    console.error(`[Overwatch] Command: ${this.options.serverConfig.command} ${(this.options.serverConfig.args || []).join(' ')}`);
    console.error(`[Overwatch] Fail mode: ${this.options.failMode || 'closed'}`);

    this.proxy = new MCPProxy({
      serverName: this.options.serverName,
      serverConfig: this.options.serverConfig,
      overwatchConfig: this.options.config,
      approvalHandler: this.options.approvalHandler,
      onAuditEntry: this.options.onAuditEntry,
      failMode: this.options.failMode,
    });

    // Set up event handlers
    this.proxy.on('started', (info) => {
      console.error(`[Overwatch] Bridge started for ${info.serverName}`);
    });

    this.proxy.on('error', (error) => {
      console.error(`[Overwatch] Bridge error: ${error.message}`);
    });

    this.proxy.on('upstream-exit', ({ code, signal }) => {
      console.error(`[Overwatch] Upstream exited (code: ${code}, signal: ${signal})`);
    });

    this.proxy.on('audit', (entry: AuditEntry) => {
      const emoji = entry.decision === 'allowed' ? '✓' : '✗';
      console.error(
        `[Overwatch] ${emoji} ${entry.tool} (${entry.riskLevel}) - ${entry.decision}`
      );
    });

    this.proxy.on('shutdown', () => {
      console.error(`[Overwatch] Bridge shutdown for ${this.options.serverName}`);
      this.running = false;
    });

    // Start the proxy
    try {
      await this.proxy.start();
    } catch (error) {
      console.error(`[Overwatch] Failed to start proxy: ${error}`);
      this.running = false;
      throw error;
    }

    // Keep running until shutdown
    await new Promise<void>((resolve) => {
      const checkRunning = () => {
        if (!this.running) {
          resolve();
        } else {
          setTimeout(checkRunning, 100);
        }
      };
      checkRunning();
    });
  }

  async shutdown(): Promise<void> {
    console.error('[Overwatch] Shutting down bridge...');
    this.running = false;

    if (this.proxy) {
      await this.proxy.shutdown();
      this.proxy = null;
    }
  }

  getStats(): {
    serverName: string;
    running: boolean;
    proxyStats?: ReturnType<MCPProxy['getStats']>;
  } {
    return {
      serverName: this.options.serverName,
      running: this.running,
      proxyStats: this.proxy?.getStats(),
    };
  }
}
