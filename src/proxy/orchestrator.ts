import type { OverwatchConfig } from '../config/types.js';
import type { ApprovalHandler } from '../approval/types.js';
import type { AuditEntry } from '../audit/logger.js';
import { TollgateBridge } from './bridge.js';

export interface OrchestratorOptions {
  config: OverwatchConfig;
  approvalHandler: ApprovalHandler;
  onAuditEntry?: (entry: AuditEntry) => void;
  failMode?: 'open' | 'closed' | 'readonly';
}

export class Orchestrator {
  private bridges: Map<string, TollgateBridge> = new Map();
  private running = false;

  constructor(private options: OrchestratorOptions) {}

  async start(): Promise<void> {
    const { config, approvalHandler, onAuditEntry, failMode } = this.options;

    if (!config.servers || Object.keys(config.servers).length === 0) {
      throw new Error('No servers configured in overwatch.yaml');
    }

    this.running = true;
    console.error(`[Overwatch] Starting orchestrator with ${Object.keys(config.servers).length} server(s)`);

    const startPromises: Promise<void>[] = [];

    for (const [serverName, serverConfig] of Object.entries(config.servers)) {
      console.error(`[Overwatch] Initializing server: ${serverName}`);

      const bridge = new TollgateBridge({
        serverName,
        serverConfig,
        config,
        approvalHandler,
        onAuditEntry,
        failMode,
      });

      this.bridges.set(serverName, bridge);

      // Start in background
      const startPromise = bridge.start().catch((error) => {
        console.error(`[Overwatch] Server ${serverName} failed to start: ${error.message}`);
        this.bridges.delete(serverName);
      });

      startPromises.push(startPromise);
    }

    // Wait a bit for servers to initialize
    await new Promise((resolve) => setTimeout(resolve, 100));

    console.error(`[Overwatch] Orchestrator started with ${this.bridges.size} active server(s)`);
  }

  async startSingle(serverName: string): Promise<void> {
    const { config, approvalHandler, onAuditEntry, failMode } = this.options;

    const serverConfig = config.servers?.[serverName];
    if (!serverConfig) {
      throw new Error(`Server not found: ${serverName}`);
    }

    if (this.bridges.has(serverName)) {
      throw new Error(`Server already running: ${serverName}`);
    }

    this.running = true;
    console.error(`[Overwatch] Starting single server: ${serverName}`);

    const bridge = new TollgateBridge({
      serverName,
      serverConfig,
      config,
      approvalHandler,
      onAuditEntry,
      failMode,
    });

    this.bridges.set(serverName, bridge);

    // Start in foreground for single server mode
    await bridge.start();
  }

  async shutdown(): Promise<void> {
    console.error('[Overwatch] Shutting down orchestrator...');
    this.running = false;

    const shutdownPromises = Array.from(this.bridges.values()).map((bridge) =>
      bridge.shutdown().catch((error) => {
        console.error(`[Overwatch] Error shutting down bridge: ${error.message}`);
      })
    );

    await Promise.all(shutdownPromises);
    this.bridges.clear();

    console.error('[Overwatch] Orchestrator shutdown complete');
  }

  async shutdownServer(serverName: string): Promise<void> {
    const bridge = this.bridges.get(serverName);
    if (!bridge) {
      throw new Error(`Server not running: ${serverName}`);
    }

    await bridge.shutdown();
    this.bridges.delete(serverName);
  }

  getStats(): {
    running: boolean;
    serverCount: number;
    servers: Record<string, ReturnType<TollgateBridge['getStats']>>;
  } {
    const servers: Record<string, ReturnType<TollgateBridge['getStats']>> = {};

    for (const [name, bridge] of this.bridges) {
      servers[name] = bridge.getStats();
    }

    return {
      running: this.running,
      serverCount: this.bridges.size,
      servers,
    };
  }

  listServers(): string[] {
    return Array.from(this.bridges.keys());
  }

  isRunning(): boolean {
    return this.running && this.bridges.size > 0;
  }
}
