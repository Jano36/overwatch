import { Command } from 'commander';
import { loadConfig } from '../../config/loader.js';
import { Orchestrator } from '../../proxy/orchestrator.js';
import { TerminalApprovalHandler } from '../../approval/terminal.js';
import { WebhookApprovalHandler } from '../../approval/webhook.js';
import type { ApprovalHandler } from '../../approval/types.js';
import { AuditStore } from '../../audit/store.js';

function createApprovalHandler(options: {
  approval?: string;
  approvalWebhookUrl?: string;
  approvalWebhookSecret?: string;
  timeout?: string;
}): ApprovalHandler {
  if (options.approval === 'webhook') {
    if (!options.approvalWebhookUrl) {
      throw new Error('--approval-webhook-url is required when using webhook approval');
    }
    return new WebhookApprovalHandler({
      url: options.approvalWebhookUrl,
      secret: options.approvalWebhookSecret,
      timeoutMs: parseInt(options.timeout || '60000', 10),
    });
  }

  return new TerminalApprovalHandler(parseInt(options.timeout || '60000', 10));
}

export const startCommand = new Command('start')
  .description('Start multi-server protection from configuration')
  .option('-c, --config <path>', 'Path to configuration file')
  .option('--fail-mode <mode>', 'Fail mode: open, closed, readonly', 'closed')
  .option('--no-audit', 'Disable audit logging')
  .option('--approval <method>', 'Approval method: terminal, webhook', 'terminal')
  .option('--approval-webhook-url <url>', 'Webhook URL for remote approvals')
  .option('--approval-webhook-secret <secret>', 'Secret for HMAC signing webhook payloads')
  .option('-t, --timeout <ms>', 'Approval timeout in milliseconds', '60000')
  .action(async (options) => {
    try {
      const config = await loadConfig(options.config);

      if (!config.servers || Object.keys(config.servers).length === 0) {
        console.error('No servers configured. Add servers to overwatch.yaml or use "overwatch wrap" for single servers.');
        process.exit(1);
      }

      const approvalHandler = createApprovalHandler(options);
      const auditStore = options.audit !== false ? new AuditStore() : undefined;

      const orchestrator = new Orchestrator({
        config,
        approvalHandler,
        failMode: options.failMode,
        onAuditEntry: auditStore ? (entry) => auditStore.save(entry) : undefined,
      });

      // Handle shutdown gracefully
      process.on('SIGINT', async () => {
        console.log('\nShutting down...');
        await orchestrator.shutdown();
        await approvalHandler.close();
        auditStore?.close();
        process.exit(0);
      });

      process.on('SIGTERM', async () => {
        await orchestrator.shutdown();
        await approvalHandler.close();
        auditStore?.close();
        process.exit(0);
      });

      console.log(`Starting ${Object.keys(config.servers).length} server(s)...`);
      await orchestrator.start();

      // Keep process alive
      await new Promise(() => {});
    } catch (error) {
      console.error('Failed to start:', error);
      process.exit(1);
    }
  });
