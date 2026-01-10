import { Command } from 'commander';
import { TollgateBridge } from '../../proxy/bridge.js';
import { loadConfig } from '../../config/loader.js';
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

export const wrapCommand = new Command('wrap')
  .description('Wrap a single MCP server with security proxy')
  .argument('<command...>', 'The MCP server command to wrap')
  .option('-c, --config <path>', 'Path to configuration file')
  .option('-n, --name <name>', 'Server name', 'wrapped')
  .option('-t, --timeout <ms>', 'Approval timeout in milliseconds', '60000')
  .option('--fail-mode <mode>', 'Fail mode: open, closed, readonly', 'closed')
  .option('--no-audit', 'Disable audit logging')
  .option('--approval <method>', 'Approval method: terminal, webhook', 'terminal')
  .option('--approval-webhook-url <url>', 'Webhook URL for remote approvals')
  .option('--approval-webhook-secret <secret>', 'Secret for HMAC signing webhook payloads')
  .action(async (commandArgs: string[], options) => {
    try {
      const config = await loadConfig(options.config);

      const approvalHandler = createApprovalHandler(options);
      const auditStore = options.audit !== false ? new AuditStore() : undefined;

      const serverConfig = {
        command: commandArgs[0],
        args: commandArgs.slice(1),
      };

      const bridge = new TollgateBridge({
        serverName: options.name,
        serverConfig,
        config,
        approvalHandler,
        failMode: options.failMode,
        onAuditEntry: auditStore ? (entry) => auditStore.save(entry) : undefined,
      });

      // Handle shutdown gracefully
      process.on('SIGINT', async () => {
        await bridge.shutdown();
        await approvalHandler.close();
        auditStore?.close();
        process.exit(0);
      });

      process.on('SIGTERM', async () => {
        await bridge.shutdown();
        await approvalHandler.close();
        auditStore?.close();
        process.exit(0);
      });

      await bridge.start();
    } catch (error) {
      console.error('Failed to start proxy:', error);
      process.exit(1);
    }
  });
