import { Command } from 'commander';
import { loadConfig, validateConfig } from '../../config/loader.js';
import * as fs from 'fs';

export const policiesCommand = new Command('policies')
  .description('Manage security policies');

policiesCommand
  .command('list')
  .alias('ls')
  .description('List active policies')
  .option('-c, --config <path>', 'Path to configuration file')
  .option('--json', 'Output as JSON')
  .action(async (options) => {
    try {
      const config = await loadConfig(options.config);

      if (options.json) {
        console.log(JSON.stringify(config, null, 2));
        return;
      }

      console.log('\nOverwatch Policies\n');

      // Global defaults
      console.log('Global Defaults');
      console.log('───────────────────────────────────────');
      console.log(`  Default action:     ${config.defaults?.action || 'prompt'}`);
      console.log(`  Timeout:            ${config.defaults?.timeout || 60000}ms`);
      console.log(`  Session duration:   ${config.defaults?.sessionDuration || 300000}ms`);
      console.log();

      // Server policies
      if (config.servers) {
        console.log('Server Policies');
        console.log('───────────────────────────────────────');

        for (const [name, server] of Object.entries(config.servers)) {
          console.log(`\n  ${name}`);
          console.log(`    Command: ${server.command} ${(server.args || []).join(' ')}`);

          if (server.policies && server.policies.length > 0) {
            for (const policy of server.policies) {
              const tools = Array.isArray(policy.tools) ? policy.tools.join(', ') : policy.tools;
              console.log(`    Policy: tools=[${tools}] action=${policy.action || 'smart'}`);
            }
          } else {
            console.log('    Policies: (using defaults)');
          }
        }
      } else {
        console.log('No servers configured');
      }

      console.log();

    } catch (error) {
      console.error('Failed to list policies:', error);
      process.exit(1);
    }
  });

policiesCommand
  .command('validate')
  .description('Validate configuration file')
  .option('-c, --config <path>', 'Path to configuration file')
  .action(async (options) => {
    try {
      const configPath = options.config || findConfigPath();

      if (!configPath) {
        console.error('No configuration file found');
        console.error('Create one with: overwatch init');
        process.exit(1);
      }

      console.log(`Validating: ${configPath}\n`);

      const content = fs.readFileSync(configPath, 'utf-8');
      const result = validateConfig(content);

      if (result.valid) {
        console.log('✓ Configuration is valid\n');

        // Show summary
        if (result.config) {
          const serverCount = result.config.servers ? Object.keys(result.config.servers).length : 0;
          console.log(`  Servers: ${serverCount}`);
          console.log(`  Tool shadowing: ${result.config.toolShadowing?.enabled !== false ? 'enabled' : 'disabled'}`);
          console.log(`  Audit logging: ${result.config.audit?.enabled !== false ? 'enabled' : 'disabled'}`);
        }
      } else {
        console.error('✗ Configuration is invalid\n');

        for (const error of result.errors || []) {
          console.error(`  • ${error}`);
        }

        process.exit(1);
      }

    } catch (error) {
      console.error('Validation failed:', error);
      process.exit(1);
    }
  });

// Default action (list)
policiesCommand.action(async () => {
  await policiesCommand.commands.find(c => c.name() === 'list')?.parseAsync([]);
});

function findConfigPath(): string | undefined {
  const candidates = [
    'overwatch.yaml',
    'overwatch.yml',
    '.overwatch.yaml',
    '.overwatch.yml',
  ];

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }

  return undefined;
}
