import { Command } from 'commander';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

export const initCommand = new Command('init')
  .description('Initialize Overwatch configuration')
  .option('-f, --force', 'Overwrite existing configuration')
  .action(async (options) => {
    try {
      const homeDir = os.homedir();
      const configPath = path.join(process.cwd(), 'overwatch.yaml');
      const globalConfigPath = path.join(homeDir, '.overwatch', 'config.yaml');

      const targetPath = fs.existsSync(path.join(process.cwd(), 'package.json'))
        ? configPath
        : globalConfigPath;

      if (fs.existsSync(targetPath) && !options.force) {
        console.log(`Configuration already exists: ${targetPath}`);
        console.log('Use --force to overwrite');
      } else {
        const dir = path.dirname(targetPath);
        if (!fs.existsSync(dir)) {
          fs.mkdirSync(dir, { recursive: true });
        }

        const defaultConfig = generateDefaultConfig();
        fs.writeFileSync(targetPath, defaultConfig);
        console.log(`✓ Created configuration: ${targetPath}`);
      }

      console.log('\n✓ Overwatch initialized');
      console.log('\nNext steps:');
      console.log('  1. Edit overwatch.yaml to configure MCP servers and policies');
      console.log('  2. Run "overwatch wrap <command>" to protect an MCP server');
      console.log('  3. Run "overwatch doctor" to verify installation');

    } catch (error) {
      console.error('Initialization failed:', error);
      process.exit(1);
    }
  });

function generateDefaultConfig(): string {
  return `# Overwatch Configuration
# MCP Security Proxy with Tool Shadowing Detection
# https://github.com/dotsetlabs/overwatch

version: 1

# Global defaults
defaults:
  action: prompt          # prompt, allow, deny
  timeout: 60000          # Approval timeout (ms)
  sessionDuration: 300000 # Default session grant (5 min)

# MCP Server configurations
# servers:
#   filesystem:
#     command: npx
#     args: ["@anthropic/mcp-server-filesystem", "/home/user/projects"]
#     policies:
#       - tools: ["read_file", "list_directory"]
#         action: allow
#       - tools: ["write_file"]
#         action: prompt
#       - tools: ["delete_file"]
#         action: deny
#
#   database:
#     command: npx
#     args: ["@modelcontextprotocol/server-postgres"]
#     env:
#       DATABASE_URL: postgresql://localhost/mydb
#     policies:
#       - tools: ["query", "select"]
#         action: allow
#       - tools: ["insert", "update"]
#         action: prompt
#       - tools: ["drop_*", "delete_*"]
#         action: deny

# Tool shadowing detection
toolShadowing:
  enabled: true
  checkDescriptions: true
  detectMutations: true

# Audit settings
audit:
  enabled: true
  # path: ~/.overwatch/audit.db
  redactPII: true
  # retention: 30d  # Auto-delete entries older than this
`;
}
