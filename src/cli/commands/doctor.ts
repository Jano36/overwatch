import { Command } from 'commander';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { loadConfig } from '../../config/loader.js';

export const doctorCommand = new Command('doctor')
  .description('Diagnose installation and configuration issues')
  .action(async () => {
    console.log('\nOverwatch Doctor\n');
    console.log('═══════════════════════════════════════════\n');

    let issues = 0;

    // Check Node.js version
    process.stdout.write('Node.js version: ');
    const nodeVersion = process.version;
    const majorVersion = parseInt(nodeVersion.slice(1).split('.')[0], 10);
    if (majorVersion >= 20) {
      console.log(`✓ ${nodeVersion}`);
    } else {
      console.log(`✗ ${nodeVersion} (requires Node.js 20+)`);
      issues++;
    }

    // Check configuration
    process.stdout.write('Configuration: ');
    try {
      const config = await loadConfig();
      const serverCount = config.servers ? Object.keys(config.servers).length : 0;
      console.log(`✓ Found (${serverCount} servers configured)`);
    } catch {
      console.log('⚠ No config found (using defaults)');
    }

    // Check shell hooks
    const homeDir = os.homedir();

    process.stdout.write('Bash hook: ');
    const bashrc = path.join(homeDir, '.bashrc');
    if (fs.existsSync(bashrc)) {
      const content = fs.readFileSync(bashrc, 'utf-8');
      if (content.includes('overwatch check')) {
        console.log('✓ Installed');
      } else {
        console.log('⚠ Not installed (run: overwatch init)');
      }
    } else {
      console.log('- No .bashrc found');
    }

    process.stdout.write('Zsh hook: ');
    const zshrc = path.join(homeDir, '.zshrc');
    if (fs.existsSync(zshrc)) {
      const content = fs.readFileSync(zshrc, 'utf-8');
      if (content.includes('overwatch check')) {
        console.log('✓ Installed');
      } else {
        console.log('⚠ Not installed (run: overwatch init)');
      }
    } else {
      console.log('- No .zshrc found');
    }

    // Check audit database
    process.stdout.write('Audit database: ');
    const auditPath = path.join(homeDir, '.overwatch', 'audit.db');
    if (fs.existsSync(auditPath)) {
      const stats = fs.statSync(auditPath);
      const sizeMB = (stats.size / 1024 / 1024).toFixed(2);
      console.log(`✓ Found (${sizeMB} MB)`);
    } else {
      console.log('- Not created yet (will be created on first use)');
    }

    // Check session database
    process.stdout.write('Session database: ');
    const sessionPath = path.join(homeDir, '.overwatch', 'sessions.db');
    if (fs.existsSync(sessionPath)) {
      console.log('✓ Found');
    } else {
      console.log('- Not created yet');
    }

    // Check data directory permissions
    process.stdout.write('Data directory: ');
    const dataDir = path.join(homeDir, '.overwatch');
    if (fs.existsSync(dataDir)) {
      try {
        fs.accessSync(dataDir, fs.constants.R_OK | fs.constants.W_OK);
        console.log('✓ Writable');
      } catch {
        console.log('✗ Not writable');
        issues++;
      }
    } else {
      console.log('- Will be created on first use');
    }

    // Summary
    console.log('\n═══════════════════════════════════════════');
    if (issues > 0) {
      console.log(`\n✗ Found ${issues} issue(s) that need attention\n`);
      process.exit(1);
    } else {
      console.log('\n✓ All checks passed\n');
    }
  });
