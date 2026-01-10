#!/usr/bin/env node

import { Command } from 'commander';
import { wrapCommand } from './commands/wrap.js';
import { startCommand } from './commands/start.js';
import { sessionsCommand } from './commands/sessions.js';
import { logsCommand } from './commands/logs.js';
import { statsCommand } from './commands/stats.js';
import { initCommand } from './commands/init.js';
import { policiesCommand } from './commands/policies.js';
import { doctorCommand } from './commands/doctor.js';

const program = new Command();

program
  .name('overwatch')
  .description('MCP Security Proxy with Tool Shadowing Detection')
  .version('0.1.0');

// Core protection commands
program.addCommand(wrapCommand);
program.addCommand(startCommand);

// Session management
program.addCommand(sessionsCommand);

// Audit & compliance
program.addCommand(logsCommand);
program.addCommand(statsCommand);

// Configuration
program.addCommand(initCommand);
program.addCommand(policiesCommand);
program.addCommand(doctorCommand);

program.parse();
