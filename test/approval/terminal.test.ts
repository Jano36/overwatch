import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { TerminalApprovalHandler, createTerminalApprovalHandler } from '../../src/approval/terminal.js';
import type { ApprovalRequest } from '../../src/approval/types.js';
import * as readline from 'readline';

// Mock readline
vi.mock('readline', () => ({
  createInterface: vi.fn(() => ({
    question: vi.fn(),
    close: vi.fn(),
  })),
}));

describe('TerminalApprovalHandler', () => {
  let handler: TerminalApprovalHandler;
  let mockRl: {
    question: ReturnType<typeof vi.fn>;
    close: ReturnType<typeof vi.fn>;
  };

  beforeEach(() => {
    handler = new TerminalApprovalHandler(5000);
    mockRl = {
      question: vi.fn(),
      close: vi.fn(),
    };
    vi.mocked(readline.createInterface).mockReturnValue(mockRl as unknown as readline.Interface);
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  function createRequest(overrides: Partial<ApprovalRequest> = {}): ApprovalRequest {
    return {
      id: 'test-request-1',
      tool: 'read_file',
      riskLevel: 'read',
      timestamp: new Date(),
      ...overrides,
    };
  }

  describe('requestApproval', () => {
    it('creates readline interface and prompts user', async () => {
      const request = createRequest();

      // Simulate user answering 'a'
      mockRl.question.mockImplementation((prompt: string, callback: (answer: string) => void) => {
        callback('a');
      });

      const response = await handler.requestApproval(request);

      expect(readline.createInterface).toHaveBeenCalled();
      expect(mockRl.question).toHaveBeenCalled();
      expect(response.approved).toBe(true);
    });

    it('closes readline after getting response', async () => {
      const request = createRequest();

      mockRl.question.mockImplementation((prompt: string, callback: (answer: string) => void) => {
        callback('a');
      });

      await handler.requestApproval(request);

      expect(mockRl.close).toHaveBeenCalled();
    });
  });

  describe('parseAnswer', () => {
    const testCases = [
      // Allow once
      { input: 'a', expected: { approved: true, sessionDuration: 'once' } },
      { input: 'A', expected: { approved: true, sessionDuration: 'once' } },
      { input: 'allow', expected: { approved: true, sessionDuration: 'once' } },
      { input: 'y', expected: { approved: true, sessionDuration: 'once' } },
      { input: 'yes', expected: { approved: true, sessionDuration: 'once' } },

      // 5 minutes
      { input: '5', expected: { approved: true, sessionDuration: '5min' } },
      { input: '5m', expected: { approved: true, sessionDuration: '5min' } },
      { input: '5min', expected: { approved: true, sessionDuration: '5min' } },

      // 15 minutes
      { input: '15', expected: { approved: true, sessionDuration: '15min' } },
      { input: '15m', expected: { approved: true, sessionDuration: '15min' } },
      { input: '15min', expected: { approved: true, sessionDuration: '15min' } },

      // Session
      { input: 's', expected: { approved: true, sessionDuration: 'session' } },
      { input: 'S', expected: { approved: true, sessionDuration: 'session' } },
      { input: 'session', expected: { approved: true, sessionDuration: 'session' } },

      // Deny
      { input: 'd', expected: { approved: false, reason: 'User denied' } },
      { input: 'D', expected: { approved: false, reason: 'User denied' } },
      { input: 'deny', expected: { approved: false, reason: 'User denied' } },
      { input: 'n', expected: { approved: false, reason: 'User denied' } },
      { input: 'no', expected: { approved: false, reason: 'User denied' } },

      // Unknown defaults to deny
      { input: 'xyz', expected: { approved: false, reason: 'User denied' } },
      { input: '', expected: { approved: false, reason: 'User denied' } },
    ];

    for (const { input, expected } of testCases) {
      it(`parses "${input}" correctly`, async () => {
        const request = createRequest();

        mockRl.question.mockImplementation((prompt: string, callback: (answer: string) => void) => {
          callback(input);
        });

        const response = await handler.requestApproval(request);

        expect(response.approved).toBe(expected.approved);
        if (expected.sessionDuration) {
          expect(response.sessionDuration).toBe(expected.sessionDuration);
        }
        if (expected.reason) {
          expect(response.reason).toBe(expected.reason);
        }
      });
    }
  });

  describe('timeout', () => {
    it('returns denied response on timeout', async () => {
      vi.useFakeTimers();

      const request = createRequest();

      // Never call the callback to simulate timeout
      mockRl.question.mockImplementation(() => {});

      const responsePromise = handler.requestApproval(request);

      // Advance time past timeout
      vi.advanceTimersByTime(6000);

      const response = await responsePromise;

      expect(response.approved).toBe(false);
      expect(response.reason).toBe('Approval timeout');

      vi.useRealTimers();
    });
  });

  describe('close', () => {
    it('closes the handler', async () => {
      await handler.close();
      // Should not throw
      expect(true).toBe(true);
    });
  });

  describe('createTerminalApprovalHandler', () => {
    it('creates a new handler with default timeout', () => {
      const newHandler = createTerminalApprovalHandler();
      expect(newHandler).toBeInstanceOf(TerminalApprovalHandler);
    });

    it('creates a new handler with custom timeout', () => {
      const newHandler = createTerminalApprovalHandler(30000);
      expect(newHandler).toBeInstanceOf(TerminalApprovalHandler);
    });
  });
});

describe('TerminalApprovalHandler output', () => {
  let handler: TerminalApprovalHandler;
  let mockRl: {
    question: ReturnType<typeof vi.fn>;
    close: ReturnType<typeof vi.fn>;
  };
  let consoleErrorSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    handler = new TerminalApprovalHandler(5000);
    mockRl = {
      question: vi.fn(),
      close: vi.fn(),
    };
    vi.mocked(readline.createInterface).mockReturnValue(mockRl as unknown as readline.Interface);
    consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    vi.clearAllMocks();
    consoleErrorSpy.mockRestore();
  });

  it('prints request details to stderr', async () => {
    const request: ApprovalRequest = {
      id: 'test-1',
      server: 'filesystem',
      tool: 'write_file',
      args: { path: '/test/file.txt', content: 'Hello World' },
      riskLevel: 'write',
      reason: 'Writing to file',
      timestamp: new Date(),
    };

    mockRl.question.mockImplementation((prompt: string, callback: (answer: string) => void) => {
      callback('a');
    });

    await handler.requestApproval(request);

    // Check that output was printed
    expect(consoleErrorSpy).toHaveBeenCalled();

    // Check for key content in output
    const allOutput = consoleErrorSpy.mock.calls.map(call => call[0]).join('\n');
    expect(allOutput).toContain('filesystem');
    expect(allOutput).toContain('write_file');
    expect(allOutput).toContain('WRITE');
    expect(allOutput).toContain('path');
    expect(allOutput).toContain('/test/file.txt');
  });

  it('truncates long argument values', async () => {
    const longValue = 'x'.repeat(100);
    const request: ApprovalRequest = {
      id: 'test-2',
      tool: 'test_tool',
      args: { longArg: longValue },
      riskLevel: 'safe',
      timestamp: new Date(),
    };

    mockRl.question.mockImplementation((prompt: string, callback: (answer: string) => void) => {
      callback('a');
    });

    await handler.requestApproval(request);

    const allOutput = consoleErrorSpy.mock.calls.map(call => call[0]).join('\n');
    expect(allOutput).toContain('...');
    expect(allOutput).not.toContain('x'.repeat(100));
  });

  it('uses color for different risk levels', async () => {
    const riskLevels = ['safe', 'read', 'write', 'destructive', 'dangerous'] as const;

    for (const riskLevel of riskLevels) {
      consoleErrorSpy.mockClear();

      const request: ApprovalRequest = {
        id: `test-${riskLevel}`,
        tool: 'test_tool',
        riskLevel,
        timestamp: new Date(),
      };

      mockRl.question.mockImplementation((prompt: string, callback: (answer: string) => void) => {
        callback('a');
      });

      await handler.requestApproval(request);

      const allOutput = consoleErrorSpy.mock.calls.map(call => call[0]).join('\n');
      expect(allOutput).toContain(riskLevel.toUpperCase());
    }
  });
});
