import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { CircuitBreaker, JSONRPCErrorCodes } from '../../src/proxy/mcp-proxy.js';

describe('CircuitBreaker', () => {
  describe('initial state', () => {
    it('should start in closed state', () => {
      const cb = new CircuitBreaker();
      expect(cb.getState()).toBe('closed');
    });

    it('should allow execution in closed state', () => {
      const cb = new CircuitBreaker();
      expect(cb.canExecute()).toBe(true);
    });

    it('should use default config when not provided', () => {
      const cb = new CircuitBreaker();
      // Verify defaults by testing behavior
      expect(cb.canExecute()).toBe(true);
      expect(cb.getState()).toBe('closed');
    });
  });

  describe('failure handling', () => {
    it('should remain closed below failure threshold', () => {
      const cb = new CircuitBreaker({ failureThreshold: 5 });

      // Record 4 failures (below threshold)
      for (let i = 0; i < 4; i++) {
        cb.recordFailure();
      }

      expect(cb.getState()).toBe('closed');
      expect(cb.canExecute()).toBe(true);
    });

    it('should open after reaching failure threshold', () => {
      const cb = new CircuitBreaker({ failureThreshold: 3 });

      // Record 3 failures (at threshold)
      for (let i = 0; i < 3; i++) {
        cb.recordFailure();
      }

      expect(cb.getState()).toBe('open');
      expect(cb.canExecute()).toBe(false);
    });

    it('should block requests in open state', () => {
      const cb = new CircuitBreaker({ failureThreshold: 1 });

      cb.recordFailure();

      expect(cb.getState()).toBe('open');
      expect(cb.canExecute()).toBe(false);
    });
  });

  describe('success handling', () => {
    it('should reset failure count on success in closed state', () => {
      const cb = new CircuitBreaker({ failureThreshold: 5 });

      // Record some failures
      cb.recordFailure();
      cb.recordFailure();

      // Record success
      cb.recordSuccess();

      // Now record more failures - should need full threshold
      cb.recordFailure();
      cb.recordFailure();
      cb.recordFailure();
      cb.recordFailure();

      // Should still be closed (4 failures, threshold is 5)
      expect(cb.getState()).toBe('closed');
    });
  });

  describe('half-open state', () => {
    it('should transition to half-open after reset timeout', async () => {
      const cb = new CircuitBreaker({
        failureThreshold: 1,
        resetTimeout: 50, // Short timeout for testing
      });

      // Open the circuit
      cb.recordFailure();
      expect(cb.getState()).toBe('open');
      expect(cb.canExecute()).toBe(false);

      // Wait for reset timeout
      await new Promise((resolve) => setTimeout(resolve, 60));

      // Should transition to half-open on next canExecute check
      expect(cb.canExecute()).toBe(true);
      expect(cb.getState()).toBe('half-open');
    });

    it('should return to open on failure in half-open state', async () => {
      const cb = new CircuitBreaker({
        failureThreshold: 1,
        resetTimeout: 50,
      });

      // Open the circuit
      cb.recordFailure();

      // Wait and transition to half-open
      await new Promise((resolve) => setTimeout(resolve, 60));
      cb.canExecute(); // Triggers transition

      expect(cb.getState()).toBe('half-open');

      // Fail again
      cb.recordFailure();

      expect(cb.getState()).toBe('open');
    });

    it('should close after success threshold in half-open state', async () => {
      const cb = new CircuitBreaker({
        failureThreshold: 1,
        resetTimeout: 50,
        successThreshold: 2,
      });

      // Open the circuit
      cb.recordFailure();

      // Wait and transition to half-open
      await new Promise((resolve) => setTimeout(resolve, 60));
      cb.canExecute();

      expect(cb.getState()).toBe('half-open');

      // Record successes
      cb.recordSuccess();
      expect(cb.getState()).toBe('half-open'); // Not yet

      cb.recordSuccess();
      expect(cb.getState()).toBe('closed'); // Now closed
    });

    it('should allow limited requests in half-open state', async () => {
      const cb = new CircuitBreaker({
        failureThreshold: 1,
        resetTimeout: 50,
      });

      // Open the circuit
      cb.recordFailure();

      // Wait and transition to half-open
      await new Promise((resolve) => setTimeout(resolve, 60));
      expect(cb.canExecute()).toBe(true);
      expect(cb.getState()).toBe('half-open');

      // Should continue allowing requests in half-open
      expect(cb.canExecute()).toBe(true);
    });
  });

  describe('reset', () => {
    it('should reset to closed state', () => {
      const cb = new CircuitBreaker({ failureThreshold: 1 });

      // Open the circuit
      cb.recordFailure();
      expect(cb.getState()).toBe('open');

      // Reset
      cb.reset();

      expect(cb.getState()).toBe('closed');
      expect(cb.canExecute()).toBe(true);
    });

    it('should clear failure and success counts', () => {
      const cb = new CircuitBreaker({ failureThreshold: 3 });

      // Record some failures
      cb.recordFailure();
      cb.recordFailure();

      // Reset
      cb.reset();

      // Should need full threshold again
      cb.recordFailure();
      cb.recordFailure();

      expect(cb.getState()).toBe('closed');
    });
  });

  describe('custom configuration', () => {
    it('should use custom failure threshold', () => {
      const cb = new CircuitBreaker({ failureThreshold: 10 });

      // Record 9 failures
      for (let i = 0; i < 9; i++) {
        cb.recordFailure();
      }
      expect(cb.getState()).toBe('closed');

      // 10th failure opens
      cb.recordFailure();
      expect(cb.getState()).toBe('open');
    });

    it('should use custom success threshold', async () => {
      const cb = new CircuitBreaker({
        failureThreshold: 1,
        resetTimeout: 50,
        successThreshold: 3,
      });

      // Open and transition to half-open
      cb.recordFailure();
      await new Promise((resolve) => setTimeout(resolve, 60));
      cb.canExecute();

      // Need 3 successes to close
      cb.recordSuccess();
      cb.recordSuccess();
      expect(cb.getState()).toBe('half-open');

      cb.recordSuccess();
      expect(cb.getState()).toBe('closed');
    });
  });
});

describe('JSONRPCErrorCodes', () => {
  it('should have correct error codes', () => {
    expect(JSONRPCErrorCodes.TOOL_DENIED).toBe(-32001);
    expect(JSONRPCErrorCodes.UPSTREAM_UNAVAILABLE).toBe(-32002);
    expect(JSONRPCErrorCodes.REQUEST_TIMEOUT).toBe(-32003);
    expect(JSONRPCErrorCodes.REQUEST_TOO_LARGE).toBe(-32004);
    expect(JSONRPCErrorCodes.CIRCUIT_BREAKER_OPEN).toBe(-32005);
    expect(JSONRPCErrorCodes.SERVER_SHUTTING_DOWN).toBe(-32006);
  });

  it('should be in valid JSON-RPC server error range', () => {
    // JSON-RPC 2.0 reserves -32000 to -32099 for server errors
    Object.values(JSONRPCErrorCodes).forEach((code) => {
      expect(code).toBeGreaterThanOrEqual(-32099);
      expect(code).toBeLessThanOrEqual(-32000);
    });
  });

  it('should have unique error codes', () => {
    const codes = Object.values(JSONRPCErrorCodes);
    const uniqueCodes = new Set(codes);
    expect(uniqueCodes.size).toBe(codes.length);
  });
});

describe('Circuit breaker state transitions', () => {
  it('should follow correct state machine', async () => {
    const cb = new CircuitBreaker({
      failureThreshold: 2,
      resetTimeout: 50,
      successThreshold: 1,
    });

    // Initial: closed
    expect(cb.getState()).toBe('closed');

    // closed -> closed (success)
    cb.recordSuccess();
    expect(cb.getState()).toBe('closed');

    // closed -> open (failures reach threshold)
    cb.recordFailure();
    cb.recordFailure();
    expect(cb.getState()).toBe('open');

    // open -> half-open (timeout expires)
    await new Promise((resolve) => setTimeout(resolve, 60));
    cb.canExecute();
    expect(cb.getState()).toBe('half-open');

    // half-open -> open (failure)
    cb.recordFailure();
    expect(cb.getState()).toBe('open');

    // Reset for second test path
    cb.reset();
    cb.recordFailure();
    cb.recordFailure();
    expect(cb.getState()).toBe('open');

    await new Promise((resolve) => setTimeout(resolve, 60));
    cb.canExecute();
    expect(cb.getState()).toBe('half-open');

    // half-open -> closed (success)
    cb.recordSuccess();
    expect(cb.getState()).toBe('closed');
  });
});

describe('Edge cases', () => {
  it('should handle rapid state changes', async () => {
    const cb = new CircuitBreaker({
      failureThreshold: 1,
      resetTimeout: 10,
      successThreshold: 1,
    });

    // Rapid failure/recovery cycles
    for (let i = 0; i < 5; i++) {
      cb.recordFailure();
      expect(cb.getState()).toBe('open');

      await new Promise((resolve) => setTimeout(resolve, 15));
      cb.canExecute();
      expect(cb.getState()).toBe('half-open');

      cb.recordSuccess();
      expect(cb.getState()).toBe('closed');
    }
  });

  it('should handle multiple failures after already open', () => {
    const cb = new CircuitBreaker({ failureThreshold: 1 });

    cb.recordFailure();
    expect(cb.getState()).toBe('open');

    // More failures shouldn't change state
    cb.recordFailure();
    cb.recordFailure();
    expect(cb.getState()).toBe('open');
  });

  it('should handle success in closed state with no prior failures', () => {
    const cb = new CircuitBreaker({ failureThreshold: 5 });

    // Multiple successes should not cause issues
    cb.recordSuccess();
    cb.recordSuccess();
    cb.recordSuccess();

    expect(cb.getState()).toBe('closed');
    expect(cb.canExecute()).toBe(true);
  });

  it('should not transition from open if called before timeout', () => {
    const cb = new CircuitBreaker({
      failureThreshold: 1,
      resetTimeout: 1000, // Long timeout
    });

    cb.recordFailure();
    expect(cb.getState()).toBe('open');

    // Immediately check - should stay open
    expect(cb.canExecute()).toBe(false);
    expect(cb.getState()).toBe('open');
  });
});
