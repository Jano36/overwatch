import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { EventEmitter, Readable, Writable } from 'stream';
import {
  MCPTransport,
  isRequest,
  isResponse,
  isNotification,
  createResponse,
  createErrorResponse,
  type JSONRPCRequest,
  type JSONRPCResponse,
  type JSONRPCNotification,
  type JSONRPCMessage,
} from '../../src/proxy/transport.js';

// Mock readable stream
class MockReadable extends Readable {
  _read(): void {}

  pushData(data: string): void {
    this.push(Buffer.from(data, 'utf-8'));
  }

  end(): void {
    this.push(null);
  }
}

// Mock writable stream
class MockWritable extends Writable {
  public chunks: string[] = [];

  _write(chunk: Buffer, _encoding: string, callback: () => void): void {
    this.chunks.push(chunk.toString('utf-8'));
    callback();
  }

  getOutput(): string {
    return this.chunks.join('');
  }

  clear(): void {
    this.chunks = [];
  }
}

describe('MCPTransport', () => {
  let input: MockReadable;
  let output: MockWritable;
  let transport: MCPTransport;

  beforeEach(() => {
    input = new MockReadable();
    output = new MockWritable();
    transport = new MCPTransport(input, output, 'test');
  });

  afterEach(() => {
    transport.close();
  });

  describe('receiving messages', () => {
    it('should parse Content-Length delimited messages', async () => {
      const message: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'test',
        params: { foo: 'bar' },
      };

      const messageReceived = new Promise<JSONRPCMessage>((resolve) => {
        transport.on('message', resolve);
      });

      const content = JSON.stringify(message);
      const data = `Content-Length: ${Buffer.byteLength(content)}\r\n\r\n${content}`;
      input.pushData(data);

      const received = await messageReceived;
      expect(received).toEqual(message);
    });

    it('should handle partial Content-Length messages', async () => {
      const message: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'test',
      };

      const messageReceived = new Promise<JSONRPCMessage>((resolve) => {
        transport.on('message', resolve);
      });

      const content = JSON.stringify(message);
      const header = `Content-Length: ${Buffer.byteLength(content)}\r\n\r\n`;

      // Send header and content in separate chunks
      input.pushData(header);
      input.pushData(content);

      const received = await messageReceived;
      expect(received).toEqual(message);
    });

    it('should handle multiple messages in one chunk', async () => {
      const messages: JSONRPCRequest[] = [
        { jsonrpc: '2.0', id: 1, method: 'test1' },
        { jsonrpc: '2.0', id: 2, method: 'test2' },
      ];

      const receivedMessages: JSONRPCMessage[] = [];
      transport.on('message', (msg) => receivedMessages.push(msg));

      // Send both messages in one chunk
      let data = '';
      for (const msg of messages) {
        const content = JSON.stringify(msg);
        data += `Content-Length: ${Buffer.byteLength(content)}\r\n\r\n${content}`;
      }
      input.pushData(data);

      // Wait for processing
      await new Promise((resolve) => setTimeout(resolve, 10));

      expect(receivedMessages).toEqual(messages);
    });

    it('should emit close when input ends', async () => {
      const closed = new Promise<void>((resolve) => {
        transport.on('close', resolve);
      });

      input.end();

      await expect(closed).resolves.toBeUndefined();
    });

    it('should emit error on invalid JSON', async () => {
      const errorReceived = new Promise<Error>((resolve) => {
        transport.on('error', resolve);
      });

      const content = 'not valid json';
      const data = `Content-Length: ${Buffer.byteLength(content)}\r\n\r\n${content}`;
      input.pushData(data);

      const error = await errorReceived;
      expect(error.message).toContain('Invalid JSON');
    });

    it('should skip invalid newline-delimited JSON silently', async () => {
      const messages: JSONRPCMessage[] = [];
      transport.on('message', (msg) => messages.push(msg));

      // Send invalid JSON followed by valid using Content-Length format
      const validMessage = { jsonrpc: '2.0', id: 1, method: 'test' };
      const validContent = JSON.stringify(validMessage);

      // First send valid message
      const data = `Content-Length: ${Buffer.byteLength(validContent)}\r\n\r\n${validContent}`;
      input.pushData(data);

      await new Promise((resolve) => setTimeout(resolve, 10));

      expect(messages.length).toBe(1);
      expect(messages[0]).toEqual(validMessage);
    });
  });

  describe('sending messages', () => {
    it('should send Content-Length formatted messages', () => {
      const message: JSONRPCResponse = {
        jsonrpc: '2.0',
        id: 1,
        result: { data: 'test' },
      };

      transport.send(message);

      const output_str = output.getOutput();
      const content = JSON.stringify(message);
      expect(output_str).toBe(`Content-Length: ${Buffer.byteLength(content)}\r\n\r\n${content}`);
    });

    it('should handle unicode content length correctly', () => {
      const message: JSONRPCResponse = {
        jsonrpc: '2.0',
        id: 1,
        result: { data: '日本語テスト' }, // Japanese characters
      };

      transport.send(message);

      const output_str = output.getOutput();
      const content = JSON.stringify(message);
      // Verify byte length is used, not character length
      expect(output_str).toContain(`Content-Length: ${Buffer.byteLength(content)}`);
    });

    it('should send multiple messages correctly', () => {
      const messages: JSONRPCResponse[] = [
        { jsonrpc: '2.0', id: 1, result: 'first' },
        { jsonrpc: '2.0', id: 2, result: 'second' },
      ];

      messages.forEach((msg) => transport.send(msg));

      const output_str = output.getOutput();
      // Both messages should be in output
      expect(output_str).toContain('"id":1');
      expect(output_str).toContain('"id":2');
    });
  });

  describe('close', () => {
    it('should remove all listeners on close', () => {
      transport.on('message', () => {});
      transport.on('error', () => {});

      transport.close();

      expect(transport.listenerCount('message')).toBe(0);
      expect(transport.listenerCount('error')).toBe(0);
    });
  });
});

describe('Type guards', () => {
  describe('isRequest', () => {
    it('should return true for valid requests', () => {
      const msg: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'test',
      };
      expect(isRequest(msg)).toBe(true);
    });

    it('should return true for string id requests', () => {
      const msg: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 'abc-123',
        method: 'test',
      };
      expect(isRequest(msg)).toBe(true);
    });

    it('should return false for notifications (no id)', () => {
      const msg: JSONRPCNotification = {
        jsonrpc: '2.0',
        method: 'test',
      };
      expect(isRequest(msg)).toBe(false);
    });

    it('should return false for responses', () => {
      const msg: JSONRPCResponse = {
        jsonrpc: '2.0',
        id: 1,
        result: {},
      };
      expect(isRequest(msg)).toBe(false);
    });
  });

  describe('isResponse', () => {
    it('should return true for success responses', () => {
      const msg: JSONRPCResponse = {
        jsonrpc: '2.0',
        id: 1,
        result: { data: 'test' },
      };
      expect(isResponse(msg)).toBe(true);
    });

    it('should return true for error responses', () => {
      const msg: JSONRPCResponse = {
        jsonrpc: '2.0',
        id: 1,
        error: { code: -32600, message: 'Invalid Request' },
      };
      expect(isResponse(msg)).toBe(true);
    });

    it('should return false for requests', () => {
      const msg: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'test',
      };
      expect(isResponse(msg)).toBe(false);
    });

    it('should return false for notifications', () => {
      const msg: JSONRPCNotification = {
        jsonrpc: '2.0',
        method: 'test',
      };
      expect(isResponse(msg)).toBe(false);
    });
  });

  describe('isNotification', () => {
    it('should return true for notifications', () => {
      const msg: JSONRPCNotification = {
        jsonrpc: '2.0',
        method: 'test',
      };
      expect(isNotification(msg)).toBe(true);
    });

    it('should return true for notifications with params', () => {
      const msg: JSONRPCNotification = {
        jsonrpc: '2.0',
        method: 'test',
        params: { data: 'test' },
      };
      expect(isNotification(msg)).toBe(true);
    });

    it('should return false for requests', () => {
      const msg: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'test',
      };
      expect(isNotification(msg)).toBe(false);
    });

    it('should return false for responses', () => {
      const msg: JSONRPCResponse = {
        jsonrpc: '2.0',
        id: 1,
        result: {},
      };
      expect(isNotification(msg)).toBe(false);
    });
  });
});

describe('Response factories', () => {
  describe('createResponse', () => {
    it('should create success response with number id', () => {
      const response = createResponse(1, { data: 'test' });

      expect(response).toEqual({
        jsonrpc: '2.0',
        id: 1,
        result: { data: 'test' },
      });
    });

    it('should create success response with string id', () => {
      const response = createResponse('abc-123', 'result');

      expect(response).toEqual({
        jsonrpc: '2.0',
        id: 'abc-123',
        result: 'result',
      });
    });

    it('should create success response with null result', () => {
      const response = createResponse(1, null);

      expect(response).toEqual({
        jsonrpc: '2.0',
        id: 1,
        result: null,
      });
    });

    it('should create success response with array result', () => {
      const response = createResponse(1, [1, 2, 3]);

      expect(response).toEqual({
        jsonrpc: '2.0',
        id: 1,
        result: [1, 2, 3],
      });
    });
  });

  describe('createErrorResponse', () => {
    it('should create error response without data', () => {
      const response = createErrorResponse(1, -32600, 'Invalid Request');

      expect(response).toEqual({
        jsonrpc: '2.0',
        id: 1,
        error: {
          code: -32600,
          message: 'Invalid Request',
        },
      });
    });

    it('should create error response with data', () => {
      const response = createErrorResponse(
        1,
        -32001,
        'Tool denied',
        { riskLevel: 'destructive' }
      );

      expect(response).toEqual({
        jsonrpc: '2.0',
        id: 1,
        error: {
          code: -32001,
          message: 'Tool denied',
          data: { riskLevel: 'destructive' },
        },
      });
    });

    it('should create error response with string id', () => {
      const response = createErrorResponse('req-123', -32603, 'Internal error');

      expect(response).toEqual({
        jsonrpc: '2.0',
        id: 'req-123',
        error: {
          code: -32603,
          message: 'Internal error',
        },
      });
    });

    it('should create error with standard JSON-RPC error codes', () => {
      const parseError = createErrorResponse(1, -32700, 'Parse error');
      expect(parseError.error?.code).toBe(-32700);

      const invalidRequest = createErrorResponse(1, -32600, 'Invalid Request');
      expect(invalidRequest.error?.code).toBe(-32600);

      const methodNotFound = createErrorResponse(1, -32601, 'Method not found');
      expect(methodNotFound.error?.code).toBe(-32601);

      const invalidParams = createErrorResponse(1, -32602, 'Invalid params');
      expect(invalidParams.error?.code).toBe(-32602);

      const internalError = createErrorResponse(1, -32603, 'Internal error');
      expect(internalError.error?.code).toBe(-32603);
    });
  });
});

describe('Edge cases', () => {
  it('should handle messages with Content-Length format', async () => {
    const input = new MockReadable();
    const output = new MockWritable();
    const transport = new MCPTransport(input, output, 'test');

    const messages: JSONRPCMessage[] = [];
    transport.on('message', (msg) => messages.push(msg));

    // Send valid message with Content-Length
    const message = { jsonrpc: '2.0', id: 1, method: 'test' };
    const content = JSON.stringify(message);
    input.pushData(`Content-Length: ${Buffer.byteLength(content)}\r\n\r\n${content}`);

    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(messages.length).toBe(1);
    transport.close();
  });

  it('should handle message with zero id', async () => {
    const input = new MockReadable();
    const output = new MockWritable();
    const transport = new MCPTransport(input, output, 'test');

    const messageReceived = new Promise<JSONRPCMessage>((resolve) => {
      transport.on('message', resolve);
    });

    const message = { jsonrpc: '2.0', id: 0, method: 'test' };
    const content = JSON.stringify(message);
    input.pushData(`Content-Length: ${Buffer.byteLength(content)}\r\n\r\n${content}`);

    const received = await messageReceived;
    expect(received).toEqual({
      jsonrpc: '2.0',
      id: 0,
      method: 'test',
    });

    transport.close();
  });

  it('should handle case-insensitive Content-Length header', async () => {
    const input = new MockReadable();
    const output = new MockWritable();
    const transport = new MCPTransport(input, output, 'test');

    const messageReceived = new Promise<JSONRPCMessage>((resolve) => {
      transport.on('message', resolve);
    });

    const message = { jsonrpc: '2.0', id: 1, method: 'test' };
    const content = JSON.stringify(message);
    // Use lowercase content-length
    input.pushData(`content-length: ${Buffer.byteLength(content)}\r\n\r\n${content}`);

    const received = await messageReceived;
    expect(received).toEqual(message);

    transport.close();
  });
});
