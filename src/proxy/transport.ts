import { EventEmitter } from 'events';
import type { Readable, Writable } from 'stream';

export interface JSONRPCRequest {
  jsonrpc: '2.0';
  id?: string | number;
  method: string;
  params?: unknown;
}

export interface JSONRPCResponse {
  jsonrpc: '2.0';
  id: string | number;
  result?: unknown;
  error?: JSONRPCError;
}

export interface JSONRPCError {
  code: number;
  message: string;
  data?: unknown;
}

export interface JSONRPCNotification {
  jsonrpc: '2.0';
  method: string;
  params?: unknown;
}

export type JSONRPCMessage = JSONRPCRequest | JSONRPCResponse | JSONRPCNotification;

export class MCPTransport extends EventEmitter {
  private buffer = '';
  private contentLength: number | null = null;

  constructor(
    private input: Readable,
    private output: Writable,
    _name: string = 'transport'
  ) {
    super();
    this.setupInputHandler();
  }

  private setupInputHandler(): void {
    this.input.on('data', (chunk: Buffer) => {
      this.buffer += chunk.toString('utf-8');
      this.processBuffer();
    });

    this.input.on('end', () => {
      this.emit('close');
    });

    this.input.on('error', (error: Error) => {
      this.emit('error', error);
    });
  }

  private processBuffer(): void {
    while (true) {
      if (this.contentLength === null) {
        // Look for Content-Length header
        const headerEnd = this.buffer.indexOf('\r\n\r\n');
        if (headerEnd === -1) return;

        const header = this.buffer.substring(0, headerEnd);
        const match = header.match(/Content-Length: (\d+)/i);
        if (!match) {
          // No Content-Length, try to parse as newline-delimited JSON
          const newlineIndex = this.buffer.indexOf('\n');
          if (newlineIndex === -1) return;

          const line = this.buffer.substring(0, newlineIndex).trim();
          this.buffer = this.buffer.substring(newlineIndex + 1);

          if (line) {
            try {
              const message = JSON.parse(line) as JSONRPCMessage;
              this.emit('message', message);
            } catch (e) {
              // Invalid JSON, skip
            }
          }
          continue;
        }

        this.contentLength = parseInt(match[1], 10);
        this.buffer = this.buffer.substring(headerEnd + 4);
      }

      if (this.buffer.length < this.contentLength) return;

      const content = this.buffer.substring(0, this.contentLength);
      this.buffer = this.buffer.substring(this.contentLength);
      this.contentLength = null;

      try {
        const message = JSON.parse(content) as JSONRPCMessage;
        this.emit('message', message);
      } catch (e) {
        this.emit('error', new Error(`Invalid JSON: ${e}`));
      }
    }
  }

  send(message: JSONRPCMessage): void {
    const content = JSON.stringify(message);
    const header = `Content-Length: ${Buffer.byteLength(content)}\r\n\r\n`;
    this.output.write(header + content);
  }

  close(): void {
    this.input.removeAllListeners();
    this.removeAllListeners();
  }
}

export function isRequest(msg: JSONRPCMessage): msg is JSONRPCRequest {
  return 'method' in msg && 'id' in msg && msg.id !== undefined;
}

export function isResponse(msg: JSONRPCMessage): msg is JSONRPCResponse {
  return 'id' in msg && ('result' in msg || 'error' in msg);
}

export function isNotification(msg: JSONRPCMessage): msg is JSONRPCNotification {
  return 'method' in msg && !('id' in msg && (msg as JSONRPCRequest).id !== undefined);
}

export function createResponse(id: string | number, result: unknown): JSONRPCResponse {
  return {
    jsonrpc: '2.0',
    id,
    result,
  };
}

export function createErrorResponse(
  id: string | number,
  code: number,
  message: string,
  data?: unknown
): JSONRPCResponse {
  return {
    jsonrpc: '2.0',
    id,
    error: { code, message, data },
  };
}
