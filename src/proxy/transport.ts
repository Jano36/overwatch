import { EventEmitter } from 'events';
import type { Readable, Writable } from 'stream';

/**
 * Configuration for MCPTransport security limits.
 */
export interface TransportConfig {
  /** Maximum message size in bytes (default: 10MB) */
  maxMessageSize?: number;
  /** Maximum buffer size in bytes (default: 20MB) */
  maxBufferSize?: number;
  /** Maximum header size in bytes (default: 8KB) */
  maxHeaderSize?: number;
}

/** Default limits to prevent resource exhaustion (T1-2) */
const DEFAULT_MAX_MESSAGE_SIZE = 10 * 1024 * 1024; // 10MB
const DEFAULT_MAX_BUFFER_SIZE = 20 * 1024 * 1024;  // 20MB
const DEFAULT_MAX_HEADER_SIZE = 8 * 1024;           // 8KB

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
  private readonly maxMessageSize: number;
  private readonly maxBufferSize: number;
  private readonly maxHeaderSize: number;

  constructor(
    private input: Readable,
    private output: Writable,
    _name: string = 'transport',
    config?: TransportConfig
  ) {
    super();
    this.maxMessageSize = config?.maxMessageSize ?? DEFAULT_MAX_MESSAGE_SIZE;
    this.maxBufferSize = config?.maxBufferSize ?? DEFAULT_MAX_BUFFER_SIZE;
    this.maxHeaderSize = config?.maxHeaderSize ?? DEFAULT_MAX_HEADER_SIZE;
    this.setupInputHandler();
  }

  private setupInputHandler(): void {
    this.input.on('data', (chunk: Buffer) => {
      // Security: Check buffer size before appending (T1-2)
      const newSize = this.buffer.length + chunk.length;
      if (newSize > this.maxBufferSize) {
        this.emit('error', new Error(
          `Buffer size limit exceeded: ${newSize} > ${this.maxBufferSize} bytes. ` +
          'Possible resource exhaustion attack.'
        ));
        // Clear buffer to recover
        this.buffer = '';
        this.contentLength = null;
        return;
      }

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
        if (headerEnd === -1) {
          // Security: Check for oversized headers (T1-2)
          if (this.buffer.length > this.maxHeaderSize) {
            this.emit('error', new Error(
              `Header size limit exceeded: ${this.buffer.length} > ${this.maxHeaderSize} bytes. ` +
              'Possible header injection attack.'
            ));
            this.buffer = '';
            return;
          }
          return;
        }

        const header = this.buffer.substring(0, headerEnd);
        const match = header.match(/Content-Length: (\d+)/i);
        if (!match) {
          // No Content-Length, try to parse as newline-delimited JSON
          const newlineIndex = this.buffer.indexOf('\n');
          if (newlineIndex === -1) return;

          const line = this.buffer.substring(0, newlineIndex).trim();
          this.buffer = this.buffer.substring(newlineIndex + 1);

          // Security: Check line length for newline-delimited mode
          if (line.length > this.maxMessageSize) {
            this.emit('error', new Error(
              `Message size limit exceeded: ${line.length} > ${this.maxMessageSize} bytes.`
            ));
            continue;
          }

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

        // Security: Validate Content-Length value (T1-2)
        const contentLength = parseInt(match[1], 10);

        // Check for invalid/malicious Content-Length values
        if (!Number.isFinite(contentLength) || contentLength < 0) {
          this.emit('error', new Error(
            `Invalid Content-Length: ${match[1]}. Must be a positive integer.`
          ));
          this.buffer = this.buffer.substring(headerEnd + 4);
          continue;
        }

        // Check against maximum message size
        if (contentLength > this.maxMessageSize) {
          this.emit('error', new Error(
            `Content-Length ${contentLength} exceeds maximum allowed size of ${this.maxMessageSize} bytes. ` +
            'Possible resource exhaustion attack. Rejecting message.'
          ));
          this.buffer = this.buffer.substring(headerEnd + 4);
          // Skip the oversized content if it's already in buffer
          if (this.buffer.length >= contentLength) {
            this.buffer = this.buffer.substring(contentLength);
          } else {
            // Content not fully received yet - we need to track and skip it
            // For simplicity, clear buffer and let sender retry with smaller message
            this.buffer = '';
          }
          continue;
        }

        this.contentLength = contentLength;
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
