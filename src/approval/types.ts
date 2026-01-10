import type { RiskLevel } from '../config/types.js';

export interface ApprovalRequest {
  id: string;
  server?: string;
  tool: string;
  args?: Record<string, unknown>;
  riskLevel: RiskLevel;
  reason?: string;
  timestamp: Date;
}

export interface ApprovalResponse {
  approved: boolean;
  sessionDuration?: 'once' | '5min' | '15min' | 'session';
  reason?: string;
}

export interface ApprovalHandler {
  requestApproval(request: ApprovalRequest): Promise<ApprovalResponse>;
  close(): Promise<void>;
}

export type ApprovalCallback = (request: ApprovalRequest) => Promise<ApprovalResponse>;
