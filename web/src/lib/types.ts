// Formas de las respuestas del API de secure-server que usa la interfaz (todas bajo /api/system y /api/metrics).
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export interface AlertItem {
  id: number; rule: string; subject: string | null; severity: Severity; title: string; status: 'open' | 'acknowledged' | 'resolved';
  count: number; firstSeen: string; lastSeen: string; details?: unknown;
  acknowledgedBy?: number | null; acknowledgedAt?: string | null; resolvedBy?: number | null; resolvedAt?: string | null;
  notified?: boolean; notifyError?: string | null;
}

export interface Dashboard {
  generatedAt: string; windowHours: number;
  alerts: { open: Record<string, number>; latest: AlertItem[] };
  events: {
    bySeverity: Record<string, number>; total: number;
    topTypes: { event_type: string; severity: string; total: number }[];
    topRules: { rule: string; total: number }[];
    topIps: { ip_address: string; total: number; max_risk: number | null; country: string | null }[];
    timeline: { hour: string; total: number }[];
  };
  auth: { logins: { success: number; failed: number }; accountsAtLockThreshold: number; activeSessions: number; refreshTokenReuse: number };
  files: { total: number; bytes: number; byScanStatus: Record<string, number>; bySanitizeStatus: Record<string, number>; rejectedInWindow: number };
  approvals: { pending: number };
  blockedIps: { active: number };
  system: { database: 'ok' | 'error'; uptimeSeconds: number; node: string; config: Record<string, boolean | string | number | null> };
}

export interface ApprovalItem {
  id: number; action: string; status: string; reason: string;
  target: { id: number; username: string | null } | null;
  requestedBy: { id: number; username: string | null }; approvedBy: number | null;
  requestedAt: string; expiresAt: string; decidedAt?: string | null; executedAt?: string | null;
}

export interface EventItem {
  id: number; created_at: string; event_type: string; rule: string | null; severity: Severity; risk_score: number;
  action_taken: string | null; ip_address: string | null; user_id: number | null; method: string | null; path: string | null;
  status_code: number | null; country: string | null; details: unknown;
}

export interface BlockedIp { ip_address: string; reason: string; blocked_until: string; block_count: number; created_at: string }

export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
