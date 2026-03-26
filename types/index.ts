export interface ThreatSignal {
  id: string;
  source: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  remediation: string;
  timestamp?: Date;
}

