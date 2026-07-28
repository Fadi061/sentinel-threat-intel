export interface ThreatSignal {
  id: string;
  source: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  remediation: string;
  ecosystem?: string;
  packageName?: string;
  category?: 'package_advisory' | 'intel_feed';
  referenceUrl?: string;
  timestamp?: Date;
}

