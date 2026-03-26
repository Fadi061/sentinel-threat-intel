import axios from 'axios';
import { ThreatSignal } from '../types';

export class NVDCollector {
  private baseUrl = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

  async collect(limit: number = 10): Promise<ThreatSignal[]> {
    try {
      // Get CVEs published in the last 24 hours only
      const endDate = new Date().toISOString();
      const startDate = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
      
      const response = await axios.get(this.baseUrl, {
        params: {
          pubStartDate: startDate,
          pubEndDate: endDate,
          resultsPerPage: limit
        }
      });

      const signals: ThreatSignal[] = [];
      const vulnerabilities = response.data.vulnerabilities || [];

      // Sort by published date (most recent first) since API doesn't support sorting
      const sortedVulns = vulnerabilities
        .sort((a: any, b: any) => {
          const dateA = new Date(a.cve.published || 0).getTime();
          const dateB = new Date(b.cve.published || 0).getTime();
          return dateB - dateA; // Descending order
        })
        .slice(0, limit);

      for (const vuln of sortedVulns) {
        const cve = vuln.cve;
        const cvss = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0] || cve.metrics?.cvssMetricV2?.[0];
        const baseScore = cvss?.cvssData?.baseScore || 0;

        signals.push({
          id: cve.id,
          source: 'NVD',
          severity: this.mapCVSSToSeverity(baseScore),
          description: cve.descriptions?.find((d: any) => d.lang === 'en')?.value || 'No description available',
          remediation: `Review and apply security patches for ${cve.id}`,
          timestamp: new Date()
        });
      }

      return signals;
    } catch (error) {
      console.error('NVD collector error:', error);
      return [];
    }
  }

  private mapCVSSToSeverity(score: number): 'low' | 'medium' | 'high' | 'critical' {
    if (score >= 9.0) return 'critical';
    if (score >= 7.0) return 'high';
    if (score >= 4.0) return 'medium';
    return 'low';
  }
}

