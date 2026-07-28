import axios from 'axios';
import { ThreatSignal } from '../types';

export class GitHubCollector {
  private baseUrl = 'https://api.github.com/advisories';

  private normalizeEcosystem(ecosystem: string | undefined): string | undefined {
    if (!ecosystem) return undefined;
    const normalized = ecosystem.toLowerCase();
    if (normalized === 'pypi') return 'pip';
    return normalized;
  }

  async collect(limit: number = 10): Promise<ThreatSignal[]> {
    try {
      // Get advisories published in the last 24 hours
      const sinceDate = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
      const response = await axios.get(this.baseUrl, {
        params: {
          per_page: limit,
          sort: 'published',
          direction: 'desc'
        },
        headers: {
          'Accept': 'application/vnd.github+json',
          'X-GitHub-Api-Version': '2022-11-28'
        }
      });

      const signals: ThreatSignal[] = [];
      const advisories = response.data || [];

      // Filter to only include advisories published in last 24 hours
      const cutoffDate = new Date(Date.now() - 24 * 60 * 60 * 1000);
      
      for (const advisory of advisories.slice(0, limit)) {
        const publishedDate = new Date(advisory.published_at);
        if (publishedDate < cutoffDate) {
          continue; // Skip old advisories
        }
        
        const severity = advisory.severity?.toLowerCase() || 'medium';
        const vulnerabilities = advisory.vulnerabilities || [];

        // Emit one signal per vulnerable third-party package for precise filtering/routing.
        for (const vulnerability of vulnerabilities) {
          const ecosystem = this.normalizeEcosystem(vulnerability?.package?.ecosystem);
          const packageName = vulnerability?.package?.name;

          if (!ecosystem || !packageName) {
            continue;
          }

          signals.push({
            id: `${advisory.ghsa_id}:${ecosystem}:${packageName}`,
            source: 'GitHub Security',
            severity: this.mapGitHubSeverity(severity),
            description: advisory.summary || advisory.description || 'No description available',
            remediation: `Review advisory: ${advisory.html_url}\nUpdate affected package ${packageName} (${ecosystem}) to a fixed version.`,
            ecosystem,
            packageName,
            category: 'package_advisory',
            referenceUrl: advisory.html_url,
            timestamp: new Date(advisory.updated_at || advisory.published_at)
          });
        }
      }

      return signals;
    } catch (error) {
      console.error('GitHub collector error:', error);
      return [];
    }
  }

  private mapGitHubSeverity(severity: string): 'low' | 'medium' | 'high' | 'critical' {
    const normalized = severity.toLowerCase();
    if (normalized.includes('critical')) return 'critical';
    if (normalized.includes('high')) return 'high';
    if (normalized.includes('low')) return 'low';
    return 'medium';
  }
}

