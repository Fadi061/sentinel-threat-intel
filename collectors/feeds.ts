import crypto from 'crypto';
import axios from 'axios';
import Parser from 'rss-parser';
import { ThreatSignal } from '../types';

interface FeedConfig {
  source: string;
  url: string;
  type: 'rss' | 'html';
}

export class FeedsCollector {
  private parser: Parser;
  private lookbackHours: number;
  private feeds: FeedConfig[] = [
    { source: 'CISA Alerts', url: 'https://us-cert.cisa.gov/ncas/alerts.xml', type: 'rss' },
    { source: 'BleepingComputer', url: 'https://www.bleepingcomputer.com/feed/', type: 'rss' },
    // AI-focused security coverage.
    { source: 'BleepingComputer AI', url: 'https://www.bleepingcomputer.com/tag/artificial-intelligence/feed/', type: 'rss' },
    { source: 'Socket.dev Blog', url: 'https://socket.dev/blog/category/security-news', type: 'html' },
    { source: 'KrebsOnSecurity', url: 'https://krebsonsecurity.com/feed/', type: 'rss' },
    // AI engineering and "vibe coding" adjacent updates.
    { source: 'Simon Willison', url: 'https://simonwillison.net/atom/everything/', type: 'rss' }
  ];

  constructor() {
    const configuredLookback = Number(process.env.FEED_LOOKBACK_HOURS || '6');
    this.lookbackHours = Number.isFinite(configuredLookback) && configuredLookback > 0 ? configuredLookback : 6;
    this.parser = new Parser({
      timeout: 10000,
      headers: {
        'User-Agent': 'sentinel-threat-intel/1.0'
      }
    });
  }

  async collect(limitPerFeed: number = 5): Promise<ThreatSignal[]> {
    const signals: ThreatSignal[] = [];
    const cutoffDate = new Date(Date.now() - this.lookbackHours * 60 * 60 * 1000);

    for (const feed of this.feeds) {
      try {
        if (feed.type === 'html') {
          const htmlSignals = await this.collectFromHtmlFeed(feed, Math.min(limitPerFeed, 3));
          signals.push(...htmlSignals);
          continue;
        }

        const parsed = await this.parser.parseURL(feed.url);
        const recentItems = (parsed.items || [])
          .filter((item) => {
            const published = item.isoDate || item.pubDate;
            if (!published) return false;
            return new Date(published) >= cutoffDate;
          })
          .slice(0, limitPerFeed);

        for (const item of recentItems) {
          const link = item.link || feed.url;
          const title = item.title || 'Untitled threat intel update';
          const summary = item.contentSnippet || item.content || title;
          const rawId = `${feed.source}|${title}|${link}`;

          signals.push({
            id: `feed-${crypto.createHash('sha256').update(rawId).digest('hex').slice(0, 16)}`,
            source: feed.source,
            severity: this.inferSeverity(`${title} ${summary}`),
            description: summary,
            remediation: `Review external advisory details: ${link}`,
            category: 'intel_feed',
            referenceUrl: link,
            timestamp: new Date(item.isoDate || item.pubDate || Date.now())
          });
        }
      } catch (error) {
        console.error(`Feed collector error (${feed.source}):`, error);
      }
    }

    return signals;
  }

  private async collectFromHtmlFeed(feed: FeedConfig, limitPerFeed: number): Promise<ThreatSignal[]> {
    const signals: ThreatSignal[] = [];
    const response = await axios.get(feed.url, {
      timeout: 10000,
      headers: {
        'User-Agent': 'sentinel-threat-intel/1.0'
      }
    });

    const html = String(response.data || '');
    const matches = [...html.matchAll(/href="(\/blog\/[^"?#]+)"/g)];
    const seen = new Set<string>();

    for (const match of matches) {
      const path = match[1];
      if (!path || path === '/blog' || path.includes('page=')) {
        continue;
      }
      seen.add(path);
      if (seen.size >= limitPerFeed) {
        break;
      }
    }

    for (const path of seen) {
      const link = `https://socket.dev${path}`;
      const slug = path.split('/').pop() || 'socket-security-update';
      const title = slug
        .replace(/-/g, ' ')
        .replace(/\b\w/g, (char) => char.toUpperCase());
      const rawId = `${feed.source}|${title}|${link}`;

      signals.push({
        id: `feed-${crypto.createHash('sha256').update(rawId).digest('hex').slice(0, 16)}`,
        source: feed.source,
        severity: this.inferSeverity(title),
        description: title,
        remediation: `Review external advisory details: ${link}`,
        category: 'intel_feed',
        referenceUrl: link,
        timestamp: new Date()
      });
    }

    return signals;
  }

  private inferSeverity(content: string): 'low' | 'medium' | 'high' | 'critical' {
    const normalized = content.toLowerCase();
    if (
      normalized.includes('critical') ||
      normalized.includes('zero-day') ||
      normalized.includes('rce') ||
      normalized.includes('remote code execution') ||
      normalized.includes('actively exploited')
    ) {
      return 'critical';
    }
    if (
      normalized.includes('high') ||
      normalized.includes('supply chain') ||
      normalized.includes('malicious package') ||
      normalized.includes('vulnerability')
    ) {
      return 'high';
    }
    return 'medium';
  }
}
