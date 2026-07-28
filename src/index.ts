import 'dotenv/config';
import cron from 'node-cron';
import { RedisService } from '../services/redis';
import { SlackService } from '../services/slack';
import { NVDCollector } from '../collectors/nvd';
import { GitHubCollector } from '../collectors/github';
import { FeedsCollector } from '../collectors/feeds';
import { ThreatSignal } from '../types';

class ThreatIntelService {
  private redis: RedisService;
  private slack: SlackService;
  private nvdCollector: NVDCollector;
  private githubCollector: GitHubCollector;
  private feedsCollector: FeedsCollector;

  constructor() {
    const redisUrl = process.env.REDIS_URL || 'redis://localhost:6380';
    const slackToken = process.env.SLACK_TOKEN;
    const slackChannel = process.env.SLACK_CHANNEL || '#security-threat-intel-alerts';

    if (!slackToken) {
      throw new Error('SLACK_TOKEN environment variable is required');
    }

    this.redis = new RedisService(redisUrl);
    this.slack = new SlackService(slackToken, slackChannel);
    this.nvdCollector = new NVDCollector();
    this.githubCollector = new GitHubCollector();
    this.feedsCollector = new FeedsCollector();
  }

  private shouldAlert(signal: ThreatSignal): boolean {
    // Explicit rule: send all configured feed-site intel updates to the same Slack channel.
    if (signal.category === 'intel_feed') {
      return true;
    }

    // Alert policy: only critical vulnerabilities that target third-party packages.
    if (signal.severity !== 'critical') {
      return false;
    }

    if (!signal.ecosystem || !signal.packageName) {
      return false;
    }

    return true;
  }

  async processSignal(signal: ThreatSignal): Promise<void> {
    try {
      if (!this.shouldAlert(signal)) {
        return;
      }

      const isDuplicate = await this.redis.isDuplicate(signal.id);
      
      if (isDuplicate) {
        if (signal.category !== 'intel_feed') {
          console.log(`Skipping duplicate signal: ${signal.id}`);
        }
        return;
      }

      await this.slack.sendAlert(signal);
      await this.redis.markAsSeen(signal.id);
      console.log(`✓ Sent alert for: ${signal.id} (${signal.severity})`);
    } catch (error: any) {
      const errorMsg = error?.message || error?.toString() || 'Unknown error';
      console.error(`✗ Failed to send alert for ${signal.id}: ${errorMsg}`);
      // Still mark as seen to avoid retrying failed Slack sends
      try {
        await this.redis.markAsSeen(signal.id);
      } catch (redisError) {
        console.error(`Failed to mark ${signal.id} as seen in Redis:`, redisError);
      }
    }
  }

  async runCollection(): Promise<void> {
    console.log('Starting threat intelligence collection...');
    
    try {
      const [nvdSignals, githubSignals, feedSignals] = await Promise.all([
        this.nvdCollector.collect(5),
        this.githubCollector.collect(5),
        this.feedsCollector.collect(3)
      ]);

      const allSignals = [...nvdSignals, ...githubSignals, ...feedSignals];
      console.log(`Collected ${allSignals.length} signals`);

      for (const signal of allSignals) {
        await this.processSignal(signal);
      }
    } catch (error) {
      console.error('Collection error:', error);
    }
  }

  async start(): Promise<void> {
    console.log('Starting Sentinel Threat Intel service...');

    await this.slack.validateConnection();
    console.log('Slack authentication validated');

    // Run immediately on start
    await this.runCollection();

    // Then run every hour
    cron.schedule('0 * * * *', () => {
      this.runCollection();
    });

    console.log('Cron scheduler started (runs every hour)');
  }

  async shutdown(): Promise<void> {
    await this.redis.close();
    console.log('Service shut down gracefully');
  }
}

const service = new ThreatIntelService();
service.start().catch((error: any) => {
  const errorMsg = error?.message || error?.toString() || 'Unknown startup error';
  console.error(`Startup error: ${errorMsg}`);
  process.exit(1);
});

process.on('SIGINT', async () => {
  await service.shutdown();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  await service.shutdown();
  process.exit(0);
});

