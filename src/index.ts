import 'dotenv/config';
import cron from 'node-cron';
import { RedisService } from '../services/redis';
import { SlackService } from '../services/slack';
import { NVDCollector } from '../collectors/nvd';
import { GitHubCollector } from '../collectors/github';
import { ThreatSignal } from '../types';

class ThreatIntelService {
  private redis: RedisService;
  private slack: SlackService;
  private nvdCollector: NVDCollector;
  private githubCollector: GitHubCollector;

  constructor() {
    const redisUrl = process.env.REDIS_URL || 'redis://localhost:6379';
    const slackToken = process.env.SLACK_TOKEN;
    const slackChannel = process.env.SLACK_CHANNEL || '#security-threat-intel-alerts';

    if (!slackToken) {
      throw new Error('SLACK_TOKEN environment variable is required');
    }

    this.redis = new RedisService(redisUrl);
    this.slack = new SlackService(slackToken, slackChannel);
    this.nvdCollector = new NVDCollector();
    this.githubCollector = new GitHubCollector();
  }

  async processSignal(signal: ThreatSignal): Promise<void> {
    try {
      // Only process critical and high severity threats
      if (signal.severity !== 'critical' && signal.severity !== 'high') {
        return;
      }

      const isDuplicate = await this.redis.isDuplicate(signal.id);
      
      if (isDuplicate) {
        console.log(`Skipping duplicate signal: ${signal.id}`);
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
      const [nvdSignals, githubSignals] = await Promise.all([
        this.nvdCollector.collect(5),
        this.githubCollector.collect(5)
      ]);

      const allSignals = [...nvdSignals, ...githubSignals];
      console.log(`Collected ${allSignals.length} signals`);

      for (const signal of allSignals) {
        await this.processSignal(signal);
      }
    } catch (error) {
      console.error('Collection error:', error);
    }
  }

  start(): void {
    console.log('Starting Sentinel Threat Intel service...');
    
    // Run immediately on start
    this.runCollection();
    
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
service.start();

process.on('SIGINT', async () => {
  await service.shutdown();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  await service.shutdown();
  process.exit(0);
});

