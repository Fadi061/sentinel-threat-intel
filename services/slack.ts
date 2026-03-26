import { WebClient } from '@slack/web-api';
import { ThreatSignal } from '../types';

export class SlackService {
  private client: WebClient;
  private channel: string;

  constructor(token: string, channel: string = '#security-alerts') {
    this.client = new WebClient(token);
    this.channel = channel;
  }

  private getSeverityColor(severity: string): string {
    const colors: Record<string, string> = {
      low: '#36a64f',
      medium: '#ffaa00',
      high: '#ff6b00',
      critical: '#ff0000'
    };
    return colors[severity] || '#808080';
  }

  async sendAlert(signal: ThreatSignal): Promise<void> {
    try {
      const text = `${signal.severity.toUpperCase()} Threat: ${signal.id} from ${signal.source}`;
      await this.client.chat.postMessage({
        channel: this.channel,
        text: text,
        blocks: [
          {
            type: 'header',
            text: {
              type: 'plain_text',
              text: `🚨 ${signal.severity.toUpperCase()} Threat Detected`
            }
          },
          {
            type: 'section',
            fields: [
              {
                type: 'mrkdwn',
                text: `*Source:*\n${signal.source}`
              },
              {
                type: 'mrkdwn',
                text: `*ID:*\n\`${signal.id}\``
              },
              {
                type: 'mrkdwn',
                text: `*Severity:*\n${signal.severity}`
              },
              {
                type: 'mrkdwn',
                text: `*Time:*\n${signal.timestamp?.toISOString() || new Date().toISOString()}`
              }
            ]
          },
          {
            type: 'section',
            text: {
              type: 'mrkdwn',
              text: `*Description:*\n${signal.description}`
            }
          },
          {
            type: 'section',
            text: {
              type: 'mrkdwn',
              text: `*Remediation:*\n${signal.remediation}`
            }
          },
          {
            type: 'divider'
          }
        ],
        attachments: [
          {
            color: this.getSeverityColor(signal.severity),
            footer: 'Sentinel Threat Intel'
          }
        ]
      });
    } catch (error: any) {
      if (error?.data?.error === 'channel_not_found') {
        throw new Error(`Slack channel "${this.channel}" not found. Please create the channel or set SLACK_CHANNEL env variable to an existing channel name (with #) or channel ID.`);
      }
      throw error;
    }
  }
}

