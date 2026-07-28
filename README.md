# Sentinel Threat Intelligence Service

A minimal TypeScript service that collects threat intelligence from NVD and GitHub Security Advisories and sends alerts to Slack.

## Features

- 🔍 Collects threats from NVD API and GitHub Security Advisories
- 📰 Ingests external threat-intel feeds (CISA, BleepingComputer, Socket.dev, KrebsOnSecurity)
- 🤖 Adds AI/security and AI engineering news signals (BleepingComputer AI, Simon Willison)
- 📢 Sends formatted alerts to Slack using Block Kit
- 🔄 Redis-based deduplication to prevent duplicate alerts
- ⏰ Automatic hourly collection via cron scheduler
- 🐳 Docker Compose setup for easy deployment

## Setup

1. Install dependencies:
```bash
npm install
```

2. Configure environment variables:
```bash
cp .env.example .env
# Edit .env with your SLACK_TOKEN
```

3. Start Redis with Docker Compose:
```bash
docker compose up redis -d
```

4. Build and run:
```bash
npm run build
npm start
```

### Docker Deployment

**Option 1: Docker Compose (Recommended)**

1. Create `.env` file with your configuration:
```bash
cp .env.example .env
# Edit .env with your SLACK_TOKEN and SLACK_CHANNEL
```

2. Build and run:
```bash
docker compose up --build -d
```

3. View logs:
```bash
docker compose logs -f app
```

4. Stop services:
```bash
docker compose down
```

**Option 2: Build Docker Image Only**
```bash
docker build -t sentinel-threat-intel .
docker run -d \
  -e SLACK_TOKEN=your-token \
  -e SLACK_CHANNEL="#your-channel" \
  -e REDIS_URL=redis://host.docker.internal:6380 \
  sentinel-threat-intel
```

## Environment Variables

- `SLACK_TOKEN`: Slack bot token (required)
- `SLACK_CHANNEL`: Slack channel name with `#` or channel ID (default: `"#security-alerts"`)
- `REDIS_URL`: Redis connection URL (default: `redis://localhost:6380`)
- `FEED_LOOKBACK_HOURS`: How far back feed items are considered "new" (default: `6`)

## Alert Policy

- Alerts are sent only for `critical` severity signals
- Alerts are sent only for third-party package advisories across all ecosystems/languages (for example npm, pip, Maven, NuGet, Go, RubyGems, Cargo, etc.)
- Feed-based threat-intel updates from configured external sources are also sent to the same Slack channel
- Feed and advisory alerts include a direct reference link in the Slack message for investigation

## Project Structure

```
├── collectors/     # Threat data collectors
├── services/       # Redis and Slack services
├── types/          # TypeScript type definitions
└── src/            # Main application code
```

