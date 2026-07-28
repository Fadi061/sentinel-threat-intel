# Deploying Sentinel Threat Intel to AWS

This is a small, always-on service: a single Node.js worker (hourly cron) plus a Redis
cache. It needs very little CPU/RAM, but it must run **24/7** so it can collect on
schedule. That profile makes it a poor fit for "serverless" and a great fit for a tiny
always-on VM.

---

## Which AWS server should I use? (cost-focused)

| Option | What it is | Approx. cost/month | Verdict |
|--------|-----------|--------------------|---------|
| **AWS Lightsail** (1 GB plan) | Simple VPS with flat pricing | **~$7** (or ~$5 / 512 MB, ~$12 / 2 GB) | ✅ **Recommended** — cheapest + simplest for a small service |
| **EC2 t3.micro** | x86 EC2, Free Tier eligible | **$0 for first 12 months**, then ~$8 | ✅ Best if you still have Free Tier |
| **EC2 t4g.small** (ARM, Graviton) | General EC2 instance | ~$12 + storage (~$1) | Good if you already use EC2; ARM = cheaper |
| ECS Fargate | Serverless containers | ~$9–15 (always-on) | More moving parts, not worth it here |
| Lambda | Function-as-a-service | N/A | ❌ Won't work — needs a persistent process + Redis |

### Recommendation
- **If you still have AWS Free Tier** → use an **EC2 `t3.micro`** (free for 12 months).
- **Otherwise** → use **AWS Lightsail, the $7/month (1 GB) plan**. Simplest and cheapest
  predictable option, and Docker runs on it fine.

Redis is tiny here, so run it **in the same Docker Compose stack on the one VM** — do
**not** pay for a managed ElastiCache Redis (that alone costs more than the whole app).

---

## Deploy with Docker Compose on a single VM (recommended)

Works the same on Lightsail or EC2. Steps assume Ubuntu 22.04.

### 1. Create the server
- **Lightsail:** Console → Create instance → Linux → OS Only → Ubuntu 22.04 → pick the
  $7 (1 GB) plan → Create.
- **EC2:** Launch instance → Ubuntu 22.04 → `t3.micro` (or `t4g.small`) → allow SSH (port
  22) in the security group → download the `.pem` key.

You do **not** need to open any inbound app ports — this service only makes outbound
calls (to NVD, GitHub, RSS feeds, Slack). Keep the firewall closed except SSH.

### 2. SSH in
```bash
# EC2
ssh -i your-key.pem ubuntu@<PUBLIC_IP>
# Lightsail: use the browser SSH button, or your downloaded key
```

### 3. Install Docker + Compose
```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
newgrp docker   # apply group without re-login
docker --version && docker compose version
```

### 4. Get the code onto the server
```bash
git clone <your-repo-url> sentinel-threat-intel
cd sentinel-threat-intel
```
(If it's not in git, copy it up from your Mac with `scp -r ./sentinel-threat-intel ubuntu@<PUBLIC_IP>:~/`)

### 5. Configure secrets
```bash
cp .env.example .env
nano .env
# set at minimum:
#   SLACK_TOKEN=xoxb-...
#   SLACK_CHANNEL=#security-threat-intel-alerts
```

### 6. Run it
```bash
docker compose up --build -d
docker compose logs -f app     # watch it start collecting
```

The included `docker-compose.yml` already runs both `redis` and `app`, with
`restart: unless-stopped`, so the service comes back automatically after a reboot or
crash.

### 7. Verify
```bash
docker compose ps             # both containers "Up"
docker compose logs app | tail -n 50
```

### Updating later
```bash
cd sentinel-threat-intel
git pull
docker compose up --build -d
```

### Stopping / removing
```bash
docker compose down           # stop
docker compose down -v        # stop + delete Redis data volume
```

---

## Cost-saving tips
- One small VM runs **both** the app and Redis — no managed database needed.
- Prefer **ARM (`t4g`)** instances over x86 — same performance here, lower price.
- Set an **AWS Budget alert** (Billing → Budgets) at e.g. $10/month so you're never
  surprised.

---

## Security notes
- Never commit `.env` — keep `SLACK_TOKEN` only on the server.
- Keep the security group / firewall closed to inbound traffic except SSH from your IP.
- Run `sudo apt-get upgrade` periodically to patch the OS.
