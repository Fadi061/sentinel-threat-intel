import Redis from 'ioredis';

export class RedisService {
  private client: Redis;

  constructor(url: string) {
    this.client = new Redis(url);
  }

  async isDuplicate(id: string): Promise<boolean> {
    const exists = await this.client.exists(`threat:${id}`);
    return exists === 1;
  }

  async markAsSeen(id: string, ttl: number = 86400): Promise<void> {
    await this.client.setex(`threat:${id}`, ttl, '1');
  }

  async close(): Promise<void> {
    await this.client.quit();
  }
}

