import 'dotenv/config';
import Redis from 'ioredis';

const redisUrl = process.env.REDIS_URL || 'redis://localhost:6380';
const client = new Redis(redisUrl);

async function clearCache() {
  try {
    const keys = await client.keys('threat:*');
    if (keys.length === 0) {
      console.log('No cached threats found.');
      return;
    }
    
    console.log(`Found ${keys.length} cached threats. Clearing...`);
    await client.del(...keys);
    console.log('✓ Cache cleared successfully!');
  } catch (error) {
    console.error('Error clearing cache:', error);
  } finally {
    await client.quit();
  }
}

clearCache();

