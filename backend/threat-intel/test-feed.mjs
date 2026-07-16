import { DEFAULT_FEED_PATH } from './index.mjs';
import { loadPhishTankFeed } from './parser.mjs';

try {
  const index = await loadPhishTankFeed(DEFAULT_FEED_PATH);
  console.log(`Raw records: ${index.rawRecordCount}`);
  console.log(`Indexed exact URLs: ${index.exactUrlCount}`);
  console.log(`Indexed hostnames: ${index.hostnameCount}`);
  console.log('Provider initialized: yes');
} catch (error) {
  console.error(`Provider initialized: no (${String(error?.message ?? error)})`);
  process.exitCode = 1;
}
