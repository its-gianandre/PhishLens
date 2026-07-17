import { startBackend } from './server.mjs';

await startBackend(undefined, { includeDemoFixtures: true });

console.log('Presentation demo records overlaid on the local threat-intelligence feeds.');
