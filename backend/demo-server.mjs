import { startBackend } from './server.mjs';

await startBackend(undefined, { includeDemoFixtures: true, includeOpenPhish: true });

console.log('Presentation demo records overlaid on the threat-intelligence feeds.');
