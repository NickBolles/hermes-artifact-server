import { config, assertProductionSecrets } from './config.js';
import { createApp } from './app.js';
import { ensureRoot } from './paths.js';

assertProductionSecrets();
await ensureRoot();

const app = createApp();
app.listen(config.port, () => {
  console.log(`Hermes Artifact Server listening on :${config.port}`);
});
