import { config } from '../config/index.js';
import { createApp } from './app.js';
import { scanStore } from '../store/scanStore.js';

const app = createApp({ store: scanStore });

app.listen(config.port, () => {
  console.log(`M3AS listening on http://localhost:${config.port} (engine: ${config.engine})`);
});
