import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
export const rootDir = path.resolve(here, '..', '..');
export const configDir = path.join(rootDir, 'config');

function intFromEnv(name, fallback) {
  const parsed = Number.parseInt(process.env[name] ?? '', 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

export const config = {
  port: intFromEnv('PORT', 3000),
  /** Directory where uploaded/cloned sources and reports are kept. */
  workspaceDir: process.env.M3AS_WORKSPACE ?? path.join(rootDir, 'workspace'),
  /** 'copilot' runs the GitHub Copilot CLI, 'simulate' produces offline demo output. */
  engine: process.env.M3AS_ENGINE === 'simulate' ? 'simulate' : 'copilot',
  copilotBin: process.env.M3AS_COPILOT_BIN ?? 'copilot',
  /** Per-model timeout in milliseconds. */
  modelTimeoutMs: intFromEnv('M3AS_MODEL_TIMEOUT_MS', 20 * 60 * 1000),
  /** How many auditor models may run at the same time. */
  concurrency: intFromEnv('M3AS_CONCURRENCY', 4),
  /** Maximum accepted ZIP upload size in bytes. */
  maxUploadBytes: intFromEnv('M3AS_MAX_UPLOAD_BYTES', 200 * 1024 * 1024),
  /** Maximum total size of the extracted archive in bytes (zip bomb guard). */
  maxExtractedBytes: intFromEnv('M3AS_MAX_EXTRACTED_BYTES', 1024 * 1024 * 1024),
  maxExtractedEntries: intFromEnv('M3AS_MAX_EXTRACTED_ENTRIES', 50000),
  modelsFile: process.env.M3AS_MODELS_FILE ?? path.join(configDir, 'models.json'),
};

export function readPromptTemplate(name) {
  return fs.readFileSync(path.join(configDir, name), 'utf8');
}

export function renderTemplate(template, values) {
  return template.replace(/{{\s*([A-Z0-9_]+)\s*}}/g, (match, key) =>
    Object.hasOwn(values, key) ? String(values[key]) : match,
  );
}
