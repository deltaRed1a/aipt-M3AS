import fs from 'node:fs';
import { config } from '../config/index.js';

const REQUIRED_FIELDS = ['id', 'label', 'cliModel'];

function normalizeModel(raw, role) {
  for (const field of REQUIRED_FIELDS) {
    if (typeof raw?.[field] !== 'string' || raw[field].trim() === '') {
      throw new Error(`Model registry entry is missing required field "${field}"`);
    }
  }
  return {
    id: raw.id,
    label: raw.label,
    cliModel: raw.cliModel,
    contextWindow: raw.contextWindow ?? 'default',
    reasoning: raw.reasoning ?? 'high',
    cliArgs: Array.isArray(raw.cliArgs) ? raw.cliArgs.map(String) : [],
    enabled: raw.enabled !== false,
    role,
  };
}

/**
 * Loads the pluggable model registry. Models can be added, removed or swapped
 * by editing config/models.json (or M3AS_MODELS_FILE) - no code changes needed.
 */
export function loadRegistry(file = config.modelsFile) {
  const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (!Array.isArray(parsed.auditors) || parsed.auditors.length === 0) {
    throw new Error('Model registry must define a non-empty "auditors" array');
  }
  if (!parsed.consolidator) {
    throw new Error('Model registry must define a "consolidator" model');
  }
  const auditors = parsed.auditors.map((model) => normalizeModel(model, 'auditor'));
  const ids = new Set();
  for (const auditor of auditors) {
    if (ids.has(auditor.id)) {
      throw new Error(`Duplicate model id in registry: ${auditor.id}`);
    }
    ids.add(auditor.id);
  }
  return {
    auditors,
    consolidator: normalizeModel(parsed.consolidator, 'consolidator'),
  };
}

export function enabledAuditors(registry, selectedIds) {
  const available = registry.auditors.filter((model) => model.enabled);
  if (!selectedIds || selectedIds.length === 0) return available;
  const wanted = new Set(selectedIds);
  const selected = available.filter((model) => wanted.has(model.id));
  if (selected.length === 0) {
    throw new Error('None of the selected models are available in the registry');
  }
  return selected;
}
