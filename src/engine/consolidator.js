import { readPromptTemplate, renderTemplate, config } from '../config/index.js';
import { runModel } from './copilotClient.js';
import { mergeFindings, parseFindings } from './findings.js';

const MAX_FINDINGS_JSON_CHARS = 400_000;

export function buildConsolidationPrompt({ targetName, sourceRoot, auditorResults }) {
  const payload = auditorResults.map(({ model, findings }) => ({
    model: model.id,
    label: model.label,
    findings,
  }));
  let json = JSON.stringify(payload, null, 2);
  if (json.length > MAX_FINDINGS_JSON_CHARS) {
    json = JSON.stringify(payload);
  }
  return renderTemplate(readPromptTemplate('consolidator-prompt.md'), {
    TARGET_NAME: targetName,
    SOURCE_ROOT: sourceRoot,
    MODEL_COUNT: auditorResults.length,
    AUDITOR_FINDINGS_JSON: json.slice(0, MAX_FINDINGS_JSON_CHARS),
  });
}

/**
 * Consolidation pass: a single long-context model de-duplicates the auditor
 * findings, confirms or denies unique ones and produces the master list.
 * If the model fails or returns unusable output we fall back to a deterministic
 * merge so a scan always yields a report.
 */
export async function consolidate({ model, targetName, sourceRoot, auditorResults, engine = config.engine, signal }) {
  const deterministic = mergeFindings(
    auditorResults.map(({ model: auditor, findings }) => ({ modelId: auditor.id, findings })),
  );
  if (auditorResults.length === 0) {
    return { findings: [], method: 'none', warning: 'No auditor model produced findings' };
  }
  const prompt = buildConsolidationPrompt({ targetName, sourceRoot, auditorResults });
  try {
    const raw = engine === 'simulate' ? null : await runModel({ model, prompt, cwd: sourceRoot, signal, engine });
    const findings = raw ? parseFindings(raw, null) : [];
    if (findings.length > 0) {
      return { findings: findings.sort((a, b) => b.cvssScore - a.cvssScore), method: 'model', raw };
    }
    return {
      findings: deterministic,
      method: 'deterministic',
      warning:
        engine === 'simulate'
          ? 'Simulate engine: findings merged deterministically'
          : 'Consolidator returned no parsable findings; deterministic merge used',
    };
  } catch (error) {
    return {
      findings: deterministic,
      method: 'deterministic',
      warning: `Consolidator model failed (${error.message}); deterministic merge used`,
    };
  }
}
