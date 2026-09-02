import crypto from 'node:crypto';

const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Informational'];

function toStringArray(value) {
  if (Array.isArray(value)) return value.filter((item) => item != null).map((item) => String(item).trim()).filter(Boolean);
  if (typeof value === 'string' && value.trim() !== '') return [value.trim()];
  return [];
}

function normalizeSeverity(value) {
  const match = SEVERITIES.find((severity) => severity.toLowerCase() === String(value ?? '').trim().toLowerCase());
  return match ?? 'Informational';
}

function normalizeScore(value) {
  const score = Number(value);
  if (!Number.isFinite(score)) return 0;
  return Math.min(10, Math.max(0, Math.round(score * 10) / 10));
}

/**
 * Extracts the JSON payload from a model response. Models are asked for a single
 * fenced ```json block, but plain JSON and JSON surrounded by prose are tolerated.
 */
export function extractJson(text) {
  if (typeof text !== 'string' || text.trim() === '') return null;
  const fenced = [...text.matchAll(/```(?:json)?\s*([\s\S]*?)```/gi)].map((match) => match[1]);
  const candidates = [...fenced.reverse(), text];
  const firstBrace = text.indexOf('{');
  const lastBrace = text.lastIndexOf('}');
  if (firstBrace !== -1 && lastBrace > firstBrace) {
    candidates.push(text.slice(firstBrace, lastBrace + 1));
  }
  for (const candidate of candidates) {
    try {
      const parsed = JSON.parse(candidate.trim());
      if (parsed && typeof parsed === 'object') return parsed;
    } catch {
      // try the next candidate
    }
  }
  return null;
}

export function normalizeFinding(raw, modelId) {
  const target = raw?.target ?? {};
  const recommendation = raw?.recommendation ?? {};
  const finding = {
    title: String(raw?.title ?? raw?.findingDescription ?? 'Untitled finding').trim().slice(0, 300),
    findingDescription: String(raw?.findingDescription ?? raw?.description ?? '').trim(),
    stepsToReproduce: toStringArray(raw?.stepsToReproduce),
    severity: normalizeSeverity(raw?.severity),
    impactLevel: String(raw?.impactLevel ?? raw?.severity ?? 'Low').trim(),
    cvssVector: String(raw?.cvssVector ?? '').trim(),
    cvssScore: normalizeScore(raw?.cvssScore),
    mitreAttack: toStringArray(raw?.mitreAttack),
    mitreAtlas: toStringArray(raw?.mitreAtlas),
    cwe: toStringArray(raw?.cwe),
    category: String(raw?.category ?? 'security').trim().toLowerCase() === 'rai' ? 'rai' : 'security',
    target: {
      file: String(target.file ?? '').trim(),
      line: Number.isFinite(Number(target.line)) ? Number(target.line) : null,
      location: String(target.location ?? '').trim(),
    },
    impact: toStringArray(raw?.impact),
    recommendation: {
      insecureSnippet: String(recommendation.insecureSnippet ?? '').trim(),
      secureSnippet: String(recommendation.secureSnippet ?? '').trim(),
      notes: String(recommendation.notes ?? '').trim(),
    },
    mitigations: toStringArray(raw?.mitigations),
    additionalInformation: toStringArray(raw?.additionalInformation),
    reportedBy: toStringArray(raw?.reportedBy),
    confirmation: String(raw?.confirmation ?? '').trim(),
  };
  if (modelId && !finding.reportedBy.includes(modelId)) finding.reportedBy.push(modelId);
  finding.id = crypto
    .createHash('sha256')
    .update(`${finding.title}|${finding.target.file}|${finding.target.line ?? ''}`)
    .digest('hex')
    .slice(0, 12);
  return finding;
}

export function parseFindings(text, modelId) {
  const parsed = extractJson(text);
  const list = Array.isArray(parsed) ? parsed : parsed?.findings;
  if (!Array.isArray(list)) return [];
  return list.map((item) => normalizeFinding(item, modelId));
}

function dedupeKey(finding) {
  return [
    finding.target.file.toLowerCase(),
    finding.target.line ?? '',
    finding.cwe.map((cwe) => cwe.toLowerCase()).sort().join(','),
    finding.title.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim(),
  ].join('|');
}

/**
 * Deterministic fallback used when the consolidator model is unavailable or
 * returns unusable output: merges identical findings and keeps reporter attribution.
 */
export function mergeFindings(findingsByModel) {
  const merged = new Map();
  for (const { modelId, findings } of findingsByModel) {
    for (const finding of findings) {
      const key = dedupeKey(finding);
      const existing = merged.get(key);
      if (!existing) {
        merged.set(key, { ...finding, reportedBy: [...new Set([...finding.reportedBy, modelId])] });
        continue;
      }
      existing.reportedBy = [...new Set([...existing.reportedBy, ...finding.reportedBy, modelId])];
      if (finding.cvssScore > existing.cvssScore) {
        existing.cvssScore = finding.cvssScore;
        existing.severity = finding.severity;
        existing.cvssVector = finding.cvssVector || existing.cvssVector;
      }
      for (const field of ['stepsToReproduce', 'impact', 'mitigations', 'additionalInformation', 'mitreAttack', 'mitreAtlas', 'cwe']) {
        existing[field] = [...new Set([...existing[field], ...finding[field]])];
      }
    }
  }
  return [...merged.values()].sort((a, b) => b.cvssScore - a.cvssScore);
}
