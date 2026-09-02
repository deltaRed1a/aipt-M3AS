import crypto from 'node:crypto';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { config, readPromptTemplate, renderTemplate } from '../config/index.js';
import { cloneRepository, parseRepoUrl } from '../ingest/git.js';
import { extractZip, resolveSourceRoot } from '../ingest/zip.js';
import { runModel } from './copilotClient.js';
import { parseFindings } from './findings.js';
import { consolidate } from './consolidator.js';
import { renderMarkdownReport, severityCounts } from './report.js';
import { enabledAuditors, loadRegistry } from './registry.js';

export function buildAuditPrompt({ model, targetName, sourceRoot }) {
  return renderTemplate(readPromptTemplate('auditor-prompt.md'), {
    TARGET_NAME: targetName,
    SOURCE_ROOT: sourceRoot,
    MODEL_LABEL: model.label,
    CONTEXT_WINDOW: model.contextWindow,
    REASONING: model.reasoning,
  });
}

async function runWithConcurrency(items, limit, worker) {
  const results = new Array(items.length);
  let cursor = 0;
  const runners = Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, async () => {
    while (cursor < items.length) {
      const index = cursor;
      cursor += 1;
      results[index] = await worker(items[index], index);
    }
  });
  await Promise.all(runners);
  return results;
}

export function createScan({ source, modelIds, registry = loadRegistry() }) {
  const auditors = enabledAuditors(registry, modelIds);
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  return {
    id,
    createdAt: now,
    updatedAt: now,
    status: 'queued',
    source,
    targetName: source.targetName ?? 'the target',
    models: auditors.map((model) => ({
      id: model.id,
      label: model.label,
      contextWindow: model.contextWindow,
      reasoning: model.reasoning,
      status: 'queued',
      findingCount: 0,
      error: null,
    })),
    consolidation: {
      id: registry.consolidator.id,
      label: registry.consolidator.label,
      status: 'queued',
      method: null,
      warning: null,
    },
    findings: [],
    summary: severityCounts([]),
    error: null,
    _auditors: auditors,
    _consolidator: registry.consolidator,
  };
}

async function ingest(scan, workspaceDir) {
  const sourceDir = path.join(workspaceDir, scan.id, 'source');
  await fsp.mkdir(path.dirname(sourceDir), { recursive: true });
  if (scan.source.type === 'zip') {
    const result = await extractZip(scan.source.archivePath, sourceDir);
    scan.source.extracted = { entries: result.entries, bytes: result.bytes, skipped: result.skipped.length };
    await fsp.rm(scan.source.archivePath, { force: true });
    delete scan.source.archivePath;
    return resolveSourceRoot(sourceDir);
  }
  const { url, provider } = parseRepoUrl(scan.source.reference);
  await cloneRepository({ url, provider, destination: sourceDir, branch: scan.source.branch });
  return sourceDir;
}

/**
 * Full pipeline: ingest source -> fan out to every auditor model -> consolidate
 * with the long-context consolidator -> render the master report.
 */
export async function runScan(scan, { store, workspaceDir = config.workspaceDir, engine = config.engine } = {}) {
  const set = (patch) => (store ? store.update(scan.id, patch) : Object.assign(scan, patch));
  const setModel = (modelId, patch) => {
    if (store) store.updateModel(scan.id, modelId, patch);
    else Object.assign(scan.models.find((model) => model.id === modelId) ?? {}, patch);
  };

  try {
    set({ status: 'ingesting' });
    const sourceRoot = await ingest(scan, workspaceDir);
    set({ status: 'auditing', sourceRoot });

    const auditorResults = await runWithConcurrency(scan._auditors, config.concurrency, async (model) => {
      setModel(model.id, { status: 'running', startedAt: new Date().toISOString() });
      try {
        const prompt = buildAuditPrompt({ model, targetName: scan.targetName, sourceRoot });
        const raw = await runModel({ model, prompt, cwd: sourceRoot, engine });
        const findings = parseFindings(raw, model.id);
        setModel(model.id, {
          status: 'completed',
          finishedAt: new Date().toISOString(),
          findingCount: findings.length,
        });
        return { model, findings };
      } catch (error) {
        setModel(model.id, {
          status: 'failed',
          finishedAt: new Date().toISOString(),
          error: error.message,
        });
        return { model, findings: [], error: error.message };
      }
    });

    const successful = auditorResults.filter((result) => !result.error);
    if (successful.length === 0) {
      throw new Error('Every auditor model failed; see per-model errors for details');
    }

    set({ status: 'consolidating' });
    scan.consolidation.status = 'running';
    const consolidated = await consolidate({
      model: scan._consolidator,
      targetName: scan.targetName,
      sourceRoot,
      auditorResults: successful,
      engine,
    });
    scan.consolidation.status = 'completed';
    scan.consolidation.method = consolidated.method;
    scan.consolidation.warning = consolidated.warning ?? null;

    const findings = consolidated.findings;
    const report = renderMarkdownReport({ ...scan, findings });
    const reportPath = path.join(workspaceDir, scan.id, 'report.md');
    await fsp.mkdir(path.dirname(reportPath), { recursive: true });
    await fsp.writeFile(reportPath, report, { mode: 0o600 });

    set({
      status: 'completed',
      findings,
      summary: severityCounts(findings),
      report,
      reportPath,
      finishedAt: new Date().toISOString(),
    });
    return scan;
  } catch (error) {
    scan.consolidation.status = scan.consolidation.status === 'running' ? 'failed' : scan.consolidation.status;
    set({ status: 'failed', error: error.message, finishedAt: new Date().toISOString() });
    return scan;
  }
}
