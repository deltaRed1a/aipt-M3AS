import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import express from 'express';
import multer from 'multer';
import { config, rootDir } from '../config/index.js';
import { createScan, runScan } from '../engine/orchestrator.js';
import { loadRegistry } from '../engine/registry.js';
import { parseRepoUrl } from '../ingest/git.js';
import { ScanStore } from '../store/scanStore.js';

const SAFE_NAME = /^[\w .-]{1,120}$/;

export function serializeScan(scan) {
  if (!scan) return null;
  const { _auditors, _consolidator, report, sourceRoot, reportPath, source, ...rest } = scan;
  return {
    ...rest,
    source: { type: source.type, reference: source.reference, extracted: source.extracted ?? null },
    hasReport: Boolean(report),
  };
}

export function createApp({ store = new ScanStore(), engine = config.engine, workspaceDir = config.workspaceDir } = {}) {
  const app = express();
  const upload = multer({
    dest: path.join(os.tmpdir(), 'm3as-uploads'),
    limits: { fileSize: config.maxUploadBytes, files: 1 },
    fileFilter: (_req, file, callback) => {
      const isZip = file.mimetype === 'application/zip'
        || file.mimetype === 'application/x-zip-compressed'
        || file.mimetype === 'application/octet-stream'
        || file.originalname.toLowerCase().endsWith('.zip');
      callback(isZip ? null : new Error('Only .zip archives are accepted'), isZip);
    },
  });

  app.disable('x-powered-by');
  app.use(express.json({ limit: '256kb' }));
  app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'",
    );
    next();
  });
  app.use(express.static(path.join(rootDir, 'public')));

  app.get('/api/models', (_req, res) => {
    const registry = loadRegistry();
    res.json({
      auditors: registry.auditors.map(({ id, label, contextWindow, reasoning, enabled }) => ({
        id,
        label,
        contextWindow,
        reasoning,
        enabled,
      })),
      consolidator: {
        id: registry.consolidator.id,
        label: registry.consolidator.label,
        contextWindow: registry.consolidator.contextWindow,
        reasoning: registry.consolidator.reasoning,
      },
      engine,
    });
  });

  app.get('/api/scans', (_req, res) => {
    res.json({ scans: store.list().map(serializeScan) });
  });

  app.get('/api/scans/:id', (req, res) => {
    const scan = store.get(req.params.id);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    return res.json(serializeScan(scan));
  });

  app.get('/api/scans/:id/report', (req, res) => {
    const scan = store.get(req.params.id);
    if (!scan?.report) return res.status(404).json({ error: 'Report not available' });
    res.type('text/markdown; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="m3as-report-${scan.id}.md"`);
    return res.send(scan.report);
  });

  app.get('/api/scans/:id/events', (req, res) => {
    const scan = store.get(req.params.id);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
    });
    const send = (updated) => {
      if (updated.id !== scan.id) return;
      res.write(`data: ${JSON.stringify(serializeScan(updated))}\n\n`);
      if (updated.status === 'completed' || updated.status === 'failed') res.end();
    };
    send(scan);
    store.on('update', send);
    req.on('close', () => store.off('update', send));
    return undefined;
  });

  const start = (source, modelIds, res) => {
    let scan;
    try {
      scan = createScan({ source, modelIds });
    } catch (error) {
      return res.status(400).json({ error: error.message });
    }
    store.create(scan);
    void runScan(scan, { store, engine, workspaceDir });
    return res.status(202).json(serializeScan(scan));
  };

  const parseModelIds = (value) => {
    if (Array.isArray(value)) return value.map(String);
    if (typeof value === 'string' && value.trim() !== '') {
      return value.split(',').map((id) => id.trim()).filter(Boolean);
    }
    return [];
  };

  app.post('/api/scans/repo', (req, res) => {
    const { repoUrl, branch, targetName } = req.body ?? {};
    let parsed;
    try {
      parsed = parseRepoUrl(repoUrl);
    } catch (error) {
      return res.status(400).json({ error: error.message });
    }
    if (branch !== undefined && (typeof branch !== 'string' || !/^[\w./-]{1,200}$/.test(branch))) {
      return res.status(400).json({ error: 'Invalid branch name' });
    }
    if (targetName !== undefined && (typeof targetName !== 'string' || !SAFE_NAME.test(targetName))) {
      return res.status(400).json({ error: 'Invalid target name' });
    }
    return start(
      {
        type: parsed.provider === 'github' ? 'github' : 'ado',
        reference: parsed.url,
        branch: branch || undefined,
        targetName: targetName || parsed.path.replace(/^\/+/, '') || 'the target',
      },
      parseModelIds(req.body?.models),
      res,
    );
  });

  app.post('/api/scans/zip', upload.single('archive'), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'A .zip archive is required' });
    const targetName = req.body?.targetName;
    if (targetName !== undefined && targetName !== '' && !SAFE_NAME.test(String(targetName))) {
      await fsp.rm(req.file.path, { force: true });
      return res.status(400).json({ error: 'Invalid target name' });
    }
    return start(
      {
        type: 'zip',
        reference: path.basename(req.file.originalname).slice(0, 120),
        archivePath: req.file.path,
        targetName: targetName || path.basename(req.file.originalname, '.zip').slice(0, 120) || 'the target',
      },
      parseModelIds(req.body?.models),
      res,
    );
  });

  // eslint-disable-next-line no-unused-vars
  app.use((error, _req, res, _next) => {
    const status = error instanceof multer.MulterError || error.status === 400 ? 400 : 500;
    res.status(status).json({ error: status === 400 ? error.message : 'Internal server error' });
  });

  return app;
}
