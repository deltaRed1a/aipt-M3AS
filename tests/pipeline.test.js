import assert from 'node:assert/strict';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createScan, runScan } from '../src/engine/orchestrator.js';
import { extractZip, resolveSourceRoot } from '../src/ingest/zip.js';
import { loadRegistry } from '../src/engine/registry.js';
import { renderMarkdownReport } from '../src/engine/report.js';

const execFileAsync = promisify(execFile);

async function makeVulnerableProject() {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'm3as-src-'));
  await fsp.mkdir(path.join(dir, 'app'), { recursive: true });
  await fsp.writeFile(
    path.join(dir, 'app', 'server.js'),
    [
      "import { exec } from 'node:child_process';",
      'export function run(userInput) {',
      '  exec(`ls ${userInput}`);',
      '}',
      "const apiKey = 'abcd1234efgh5678';",
      'export default apiKey;',
    ].join('\n'),
  );
  return dir;
}

test('registry loads the configured auditor fleet and consolidator', () => {
  const registry = loadRegistry();
  assert.ok(registry.auditors.length >= 8);
  assert.equal(registry.consolidator.cliModel, 'claude-opus-4.8');
  for (const auditor of registry.auditors) {
    assert.ok(auditor.id && auditor.cliModel && auditor.contextWindow && auditor.reasoning);
  }
});

test('extractZip refuses to write outside the destination', async () => {
  const stage = await fsp.mkdtemp(path.join(os.tmpdir(), 'm3as-zip-'));
  const payload = path.join(stage, 'evil.txt');
  await fsp.writeFile(payload, 'pwned');
  const archive = path.join(stage, 'archive.zip');
  // -j stores a flat name; the traversal name is added explicitly below.
  await execFileAsync('zip', ['-j', archive, payload], { cwd: stage });
  await execFileAsync('python3', [
    '-c',
    'import sys,zipfile\nz=zipfile.ZipFile(sys.argv[1],"a")\nz.writestr("../escaped.txt","pwned")\nz.writestr("app/ok.txt","fine")\nz.close()',
    archive,
  ]);
  const destination = path.join(stage, 'out');
  await assert.rejects(extractZip(archive, destination));
  await assert.rejects(fsp.access(path.join(stage, 'escaped.txt')));

  // A benign archive with a single top-level directory extracts and resolves to it.
  const benign = path.join(stage, 'benign.zip');
  await execFileAsync('python3', [
    '-c',
    'import sys,zipfile\nz=zipfile.ZipFile(sys.argv[1],"w")\nz.writestr("app/ok.txt","fine")\nz.close()',
    benign,
  ]);
  const benignOut = path.join(stage, 'benign-out');
  const result = await extractZip(benign, benignOut);
  assert.equal(result.entries, 1);
  assert.equal(await fsp.readFile(path.join(benignOut, 'app', 'ok.txt'), 'utf8'), 'fine');
  assert.equal(await resolveSourceRoot(benignOut), path.join(benignOut, 'app'));
});

test('scan pipeline audits with every model and consolidates a master list', async () => {
  const sourceDir = await makeVulnerableProject();
  const stage = await fsp.mkdtemp(path.join(os.tmpdir(), 'm3as-zip-'));
  const archive = path.join(stage, 'project.zip');
  await execFileAsync('zip', ['-r', archive, '.'], { cwd: sourceDir });
  const workspaceDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'm3as-ws-'));

  const scan = createScan({
    source: { type: 'zip', reference: 'project.zip', archivePath: archive, targetName: 'AICT' },
  });
  assert.equal(scan.models.length, loadRegistry().auditors.length);

  await runScan(scan, { workspaceDir, engine: 'simulate' });

  assert.equal(scan.status, 'completed', scan.error ?? '');
  assert.ok(scan.models.every((model) => model.status === 'completed'));
  assert.ok(scan.models.some((model) => model.findingCount > 0));
  assert.ok(scan.findings.length > 0);
  // Every finding must carry the full required report schema.
  for (const finding of scan.findings) {
    assert.ok(finding.title);
    assert.ok(finding.cvssVector.startsWith('CVSS:3.1/'));
    assert.ok(finding.cwe.length > 0);
    assert.ok(finding.mitreAttack.length > 0);
    assert.ok(finding.mitreAtlas.length > 0);
    assert.equal(finding.impact.length, 3);
    assert.equal(finding.mitigations.length, 3);
    assert.ok(finding.additionalInformation.length >= 1);
    assert.ok(finding.reportedBy.length >= 1);
  }
  // Duplicates across models are merged into a single master entry.
  const keys = scan.findings.map((finding) => `${finding.title}|${finding.target.file}|${finding.target.line}`);
  assert.equal(new Set(keys).size, keys.length);
  assert.ok(scan.findings.some((finding) => finding.reportedBy.length > 1));

  const report = await fsp.readFile(path.join(workspaceDir, scan.id, 'report.md'), 'utf8');
  assert.match(report, /# M3AS Security & RAI Audit - AICT/);
  assert.match(report, /MITRE ATLAS/);
  assert.match(report, /Steps to Reproduce/);
  assert.equal(report, renderMarkdownReport(scan));
});

test('scan fails cleanly when the source cannot be ingested', async () => {
  const workspaceDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'm3as-ws-'));
  const scan = createScan({
    source: { type: 'zip', reference: 'missing.zip', archivePath: path.join(workspaceDir, 'missing.zip') },
  });
  await runScan(scan, { workspaceDir, engine: 'simulate' });
  assert.equal(scan.status, 'failed');
  assert.ok(scan.error);
});
