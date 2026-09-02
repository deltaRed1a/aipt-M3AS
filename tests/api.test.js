import assert from 'node:assert/strict';
import test from 'node:test';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createApp } from '../src/server/app.js';
import { ScanStore } from '../src/store/scanStore.js';

async function withServer(run) {
  const workspaceDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'm3as-api-'));
  const app = createApp({ store: new ScanStore(), engine: 'simulate', workspaceDir });
  const server = app.listen(0);
  await new Promise((resolve) => server.once('listening', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    await run(base);
  } finally {
    server.close();
  }
}

test('GET /api/models exposes the swappable registry', async () => {
  await withServer(async (base) => {
    const response = await fetch(`${base}/api/models`);
    const data = await response.json();
    assert.equal(response.status, 200);
    assert.ok(data.auditors.length >= 8);
    assert.ok(data.consolidator.label.includes('Opus 4.8'));
    assert.equal(data.engine, 'simulate');
  });
});

test('POST /api/scans/repo rejects untrusted hosts and starts allowed ones', async () => {
  await withServer(async (base) => {
    const bad = await fetch(`${base}/api/scans/repo`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ repoUrl: 'https://evil.example.com/a/b' }),
    });
    assert.equal(bad.status, 400);

    const badBranch = await fetch(`${base}/api/scans/repo`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ repoUrl: 'https://github.com/org/repo', branch: 'main; rm -rf /' }),
    });
    assert.equal(badBranch.status, 400);

    const good = await fetch(`${base}/api/scans/repo`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ repoUrl: 'https://github.com/org/repo', models: ['gpt-5.5'] }),
    });
    const scan = await good.json();
    assert.equal(good.status, 202);
    assert.equal(scan.models.length, 1);
    assert.equal(scan.source.type, 'github');
    assert.equal(scan.sourceRoot, undefined);
    assert.equal(scan._auditors, undefined);
  });
});

test('GET /api/scans/:id returns 404 for unknown scans', async () => {
  await withServer(async (base) => {
    const response = await fetch(`${base}/api/scans/does-not-exist`);
    assert.equal(response.status, 404);
  });
});

test('POST /api/scans/zip runs a full scan and serves the report', async () => {
  await withServer(async (base) => {
    const zipDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'm3as-upload-'));
    const source = path.join(zipDir, 'index.js');
    await fsp.writeFile(source, "const password = 'supersecretvalue';\neval(userInput);\n");
    const { execFile } = await import('node:child_process');
    const { promisify } = await import('node:util');
    const archive = path.join(zipDir, 'src.zip');
    await promisify(execFile)('zip', ['-j', archive, source]);

    const form = new FormData();
    form.append('archive', new Blob([await fsp.readFile(archive)], { type: 'application/zip' }), 'src.zip');
    form.append('targetName', 'AICT');
    const response = await fetch(`${base}/api/scans/zip`, { method: 'POST', body: form });
    const scan = await response.json();
    assert.equal(response.status, 202);

    let current = scan;
    for (let attempt = 0; attempt < 100 && current.status !== 'completed' && current.status !== 'failed'; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 100));
      current = await (await fetch(`${base}/api/scans/${scan.id}`)).json();
    }
    assert.equal(current.status, 'completed', current.error ?? '');
    assert.ok(current.findings.length > 0);

    const report = await fetch(`${base}/api/scans/${scan.id}/report`);
    assert.equal(report.status, 200);
    assert.match(await report.text(), /M3AS Security & RAI Audit/);
  });
});

test('scan start endpoints are rate limited', async () => {
  process.env.M3AS_RATE_LIMIT = '2';
  try {
    await withServer(async (base) => {
      const post = () => fetch(`${base}/api/scans/repo`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repoUrl: 'https://github.com/org/repo' }),
      });
      assert.equal((await post()).status, 202);
      assert.equal((await post()).status, 202);
      const blocked = await post();
      assert.equal(blocked.status, 429);
      assert.match((await blocked.json()).error, /Too many scan requests/);
    });
  } finally {
    delete process.env.M3AS_RATE_LIMIT;
  }
});
