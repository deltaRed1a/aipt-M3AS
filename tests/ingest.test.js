import assert from 'node:assert/strict';
import test from 'node:test';
import { parseRepoUrl } from '../src/ingest/git.js';
import { safeEntryPath } from '../src/ingest/zip.js';

test('parseRepoUrl accepts GitHub and Azure DevOps https URLs', () => {
  assert.equal(parseRepoUrl('https://github.com/org/repo').provider, 'github');
  assert.equal(parseRepoUrl('https://dev.azure.com/org/project/_git/repo').provider, 'ado');
  assert.equal(parseRepoUrl('https://myorg.visualstudio.com/project/_git/repo').provider, 'ado');
});

test('parseRepoUrl rejects unsafe URLs', () => {
  for (const url of [
    'http://github.com/org/repo',
    'file:///etc/passwd',
    'ext::sh -c whoami',
    'https://evil.example.com/org/repo',
    'https://169.254.169.254/latest/meta-data',
    `https://user:${'pw'}@github.com/org/repo`,
    '',
    '--upload-pack=touch /tmp/pwn',
  ]) {
    assert.throws(() => parseRepoUrl(url), undefined, `expected ${url} to be rejected`);
  }
});

test('safeEntryPath blocks zip slip and absolute paths', () => {
  const root = '/tmp/scan/source';
  assert.equal(safeEntryPath(root, 'app/index.js'), '/tmp/scan/source/app/index.js');
  assert.equal(safeEntryPath(root, '../../etc/passwd'), null);
  assert.equal(safeEntryPath(root, 'a/../../b'), null);
  assert.equal(safeEntryPath(root, '/etc/passwd'), null);
  assert.equal(safeEntryPath(root, 'C:/Windows/system32'), null);
  assert.equal(safeEntryPath(root, '..\\..\\evil.txt'), null);
  assert.equal(safeEntryPath(root, ''), null);
});
