import assert from 'node:assert/strict';
import test from 'node:test';
import { extractJson, mergeFindings, normalizeFinding, parseFindings } from '../src/engine/findings.js';

test('extractJson reads a fenced json block', () => {
  const parsed = extractJson('Sure!\n```json\n{"findings":[]}\n```\nDone.');
  assert.deepEqual(parsed, { findings: [] });
});

test('extractJson falls back to embedded json', () => {
  assert.deepEqual(extractJson('noise {"findings": [{"title": "x"}]} tail').findings[0].title, 'x');
  assert.equal(extractJson('no json here'), null);
});

test('normalizeFinding fills every required report field', () => {
  const finding = normalizeFinding({ title: 'SQLi', severity: 'high', cvssScore: '9.81' }, 'gpt-5.5');
  assert.equal(finding.severity, 'High');
  assert.equal(finding.cvssScore, 9.8);
  assert.deepEqual(finding.reportedBy, ['gpt-5.5']);
  assert.deepEqual(finding.impact, []);
  assert.equal(finding.category, 'security');
  assert.ok(finding.id.length === 12);
});

test('normalizeFinding clamps unknown severity and score', () => {
  const finding = normalizeFinding({ title: 'x', severity: 'bogus', cvssScore: 42 });
  assert.equal(finding.severity, 'Informational');
  assert.equal(finding.cvssScore, 10);
});

test('parseFindings returns an empty list for unusable output', () => {
  assert.deepEqual(parseFindings('the model refused', 'm'), []);
});

test('mergeFindings de-duplicates across models and keeps attribution', () => {
  const base = { title: 'Command injection', target: { file: 'src/a.js', line: 10 }, cwe: ['CWE-78'] };
  const merged = mergeFindings([
    { modelId: 'model-a', findings: [normalizeFinding({ ...base, cvssScore: 7.5, severity: 'High' }, 'model-a')] },
    { modelId: 'model-b', findings: [normalizeFinding({ ...base, cvssScore: 9.1, severity: 'Critical', mitigations: ['Use spawn'] }, 'model-b')] },
    { modelId: 'model-c', findings: [normalizeFinding({ title: 'Weak hash', target: { file: 'src/b.js', line: 3 }, cvssScore: 4.8 }, 'model-c')] },
  ]);
  assert.equal(merged.length, 2);
  assert.equal(merged[0].cvssScore, 9.1);
  assert.equal(merged[0].severity, 'Critical');
  assert.deepEqual(merged[0].reportedBy.sort(), ['model-a', 'model-b']);
  assert.deepEqual(merged[0].mitigations, ['Use spawn']);
});
