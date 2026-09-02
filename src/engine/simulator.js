import fs from 'node:fs/promises';
import path from 'node:path';

/**
 * Offline heuristics used by the "simulate" engine (M3AS_ENGINE=simulate).
 * They let the whole pipeline - ingestion, per-model audit, consolidation and
 * reporting - run end to end without the Copilot CLI (demos, CI and tests).
 */
const RULES = [
  {
    pattern: /\beval\s*\(/,
    title: 'Unsafe dynamic code evaluation',
    severity: 'Critical',
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    cvssScore: 9.8,
    cwe: ['CWE-95'],
    attack: ['T1059 - Command and Scripting Interpreter'],
    atlas: ['AML.T0050 - Command and Scripting Interpreter'],
    secure: 'JSON.parse(untrustedInput)',
    link: 'https://cwe.mitre.org/data/definitions/95.html',
  },
  {
    pattern: /child_process[\s\S]{0,40}\bexec\s*\(|\bos\.system\s*\(/,
    title: 'Potential OS command injection',
    severity: 'High',
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
    cvssScore: 8.8,
    cwe: ['CWE-78'],
    attack: ['T1059 - Command and Scripting Interpreter'],
    atlas: ['AML.T0050 - Command and Scripting Interpreter'],
    secure: 'spawn(bin, args, { shell: false })',
    link: 'https://owasp.org/www-community/attacks/Command_Injection',
  },
  {
    pattern: /(password|secret|api[_-]?key|token)\s*[:=]\s*['"][^'"\s]{8,}['"]/i,
    title: 'Hardcoded credential in source code',
    severity: 'High',
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    cvssScore: 7.5,
    cwe: ['CWE-798'],
    attack: ['T1552 - Unsecured Credentials'],
    atlas: ['AML.T0055 - Unsecured Credentials'],
    secure: 'const apiKey = process.env.API_KEY;',
    link: 'https://cwe.mitre.org/data/definitions/798.html',
  },
  {
    pattern: /createHash\(\s*['"](md5|sha1)['"]\s*\)|hashlib\.(md5|sha1)\s*\(/,
    title: 'Use of a broken cryptographic hash function',
    severity: 'Medium',
    cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N',
    cvssScore: 4.8,
    cwe: ['CWE-327'],
    attack: ['T1553 - Subvert Trust Controls'],
    atlas: ['AML.T0043 - Craft Adversarial Data'],
    secure: "createHash('sha256')",
    link: 'https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure',
  },
  {
    pattern: /verify\s*=\s*False|rejectUnauthorized\s*:\s*false/,
    title: 'TLS certificate validation disabled',
    severity: 'High',
    cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N',
    cvssScore: 7.4,
    cwe: ['CWE-295'],
    attack: ['T1557 - Adversary-in-the-Middle'],
    atlas: ['AML.T0040 - ML Model Inference API Access'],
    secure: 'rejectUnauthorized: true',
    link: 'https://cwe.mitre.org/data/definitions/295.html',
  },
  {
    pattern: /(prompt|system_prompt|systemPrompt)\s*[+=]\s*.*(userInput|user_input|req\.body)/,
    title: 'Unsanitized user input concatenated into an LLM prompt (RAI / prompt injection)',
    severity: 'High',
    category: 'rai',
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N',
    cvssScore: 8.5,
    cwe: ['CWE-1427'],
    attack: ['T1059 - Command and Scripting Interpreter'],
    atlas: ['AML.T0051 - LLM Prompt Injection'],
    secure: 'Pass user content as clearly delimited untrusted data, never as instructions.',
    link: 'https://owasp.org/www-project-top-10-for-large-language-model-applications/',
  },
];

const SKIP_DIRS = new Set(['.git', 'node_modules', 'dist', 'build', 'vendor', '.venv', '__pycache__']);
const MAX_FILES = 400;
const MAX_FILE_BYTES = 512 * 1024;

async function collectFiles(root) {
  const files = [];
  const queue = [root];
  while (queue.length > 0 && files.length < MAX_FILES) {
    const dir = queue.shift();
    let entries = [];
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) queue.push(full);
      } else if (entry.isFile()) {
        files.push(full);
        if (files.length >= MAX_FILES) break;
      }
    }
  }
  return files;
}

function hashString(value) {
  let hash = 0;
  for (const char of value) hash = (hash * 31 + char.charCodeAt(0)) % 100000;
  return hash;
}

export async function simulateModelResponse({ model, cwd }) {
  const files = await collectFiles(cwd);
  const findings = [];
  for (const file of files) {
    let content = '';
    try {
      const stat = await fs.stat(file);
      if (stat.size > MAX_FILE_BYTES) continue;
      content = await fs.readFile(file, 'utf8');
    } catch {
      continue;
    }
    const lines = content.split('\n');
    for (const rule of RULES) {
      const index = lines.findIndex((line) => rule.pattern.test(line));
      if (index === -1) continue;
      const relative = path.relative(cwd, file);
      // Each model reports a slightly different subset so that the consolidation
      // pass has both overlapping duplicates and unique findings to reconcile.
      if ((hashString(model.id + relative + rule.title) % 10) === 0) continue;
      findings.push({
        title: rule.title,
        findingDescription: `${rule.title} detected in ${relative} by ${model.label} (offline heuristic engine).`,
        stepsToReproduce: [`Open ${relative}`, `Inspect line ${index + 1}`, 'Trigger the code path with attacker-controlled input'],
        severity: rule.severity,
        impactLevel: rule.severity,
        cvssVector: rule.cvssVector,
        cvssScore: rule.cvssScore,
        mitreAttack: rule.attack,
        mitreAtlas: rule.atlas,
        cwe: rule.cwe,
        category: rule.category ?? 'security',
        target: { file: relative, line: index + 1, location: lines[index].trim().slice(0, 160) },
        impact: [
          'An attacker may influence application behaviour beyond intended limits.',
          'Confidentiality and integrity of processed data may be lost.',
          'Downstream systems trusting this component inherit the risk.',
        ],
        recommendation: {
          insecureSnippet: lines[index].trim().slice(0, 240),
          secureSnippet: rule.secure,
          notes: 'Validate and constrain untrusted input, and prefer safe platform APIs.',
        },
        mitigations: [
          'Add input validation and output encoding on the affected path.',
          'Apply least privilege to the executing component.',
          'Add regression tests and static analysis rules for this pattern.',
        ],
        additionalInformation: [rule.link],
      });
    }
  }
  return `\`\`\`json\n${JSON.stringify({ findings }, null, 2)}\n\`\`\``;
}
