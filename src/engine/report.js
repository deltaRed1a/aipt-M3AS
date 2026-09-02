function bullets(items, fallback = '_Not provided_') {
  if (!items || items.length === 0) return fallback;
  return items.map((item) => `- ${item}`).join('\n');
}

function codeBlock(code) {
  return code ? `\n\`\`\`\n${code}\n\`\`\`\n` : '\n_Not provided_\n';
}

export function severityCounts(findings) {
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 };
  for (const finding of findings) {
    counts[finding.severity] = (counts[finding.severity] ?? 0) + 1;
  }
  return counts;
}

/**
 * Renders the consolidated master finding list in the required report format.
 */
export function renderMarkdownReport(scan) {
  const findings = scan.findings ?? [];
  const counts = severityCounts(findings);
  const lines = [];
  lines.push(`# M3AS Security & RAI Audit - ${scan.targetName}`);
  lines.push('');
  lines.push(`- Scan ID: \`${scan.id}\``);
  lines.push(`- Source: ${scan.source.type} (${scan.source.reference})`);
  lines.push(`- Started: ${scan.createdAt}`);
  lines.push(`- Auditor models: ${scan.models.map((model) => `${model.label} (${model.status})`).join(', ')}`);
  lines.push(`- Consolidated by: ${scan.consolidation?.label ?? 'n/a'} (${scan.consolidation?.method ?? 'n/a'})`);
  lines.push('');
  lines.push('## Summary');
  lines.push('');
  lines.push('| Severity | Count |');
  lines.push('| --- | --- |');
  for (const [severity, count] of Object.entries(counts)) {
    lines.push(`| ${severity} | ${count} |`);
  }
  lines.push(`| **Total unique findings** | **${findings.length}** |`);
  lines.push('');

  findings.forEach((finding, index) => {
    lines.push(`## ${index + 1}. ${finding.title}`);
    lines.push('');
    lines.push('**Finding Description**');
    lines.push('');
    lines.push(finding.findingDescription || '_Not provided_');
    lines.push('');
    lines.push('**Steps to Reproduce**');
    lines.push('');
    lines.push(bullets(finding.stepsToReproduce));
    lines.push('');
    lines.push(`**Severity:** ${finding.severity}`);
    lines.push('');
    lines.push(`**Impact level:** ${finding.impactLevel}`);
    lines.push('');
    lines.push(`**CVSS 3.1 Vector:** ${finding.cvssVector || '_Not provided_'} (${finding.cvssScore})`);
    lines.push('');
    lines.push(`**MITRE ATT&CK® v15.1:** ${finding.mitreAttack.join(', ') || '_Not provided_'}`);
    lines.push('');
    lines.push(`**MITRE ATLAS™ v4.7:** ${finding.mitreAtlas.join(', ') || '_Not provided_'}`);
    lines.push('');
    lines.push(`**CWE:** ${finding.cwe.join(', ') || '_Not provided_'}`);
    lines.push('');
    lines.push(
      `**Target Description:** ${finding.target.file || 'unknown'}${finding.target.line ? `:${finding.target.line}` : ''}${finding.target.location ? ` - ${finding.target.location}` : ''}`,
    );
    lines.push('');
    lines.push('**Impact**');
    lines.push('');
    lines.push(bullets(finding.impact));
    lines.push('');
    lines.push('**Recommendation**');
    lines.push('');
    lines.push('Insecure code:');
    lines.push(codeBlock(finding.recommendation.insecureSnippet));
    lines.push('Recommended secure code:');
    lines.push(codeBlock(finding.recommendation.secureSnippet));
    if (finding.recommendation.notes) {
      lines.push(finding.recommendation.notes);
      lines.push('');
    }
    lines.push('**Mitigations**');
    lines.push('');
    lines.push(bullets(finding.mitigations));
    lines.push('');
    lines.push('**Additional Information**');
    lines.push('');
    lines.push(bullets(finding.additionalInformation.map((link) => `[${link}](${link})`)));
    lines.push('');
    lines.push(`_Reported by: ${finding.reportedBy.join(', ') || 'n/a'}${finding.confirmation ? ` | ${finding.confirmation}` : ''}_`);
    lines.push('');
  });

  return lines.join('\n');
}
