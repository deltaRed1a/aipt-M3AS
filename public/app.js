const els = {
  engineBadge: document.getElementById('engine-badge'),
  modelList: document.getElementById('model-list'),
  consolidator: document.getElementById('consolidator'),
  repoForm: document.getElementById('repo-form'),
  zipForm: document.getElementById('zip-form'),
  repoUrl: document.getElementById('repo-url'),
  formError: document.getElementById('form-error'),
  status: document.getElementById('scan-status'),
  target: document.getElementById('scan-target'),
  progress: document.getElementById('progress-list'),
  summary: document.getElementById('summary'),
  findings: document.getElementById('findings'),
  download: document.getElementById('download-report'),
};

const PLACEHOLDERS = {
  github: 'https://github.com/org/repo',
  ado: 'https://dev.azure.com/org/project/_git/repo',
};

let eventSource = null;

function el(tag, props = {}, children = []) {
  const node = document.createElement(tag);
  Object.assign(node, props);
  for (const child of [].concat(children)) {
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function showError(message) {
  els.formError.textContent = message;
  els.formError.hidden = !message;
}

function selectedModels() {
  return [...els.modelList.querySelectorAll('input[type=checkbox]:checked')].map((input) => input.value);
}

async function loadModels() {
  const response = await fetch('/api/models');
  const data = await response.json();
  els.engineBadge.textContent = `engine: ${data.engine}`;
  els.modelList.replaceChildren(
    ...data.auditors.map((model) =>
      el('li', {}, [
        el('label', {}, [
          Object.assign(document.createElement('input'), {
            type: 'checkbox',
            value: model.id,
            checked: model.enabled,
            disabled: !model.enabled,
          }),
          model.label,
        ]),
        el('span', { className: 'chip' }, `${model.contextWindow} · ${model.reasoning}`),
      ]),
    ),
  );
  els.consolidator.replaceChildren(
    el('span', { className: 'chip' }, `consolidator: ${data.consolidator.label} · ${data.consolidator.contextWindow} · ${data.consolidator.reasoning}`),
  );
}

function renderProgress(scan) {
  els.status.textContent = scan.status;
  els.target.textContent = `${scan.source.type} · ${scan.source.reference}${scan.error ? ` · ${scan.error}` : ''}`;
  els.progress.replaceChildren(
    ...scan.models.map((model) =>
      el('li', {}, [
        el('span', {}, `${model.label} (${model.contextWindow} · ${model.reasoning})`),
        el('span', { className: `state-${model.status}` }, model.error ? `failed: ${model.error}` : `${model.status} · ${model.findingCount} findings`),
      ]),
    ),
    el('li', {}, [
      el('span', {}, `${scan.consolidation.label} — consolidation`),
      el('span', { className: `state-${scan.consolidation.status}` }, scan.consolidation.warning ?? scan.consolidation.status),
    ]),
  );
}

function section(title, node) {
  return [el('h4', {}, title), node];
}

function list(items) {
  return el('ul', {}, (items ?? []).map((item) => el('li', {}, item)));
}

function renderFindings(scan) {
  els.summary.replaceChildren(
    ...Object.entries(scan.summary ?? {}).map(([severity, count]) =>
      el('span', { className: `chip ${severity}` }, `${severity}: ${count}`),
    ),
  );
  els.findings.replaceChildren(
    ...(scan.findings ?? []).map((finding) => {
      const body = el('div', { className: 'body' }, [
        el('p', {}, finding.findingDescription),
        ...section('Steps to Reproduce', list(finding.stepsToReproduce)),
        ...section('Severity / Impact level', el('p', {}, `${finding.severity} / ${finding.impactLevel}`)),
        ...section('CVSS 3.1', el('p', {}, `${finding.cvssVector} (${finding.cvssScore})`)),
        ...section('MITRE ATT&CK v15.1', list(finding.mitreAttack)),
        ...section('MITRE ATLAS v4.7', list(finding.mitreAtlas)),
        ...section('CWE', el('p', {}, finding.cwe.join(', '))),
        ...section(
          'Target Description',
          el('p', {}, `${finding.target.file}${finding.target.line ? `:${finding.target.line}` : ''} ${finding.target.location}`),
        ),
        ...section('Impact', list(finding.impact)),
        ...section('Recommendation — insecure code', el('pre', {}, finding.recommendation.insecureSnippet)),
        ...section('Recommendation — secure code', el('pre', {}, finding.recommendation.secureSnippet)),
        ...section('Mitigations', list(finding.mitigations)),
        ...section(
          'Additional Information',
          el('ul', {}, (finding.additionalInformation ?? []).map((link) => el('li', {}, [el('a', { href: link, rel: 'noopener noreferrer', target: '_blank' }, link)]))),
        ),
        el('p', { className: 'muted small' }, `Reported by: ${finding.reportedBy.join(', ')}${finding.confirmation ? ` · ${finding.confirmation}` : ''}`),
      ]);
      return el('details', { className: `finding sev-${finding.severity}` }, [
        el('summary', {}, [
          el('span', { className: `chip ${finding.severity}` }, finding.severity),
          el('strong', {}, finding.title),
          el('span', { className: 'muted small' }, `${finding.target.file}${finding.target.line ? `:${finding.target.line}` : ''}`),
        ]),
        body,
      ]);
    }),
  );
  if (scan.hasReport) {
    els.download.href = `/api/scans/${scan.id}/report`;
    els.download.classList.remove('hidden');
  }
}

function track(scan) {
  renderProgress(scan);
  renderFindings(scan);
  eventSource?.close();
  eventSource = new EventSource(`/api/scans/${scan.id}/events`);
  eventSource.onmessage = (event) => {
    const updated = JSON.parse(event.data);
    renderProgress(updated);
    renderFindings(updated);
  };
  eventSource.onerror = () => eventSource.close();
}

async function submitScan(url, body, isForm) {
  showError('');
  els.download.classList.add('hidden');
  const response = await fetch(url, isForm ? { method: 'POST', body } : {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const data = await response.json();
  if (!response.ok) {
    showError(data.error ?? 'Scan could not be started');
    return;
  }
  track(data);
}

document.querySelectorAll('.tab').forEach((tab) => {
  tab.addEventListener('click', () => {
    const target = tab.dataset.tab;
    document.querySelectorAll('.tab').forEach((other) => {
      const active = other === tab;
      other.classList.toggle('active', active);
      other.setAttribute('aria-selected', String(active));
    });
    els.repoForm.classList.toggle('hidden', target === 'zip');
    els.zipForm.classList.toggle('hidden', target !== 'zip');
    if (target !== 'zip') els.repoUrl.placeholder = PLACEHOLDERS[target];
  });
});

els.repoForm.addEventListener('submit', (event) => {
  event.preventDefault();
  const form = new FormData(els.repoForm);
  submitScan('/api/scans/repo', {
    repoUrl: form.get('repoUrl'),
    branch: form.get('branch') || undefined,
    models: selectedModels(),
  }, false);
});

els.zipForm.addEventListener('submit', (event) => {
  event.preventDefault();
  const form = new FormData(els.zipForm);
  if (!form.get('targetName')) form.delete('targetName');
  for (const id of selectedModels()) form.append('models', id);
  submitScan('/api/scans/zip', form, true);
});

loadModels().catch(() => showError('Unable to load the model registry'));
