const state = { cases: [], currentCase: null, currentEvidence: null, bundle: null };
let caseDialogBusy = false;
let uploadBusy = false;

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

async function api(path, options = {}) {
  let response;
  try {
    response = await fetch(path, options);
  } catch (error) {
    setApiState(false);
    throw new Error(error.name === 'AbortError' ? 'Request cancelled' : 'The local engine is unreachable');
  }

  let body = {};
  try {
    body = await response.json();
  } catch (_) {
    // Binary downloads and empty responses do not contain JSON.
  }
  if (!response.ok) {
    throw new Error(body.error || `Request failed (${response.status})`);
  }
  setApiState(true);
  return body;
}

function setApiState(online) {
  const label = $('#api-label');
  const indicator = $('.api-state i');
  if (!label || !indicator) return;
  label.textContent = online ? 'Local engine online' : 'Engine unavailable';
  indicator.style.background = online ? '#43b7a6' : '#c55353';
}

function toast(message, error = false) {
  const node = $('#toast');
  if (!node) return;
  node.textContent = message;
  node.className = `toast show${error ? ' error' : ''}`;
  window.clearTimeout(toast.timer);
  toast.timer = window.setTimeout(() => { node.className = 'toast'; }, 3600);
}

function bytes(value) {
  if (value === 0) return '0 B';
  if (!value) return '—';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let number = value;
  let index = 0;
  while (number >= 1024 && index < units.length - 1) {
    number /= 1024;
    index += 1;
  }
  return `${number >= 100 || index === 0 ? Math.round(number) : number.toFixed(1)} ${units[index]}`;
}

function date(value) {
  if (!value) return '—';
  try {
    return new Date(value).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });
  } catch (_) {
    return value;
  }
}

function esc(value) {
  const node = document.createElement('span');
  node.textContent = value ?? '';
  return node.innerHTML;
}

function currentCaseId() {
  return state.currentCase?.id || '';
}

function selectedMode() {
  return document.querySelector('input[name="mode"]:checked')?.value || 'normal';
}

function showView(view) {
  const target = $(`#view-${view}`);
  if (!target) return;
  $$('.view').forEach((node) => node.classList.remove('active-view'));
  target.classList.add('active-view');
  $$('.nav-item').forEach((node) => node.classList.toggle('active', node.dataset.view === view));
  const labels = { overview: 'Overview', acquisition: 'Acquire evidence', analysis: 'Analyze & recover', reports: 'Reports & custody' };
  $('#crumb').textContent = labels[view] || 'Overview';
}

function renderCases() {
  const list = $('#cases-list');
  $('#case-count').textContent = `${state.cases.length} CASE${state.cases.length === 1 ? '' : 'S'}`;
  $('#metric-cases').textContent = state.cases.length;
  const evidenceCount = state.cases.reduce((sum, item) => sum + Number(item.evidence_count || 0), 0);
  const segmentCount = state.cases.reduce((sum, item) => sum + Number(item.segment_count || 0), 0);
  $('#metric-evidence').textContent = evidenceCount;
  $('#metric-segments').textContent = segmentCount;
  $('#metric-chains').textContent = state.cases.length ? '✓' : '—';

  if (!state.cases.length) {
    list.innerHTML = '<div class="empty-state"><div class="empty-icon">◌</div><strong>No examinations yet</strong><span>Create a case to begin a preserved workflow.</span></div>';
    return;
  }

  list.innerHTML = state.cases.map((item) => `<div class="case-row ${currentCaseId() === item.id ? 'selected' : ''}" data-case="${esc(item.id)}">
    <div class="case-info"><div class="case-title">${esc(item.title)}</div><div class="case-id">${esc(item.id)} · ${esc(item.status || 'open').toUpperCase()}</div></div>
    <div class="case-stats"><div class="case-stat"><strong>${item.evidence_count || 0}</strong><small>SOURCES</small></div><div class="case-stat"><strong>${item.segment_count || 0}</strong><small>RANGES</small></div></div><div class="case-time">${date(item.created_at)}</div></div>`).join('');
  $$('.case-row').forEach((row) => row.addEventListener('click', () => selectCase(row.dataset.case)));
}

async function loadCases() {
  state.cases = (await api('/api/cases')).cases || [];
  renderCases();
}

async function selectCase(id, options = {}) {
  try {
    const previousCaseId = currentCaseId();
    const preserveEvidenceId = options.evidenceId || (previousCaseId === id ? state.currentEvidence?.id : null);
    state.bundle = await api(`/api/cases/${encodeURIComponent(id)}`);
    state.currentCase = state.bundle.case;
    const evidence = state.bundle.evidence || [];
    state.currentEvidence = evidence.find((item) => item.id === preserveEvidenceId) || evidence[0] || null;
    $('#rail-case').textContent = `${state.currentCase.id} · ${state.currentCase.title}`;
    $('#rail-status').innerHTML = '<i></i> Case active';
    $('#rail-status').style.color = '#70cfc7';
    renderCases();
    renderAll();
    if (options.announce !== false) toast(`Loaded ${state.currentCase.id}`);
  } catch (error) {
    toast(error.message, true);
  }
}

async function refreshSelectedCase(evidenceId = null) {
  if (!currentCaseId()) return;
  await loadCases();
  await selectCase(currentCaseId(), { evidenceId, announce: false });
}

function renderAll() {
  renderAcquisition();
  renderAnalysis();
  renderReports();
}

function renderAcquisition() {
  const active = !!state.currentCase;
  $('#acquisition-gate').style.display = active ? 'none' : 'flex';
  $('#evidence-case-hint').textContent = active ? `${state.currentCase.id} · ${state.currentCase.title}` : 'Select a case to view its source inventory.';
  const list = $('#evidence-list');
  const evidence = state.bundle?.evidence || [];

  if (!evidence.length) {
    list.innerHTML = `<div class="empty-state compact"><span>${active ? 'No source acquired for this case.' : 'No source selected.'}</span></div>`;
    return;
  }

  list.innerHTML = evidence.map((item) => `<div class="evidence-row ${state.currentEvidence?.id === item.id ? 'selected' : ''}" data-evidence="${esc(item.id)}"><div class="evidence-file-icon">▣</div><div class="evidence-main"><div class="evidence-name">${esc(item.original_name)}</div><div class="evidence-meta">${esc(item.id)} · ${bytes(item.size)} · acquired ${date(item.acquired_at)}</div></div><div class="evidence-hash">${esc(item.sha256)}</div><div class="hash-ok">✓ HASHED</div></div>`).join('');
  $$('.evidence-row').forEach((row) => row.addEventListener('click', () => {
    state.currentEvidence = evidence.find((item) => item.id === row.dataset.evidence) || null;
    renderAll();
  }));
}

function renderAnalysis() {
  const evidence = state.bundle?.evidence || [];
  const active = !!state.currentCase && evidence.length > 0;
  $('#analysis-gate').style.display = active ? 'none' : 'flex';
  $('#identify-button').disabled = !active;
  $('#recover-button').disabled = !active;
  $('#segment-count').textContent = '0 RANGES';
  const list = $('#analysis-evidence-list');

  if (!evidence.length) {
    list.innerHTML = '<div class="empty-state compact"><span>No acquired evidence.</span></div>';
    $('#identity-result').innerHTML = '<div class="empty-state compact"><span>Acquire a source first.</span></div>';
    $('#segments-list').innerHTML = '<div class="empty-state compact"><span>No recovered ranges.</span></div>';
    return;
  }

  if (!state.currentEvidence || !evidence.some((item) => item.id === state.currentEvidence.id)) {
    state.currentEvidence = evidence[0];
  }
  list.innerHTML = evidence.map((item) => `<div class="analysis-evidence-row ${state.currentEvidence?.id === item.id ? 'selected' : ''}" data-evidence="${esc(item.id)}"><span class="source-dot"></span><div class="source-label"><strong>${esc(item.original_name)}</strong><small>${esc(item.id)} · ${bytes(item.size)}</small></div></div>`).join('');
  $$('.analysis-evidence-row').forEach((row) => row.addEventListener('click', () => {
    state.currentEvidence = evidence.find((item) => item.id === row.dataset.evidence) || null;
    renderAnalysis();
  }));

  const identity = state.currentEvidence?.identification;
  if (!identity) {
    $('#identity-result').innerHTML = '<div class="identity-empty">No identification run for this source. The engine will scan bounded signatures when you run it.</div>';
  } else {
    const primary = identity.hits?.find((hit) => hit.vendor === identity.primary_vendor) || identity.hits?.[0] || {};
    const chips = (identity.hits || []).map((hit) => `<span class="hit-chip">${esc(hit.display_name)} <em>${Math.round((hit.confidence || 0) * 100)}%</em></span>`).join('');
    const limitation = (primary.limitations || [])[0] || 'Interpretation remains bounded to the observed signatures.';
    $('#identity-result').innerHTML = `<div class="identity-main"><div class="vendor-logo">⌁</div><div><strong>${esc(primary.display_name || identity.primary_vendor)}</strong><small>${esc(primary.filesystem || 'unidentified')} · route ${esc(primary.route || 'generic')}</small></div><div class="confidence"><b>${Math.round((identity.confidence || 0) * 100)}%</b><small>CONFIDENCE</small></div></div><div class="hit-list">${chips || '<span class="hit-chip">No specific signature</span>'}</div><div class="limitation">${esc(limitation)}</div>`;
  }

  const segments = state.currentEvidence?.segments || [];
  $('#segment-count').textContent = `${segments.length} RANGE${segments.length === 1 ? '' : 'S'}`;
  const segList = $('#segments-list');
  if (!segments.length) {
    segList.innerHTML = '<div class="empty-state compact"><div class="empty-icon">⌁</div><span>Run recovery to populate the evidence timeline.</span></div>';
    return;
  }
  segList.innerHTML = segments.map((seg, index) => `<div class="segment-row"><div class="segment-index">RANGE ${String(index + 1).padStart(2, '0')}</div><div class="segment-title">${esc(seg.codec)} · ${esc(seg.state)}<small>${esc(seg.source)} · ${bytes(seg.size)} · offset 0x${Number(seg.start_offset).toString(16).toUpperCase()}</small></div><div class="segment-facts"><strong>${Math.round((seg.confidence || 0) * 100)}%</strong><small>${esc(seg.recovery_mode)}</small></div><div class="segment-actions"><a class="tiny-link" href="/api/segments/${encodeURIComponent(seg.id)}/export?format=native">↓ Native bytes</a><a class="tiny-link" href="/api/segments/${encodeURIComponent(seg.id)}/export?format=mp4">▶ MP4 if ffmpeg</a></div></div>`).join('');
}

function renderReports() {
  const active = !!state.currentCase;
  $('#report-gate').style.display = active ? 'none' : 'flex';
  $('#generate-report').disabled = !active;
  $('#report-case-label').textContent = active ? `${state.currentCase.id} · ${state.currentCase.title}` : 'No case selected';
  // Links are case-specific. Clear them whenever the selected case or bundle changes.
  $('#report-links').innerHTML = '';
  const chain = state.bundle?.chain;
  const chainNode = $('#report-chain');

  if (!chain) {
    chainNode.className = 'report-chain';
    chainNode.innerHTML = '<i></i> Awaiting case';
    $('#report-summary').innerHTML = '<div class="empty-state compact"><span>Generate a report after acquiring or analyzing evidence.</span></div>';
    $('#audit-list').innerHTML = '<div class="empty-state compact"><span>No case selected.</span></div>';
    return;
  }

  chainNode.className = `report-chain ${chain.valid ? 'valid' : 'invalid'}`;
  chainNode.innerHTML = `<i></i> ${chain.valid ? 'Chain verified' : 'Chain broken'}`;
  const evidence = state.bundle.evidence || [];
  const ranges = evidence.reduce((sum, item) => sum + (item.segments || []).length, 0);
  $('#report-summary').innerHTML = `<div class="summary-grid"><div class="summary-cell"><b>${evidence.length}</b><span>SOURCES</span></div><div class="summary-cell"><b>${ranges}</b><span>RECOVERED RANGES</span></div><div class="summary-cell"><b>${chain.event_count || 0}</b><span>AUDIT EVENTS</span></div></div>`;
  const events = state.bundle.audit || [];
  $('#audit-list').innerHTML = events.length ? events.map((event) => `<div class="audit-row"><div class="audit-id">#${event.id}</div><div class="audit-body"><strong>${esc(event.action.replaceAll('_', ' '))}</strong><small>${date(event.occurred_at)} · ${esc(event.actor)}</small><div class="audit-hash">${esc(event.event_hash)}</div></div></div>`).join('') : '<div class="empty-state compact"><span>No events.</span></div>';
}

function resetCaseDialog() {
  $('#case-form')?.reset();
  caseDialogBusy = false;
  const submit = $('#submit-case');
  if (submit) {
    submit.disabled = false;
    submit.textContent = 'Create case';
  }
}

function closeCaseDialog() {
  const dialog = $('#case-dialog');
  if (dialog?.open) dialog.close('cancel');
  resetCaseDialog();
}

function openCaseDialog() {
  const dialog = $('#case-dialog');
  if (!dialog || dialog.open) return;
  resetCaseDialog();
  dialog.showModal();
  $('#case-title').focus();
}

async function createCase(event) {
  event.preventDefault();
  if (caseDialogBusy) return;
  const titleInput = $('#case-title');
  const title = titleInput.value.trim();
  if (!title) {
    titleInput.focus();
    titleInput.reportValidity();
    return;
  }

  caseDialogBusy = true;
  const submit = $('#submit-case');
  submit.disabled = true;
  submit.textContent = 'Creating…';
  try {
    const created = await api('/api/cases', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        title,
        investigator: $('#case-investigator').value.trim(),
        notes: $('#case-notes').value.trim(),
      }),
    });
    closeCaseDialog();
    await loadCases();
    await selectCase(created.id, { announce: false });
    showView('acquisition');
    toast('Examination created');
  } catch (error) {
    toast(error.message, true);
    caseDialogBusy = false;
    submit.disabled = false;
    submit.textContent = 'Create case';
  }
}

async function upload(file) {
  if (uploadBusy) return;
  if (!state.currentCase) {
    toast('Select a case before acquiring evidence', true);
    return;
  }
  uploadBusy = true;
  const progress = $('#upload-progress');
  progress.classList.add('visible');
  $('#upload-name').textContent = file.name;
  $('#upload-percent').textContent = 'Uploading…';
  $('#upload-bar').style.width = '8%';
  try {
    const item = await api(`/api/cases/${encodeURIComponent(currentCaseId())}/evidence`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream', 'X-Filename': file.name },
      body: file,
    });
    $('#upload-bar').style.width = '100%';
    $('#upload-percent').textContent = '100%';
    await refreshSelectedCase(item.id);
    toast(`Acquired ${item.id}`);
  } catch (error) {
    $('#upload-bar').style.width = '0%';
    $('#upload-percent').textContent = 'Upload failed';
    toast(error.message, true);
  } finally {
    uploadBusy = false;
    window.setTimeout(() => progress.classList.remove('visible'), 800);
  }
}

async function identify() {
  if (!state.currentEvidence) return;
  const evidenceId = state.currentEvidence.id;
  const button = $('#identify-button');
  button.disabled = true;
  button.textContent = 'Scanning…';
  try {
    await api(`/api/evidence/${encodeURIComponent(evidenceId)}/identify`, { method: 'POST' });
    await refreshSelectedCase(evidenceId);
    showView('analysis');
    toast('Recorder identification complete');
  } catch (error) {
    toast(error.message, true);
  } finally {
    button.textContent = 'Run identification';
    button.disabled = false;
  }
}

async function recover() {
  if (!state.currentEvidence) return;
  const evidenceId = state.currentEvidence.id;
  const button = $('#recover-button');
  button.disabled = true;
  button.innerHTML = 'Scanning source…';
  try {
    const result = await api(`/api/evidence/${encodeURIComponent(evidenceId)}/recover`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: selectedMode() }),
    });
    await refreshSelectedCase(evidenceId);
    showView('analysis');
    toast(`Recovery complete · ${result.segment_count} range${result.segment_count === 1 ? '' : 's'}`);
  } catch (error) {
    toast(error.message, true);
  } finally {
    button.innerHTML = 'Run recovery scan <span>→</span>';
    button.disabled = false;
  }
}

async function generateReport() {
  if (!state.currentCase) return;
  const caseId = currentCaseId();
  const button = $('#generate-report');
  button.disabled = true;
  button.textContent = 'Building…';
  try {
    await api(`/api/cases/${encodeURIComponent(caseId)}/report`, { method: 'POST' });
    await refreshSelectedCase();
    $('#report-links').innerHTML = `<a href="/api/cases/${encodeURIComponent(caseId)}/report.html" target="_blank" rel="noopener">View HTML report ↗</a><a href="/api/cases/${encodeURIComponent(caseId)}/report.pdf">Download PDF ↓</a><a href="/api/cases/${encodeURIComponent(caseId)}/report.json">Download JSON ↓</a>`;
    toast('Report package generated');
  } catch (error) {
    toast(error.message, true);
  } finally {
    button.textContent = 'Generate report';
    button.disabled = false;
  }
}

function wire() {
  $$('.nav-item').forEach((button) => button.addEventListener('click', () => showView(button.dataset.view)));
  $('#new-case').addEventListener('click', openCaseDialog);
  $('#case-form').addEventListener('submit', createCase);
  $('#cancel-case-dialog').addEventListener('click', closeCaseDialog);
  $('#close-case-dialog').addEventListener('click', closeCaseDialog);
  $('#case-dialog').addEventListener('close', resetCaseDialog);
  $('#refresh').addEventListener('click', async () => {
    try {
      await refreshSelectedCase();
      toast('Workspace refreshed');
    } catch (error) {
      toast(error.message, true);
    }
  });

  $('#file-input').addEventListener('change', (event) => {
    const file = event.target.files[0];
    if (file) upload(file);
    event.target.value = '';
  });
  const drop = $('#drop-zone');
  ['dragenter', 'dragover'].forEach((name) => drop.addEventListener(name, (event) => {
    event.preventDefault();
    drop.classList.add('dragging');
  }));
  ['dragleave', 'drop'].forEach((name) => drop.addEventListener(name, (event) => {
    event.preventDefault();
    drop.classList.remove('dragging');
  }));
  drop.addEventListener('drop', (event) => {
    const file = event.dataTransfer.files[0];
    if (file) upload(file);
  });

  $('#identify-button').addEventListener('click', identify);
  $('#recover-button').addEventListener('click', recover);
  $('#generate-report').addEventListener('click', generateReport);
  $$('input[name="mode"]').forEach((input) => input.addEventListener('change', () => $$('.mode-option').forEach((node) => node.classList.toggle('selected', node.querySelector('input').checked))));
}

(async function init() {
  wire();
  try {
    const health = await api('/api/health');
    $('#version').textContent = `v${health.version}`;
    await loadCases();
  } catch (error) {
    setApiState(false);
    toast(error.message, true);
  }
  renderAll();
}());
