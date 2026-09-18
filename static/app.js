const state = { cases: [], currentCase: null, currentEvidence: null, bundle: null };
const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

async function api(path, options = {}) {
  const response = await fetch(path, options);
  let body = {};
  try { body = await response.json(); } catch (_) { /* binary response */ }
  if (!response.ok) throw new Error(body.error || `Request failed (${response.status})`);
  return body;
}

function toast(message, error = false) {
  const node = $('#toast'); node.textContent = message; node.className = `toast show${error ? ' error' : ''}`;
  window.clearTimeout(toast.timer); toast.timer = window.setTimeout(() => { node.className = 'toast'; }, 3600);
}
function bytes(value) {
  if (value === 0) return '0 B';
  if (!value) return '—';
  const units = ['B', 'KB', 'MB', 'GB', 'TB']; let number = value; let index = 0;
  while (number >= 1024 && index < units.length - 1) { number /= 1024; index++; }
  return `${number >= 100 || index === 0 ? Math.round(number) : number.toFixed(1)} ${units[index]}`;
}
function date(value) { if (!value) return '—'; try { return new Date(value).toLocaleString([], {dateStyle:'medium', timeStyle:'short'}); } catch (_) { return value; } }
function esc(value) { const node = document.createElement('span'); node.textContent = value ?? ''; return node.innerHTML; }
function currentCaseId() { return state.currentCase?.id || ''; }
function selectedMode() { return document.querySelector('input[name="mode"]:checked')?.value || 'normal'; }

function showView(view) {
  $$('.view').forEach((node) => node.classList.remove('active-view'));
  $(`#view-${view}`).classList.add('active-view');
  $$('.nav-item').forEach((node) => node.classList.toggle('active', node.dataset.view === view));
  const labels = {overview:'Overview', acquisition:'Acquire evidence', analysis:'Analyze & recover', reports:'Reports & custody'};
  $('#crumb').textContent = labels[view];
}

function renderCases() {
  const list = $('#cases-list'); $('#case-count').textContent = `${state.cases.length} CASE${state.cases.length === 1 ? '' : 'S'}`;
  $('#metric-cases').textContent = state.cases.length;
  const evidenceCount = state.cases.reduce((sum, item) => sum + Number(item.evidence_count || 0), 0);
  const segmentCount = state.cases.reduce((sum, item) => sum + Number(item.segment_count || 0), 0);
  $('#metric-evidence').textContent = evidenceCount;
  $('#metric-segments').textContent = segmentCount;
  $('#metric-chains').textContent = state.cases.length ? '✓' : '—';
  if (!state.cases.length) { list.innerHTML = '<div class="empty-state"><div class="empty-icon">◌</div><strong>No examinations yet</strong><span>Create a case to begin a preserved workflow.</span></div>'; return; }
  list.innerHTML = state.cases.map((item) => `<div class="case-row ${currentCaseId() === item.id ? 'selected' : ''}" data-case="${esc(item.id)}">
    <div class="case-info"><div class="case-title">${esc(item.title)}</div><div class="case-id">${esc(item.id)} · ${esc(item.status || 'open').toUpperCase()}</div></div>
    <div class="case-stats"><div class="case-stat"><strong>${item.evidence_count || 0}</strong><small>SOURCES</small></div><div class="case-stat"><strong>${item.segment_count || 0}</strong><small>RANGES</small></div></div><div class="case-time">${date(item.created_at)}</div></div>`).join('');
  $$('.case-row').forEach((row) => row.addEventListener('click', () => selectCase(row.dataset.case)));
}

async function loadCases() { state.cases = (await api('/api/cases')).cases || []; renderCases(); }
async function selectCase(id) {
  try {
    state.bundle = await api(`/api/cases/${encodeURIComponent(id)}`); state.currentCase = state.bundle.case;
    const evidence = state.bundle.evidence || []; state.currentEvidence = evidence[0] || null;
    $('#rail-case').textContent = `${state.currentCase.id} · ${state.currentCase.title}`; $('#rail-status').innerHTML = '<i></i> Case active';
    $('#rail-status').style.color = '#70cfc7';
    renderCases(); renderAll(); toast(`Loaded ${state.currentCase.id}`);
  } catch (error) { toast(error.message, true); }
}
function renderAll() { renderAcquisition(); renderAnalysis(); renderReports(); }
function renderAcquisition() {
  const active = !!state.currentCase; $('#acquisition-gate').style.display = active ? 'none' : 'flex';
  $('#evidence-case-hint').textContent = active ? `${state.currentCase.id} · ${state.currentCase.title}` : 'Select a case to view its source inventory.';
  const list = $('#evidence-list'); const evidence = state.bundle?.evidence || [];
  if (!evidence.length) { list.innerHTML = '<div class="empty-state compact"><span>No source acquired for this case.</span></div>'; return; }
  list.innerHTML = evidence.map((item) => `<div class="evidence-row ${state.currentEvidence?.id === item.id ? 'selected' : ''}" data-evidence="${esc(item.id)}"><div class="evidence-file-icon">▣</div><div class="evidence-main"><div class="evidence-name">${esc(item.original_name)}</div><div class="evidence-meta">${esc(item.id)} · ${bytes(item.size)} · acquired ${date(item.acquired_at)}</div></div><div class="evidence-hash">${esc(item.sha256)}</div><div class="hash-ok">✓ HASHED</div></div>`).join('');
  $$('.evidence-row').forEach((row) => row.addEventListener('click', () => { state.currentEvidence = evidence.find((x) => x.id === row.dataset.evidence); renderAll(); }));
}
function renderAnalysis() {
  const evidence = state.bundle?.evidence || []; const active = !!state.currentCase && evidence.length > 0;
  $('#analysis-gate').style.display = active ? 'none' : 'flex'; $('#identify-button').disabled = !active; $('#recover-button').disabled = !active;
  const list = $('#analysis-evidence-list');
  if (!evidence.length) { list.innerHTML = '<div class="empty-state compact"><span>No acquired evidence.</span></div>'; $('#identity-result').innerHTML = '<div class="empty-state compact"><span>Acquire a source first.</span></div>'; $('#segments-list').innerHTML = '<div class="empty-state compact"><span>No recovered ranges.</span></div>'; return; }
  list.innerHTML = evidence.map((item) => `<div class="analysis-evidence-row ${state.currentEvidence?.id === item.id ? 'selected' : ''}" data-evidence="${esc(item.id)}"><span class="source-dot"></span><div class="source-label"><strong>${esc(item.original_name)}</strong><small>${esc(item.id)} · ${bytes(item.size)}</small></div></div>`).join('');
  $$('.analysis-evidence-row').forEach((row) => row.addEventListener('click', () => { state.currentEvidence = evidence.find((x) => x.id === row.dataset.evidence); renderAnalysis(); }));
  const identity = state.currentEvidence?.identification;
  if (!identity) $('#identity-result').innerHTML = '<div class="identity-empty">No identification run for this source. The engine will scan bounded signatures when you run it.</div>';
  else {
    const primary = identity.hits?.find((hit) => hit.vendor === identity.primary_vendor) || identity.hits?.[0] || {};
    const chips = (identity.hits || []).map((hit) => `<span class="hit-chip">${esc(hit.display_name)} <em>${Math.round((hit.confidence || 0) * 100)}%</em></span>`).join('');
    const limitation = (primary.limitations || [])[0] || 'Interpretation remains bounded to the observed signatures.';
    $('#identity-result').innerHTML = `<div class="identity-main"><div class="vendor-logo">⌁</div><div><strong>${esc(primary.display_name || identity.primary_vendor)}</strong><small>${esc(primary.filesystem || 'unidentified')} · route ${esc(primary.route || 'generic')}</small></div><div class="confidence"><b>${Math.round((identity.confidence || 0) * 100)}%</b><small>CONFIDENCE</small></div></div><div class="hit-list">${chips || '<span class="hit-chip">No specific signature</span>'}</div><div class="limitation">${esc(limitation)}</div>`;
  }
  const segments = state.currentEvidence?.segments || []; $('#segment-count').textContent = `${segments.length} RANGE${segments.length === 1 ? '' : 'S'}`;
  const segList = $('#segments-list');
  if (!segments.length) { segList.innerHTML = '<div class="empty-state compact"><div class="empty-icon">⌁</div><span>Run recovery to populate the evidence timeline.</span></div>'; return; }
  segList.innerHTML = segments.map((seg, index) => `<div class="segment-row"><div class="segment-index">RANGE ${String(index + 1).padStart(2,'0')}</div><div class="segment-title">${esc(seg.codec)} · ${esc(seg.state)}<small>${esc(seg.source)} · ${bytes(seg.size)} · offset 0x${Number(seg.start_offset).toString(16).toUpperCase()}</small></div><div class="segment-facts"><strong>${Math.round((seg.confidence || 0) * 100)}%</strong><small>${esc(seg.recovery_mode)}</small></div><div class="segment-actions"><a class="tiny-link" href="/api/segments/${encodeURIComponent(seg.id)}/export?format=native">↓ Native bytes</a><a class="tiny-link" href="/api/segments/${encodeURIComponent(seg.id)}/export?format=mp4">▶ MP4 if ffmpeg</a></div></div>`).join('');
}
function renderReports() {
  const active = !!state.currentCase; $('#report-gate').style.display = active ? 'none' : 'flex'; $('#generate-report').disabled = !active;
  $('#report-case-label').textContent = active ? `${state.currentCase.id} · ${state.currentCase.title}` : 'No case selected';
  const chain = state.bundle?.chain; const chainNode = $('#report-chain');
  if (!chain) { chainNode.className = 'report-chain'; chainNode.innerHTML = '<i></i> Awaiting case'; $('#report-summary').innerHTML = '<div class="empty-state compact"><span>Generate a report after acquiring or analyzing evidence.</span></div>'; $('#audit-list').innerHTML = '<div class="empty-state compact"><span>No case selected.</span></div>'; return; }
  chainNode.className = `report-chain ${chain.valid ? 'valid' : 'invalid'}`; chainNode.innerHTML = `<i></i> ${chain.valid ? 'Chain verified' : 'Chain broken'}`;
  const evidence = state.bundle.evidence || []; const ranges = evidence.reduce((sum, item) => sum + (item.segments || []).length, 0);
  $('#report-summary').innerHTML = `<div class="summary-grid"><div class="summary-cell"><b>${evidence.length}</b><span>SOURCES</span></div><div class="summary-cell"><b>${ranges}</b><span>RECOVERED RANGES</span></div><div class="summary-cell"><b>${chain.event_count || 0}</b><span>AUDIT EVENTS</span></div></div>`;
  const events = state.bundle.audit || []; $('#audit-list').innerHTML = events.length ? events.map((event) => `<div class="audit-row"><div class="audit-id">#${event.id}</div><div class="audit-body"><strong>${esc(event.action.replaceAll('_',' '))}</strong><small>${date(event.occurred_at)} · ${esc(event.actor)}</small><div class="audit-hash">${esc(event.event_hash)}</div></div></div>`).join('') : '<div class="empty-state compact"><span>No events.</span></div>';
}

async function createCase(event) {
  event.preventDefault();
  try { const created = await api('/api/cases', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({title:$('#case-title').value, investigator:$('#case-investigator').value, notes:$('#case-notes').value})}); $('#case-dialog').close(); event.target.reset(); await loadCases(); await selectCase(created.id); showView('acquisition'); toast('Examination created'); } catch (error) { toast(error.message, true); }
}
async function upload(file) {
  if (!state.currentCase) { toast('Select a case before acquiring evidence', true); return; }
  const progress = $('#upload-progress'); progress.classList.add('visible'); $('#upload-name').textContent = file.name; $('#upload-percent').textContent = 'Uploading…'; $('#upload-bar').style.width = '8%';
  try {
    const item = await api(`/api/cases/${encodeURIComponent(currentCaseId())}/evidence`, {method:'POST', headers:{'Content-Type':'application/octet-stream','X-Filename':file.name}, body:file});
    $('#upload-bar').style.width = '100%'; $('#upload-percent').textContent = '100%'; toast(`Acquired ${item.id}`); await selectCase(currentCaseId());
  } catch (error) { toast(error.message, true); } finally { window.setTimeout(() => progress.classList.remove('visible'), 800); }
}
async function identify() { if (!state.currentEvidence) return; const button = $('#identify-button'); button.disabled = true; button.textContent = 'Scanning…'; try { await api(`/api/evidence/${encodeURIComponent(state.currentEvidence.id)}/identify`, {method:'POST'}); await selectCase(currentCaseId()); showView('analysis'); toast('Recorder identification complete'); } catch (error) { toast(error.message, true); } finally { button.textContent = 'Run identification'; button.disabled = false; } }
async function recover() { if (!state.currentEvidence) return; const button = $('#recover-button'); button.disabled = true; button.innerHTML = 'Scanning source…'; try { const result = await api(`/api/evidence/${encodeURIComponent(state.currentEvidence.id)}/recover`, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({mode:selectedMode()})}); await selectCase(currentCaseId()); showView('analysis'); toast(`Recovery complete · ${result.segment_count} range${result.segment_count === 1 ? '' : 's'}`); } catch (error) { toast(error.message, true); } finally { button.innerHTML = 'Run recovery scan <span>→</span>'; button.disabled = false; } }
async function generateReport() { if (!state.currentCase) return; const button = $('#generate-report'); button.disabled = true; button.textContent = 'Building…'; try { const result = await api(`/api/cases/${encodeURIComponent(currentCaseId())}/report`, {method:'POST'}); await selectCase(currentCaseId()); $('#report-links').innerHTML = `<a href="/api/cases/${encodeURIComponent(currentCaseId())}/report.html" target="_blank">View HTML report ↗</a><a href="/api/cases/${encodeURIComponent(currentCaseId())}/report.pdf">Download PDF ↓</a><a href="/api/cases/${encodeURIComponent(currentCaseId())}/report.json">Download JSON ↓</a>`; toast('Report package generated'); } catch (error) { toast(error.message, true); } finally { button.textContent = 'Generate report'; button.disabled = false; } }

function wire() {
  $$('.nav-item').forEach((button) => button.addEventListener('click', () => showView(button.dataset.view)));
  $('#new-case').addEventListener('click', () => { $('#case-dialog').showModal(); $('#case-title').focus(); });
  $('#case-form').addEventListener('submit', createCase);
  $('#refresh').addEventListener('click', async () => { try { await loadCases(); if (currentCaseId()) await selectCase(currentCaseId()); toast('Workspace refreshed'); } catch (error) { toast(error.message, true); } });
  $('#file-input').addEventListener('change', (event) => { const file = event.target.files[0]; if (file) upload(file); event.target.value = ''; });
  const drop = $('#drop-zone'); ['dragenter','dragover'].forEach((name) => drop.addEventListener(name, (event) => { event.preventDefault(); drop.classList.add('dragging'); })); ['dragleave','drop'].forEach((name) => drop.addEventListener(name, (event) => { event.preventDefault(); drop.classList.remove('dragging'); })); drop.addEventListener('drop', (event) => { const file = event.dataTransfer.files[0]; if (file) upload(file); });
  $('#identify-button').addEventListener('click', identify); $('#recover-button').addEventListener('click', recover); $('#generate-report').addEventListener('click', generateReport);
  $$('input[name="mode"]').forEach((input) => input.addEventListener('change', () => $$('.mode-option').forEach((node) => node.classList.toggle('selected', node.querySelector('input').checked))));
}
(async function init() { wire(); try { const health = await api('/api/health'); $('#version').textContent = `v${health.version}`; await loadCases(); } catch (error) { $('#api-label').textContent = 'Engine unavailable'; toast(error.message, true); } renderAll(); })();
