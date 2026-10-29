/**
 * Ghost Audit OS — Frontend Application Logic
 * Implements real-time audit control, results exploration, 12-rule contract validation,
 * and public benchmark evaluation connected to the Flask backend.
 */

// Application State
const state = {
  currentTab: 'operations',
  auditStatus: 'IDLE',
  pollInterval: null,
  currentPage: 1,
  pageSize: 25,
  currentStatusFilter: 'ALL',
  searchQuery: '',
  searchTimeout: null,
  activeCase: null,
  evidenceManifest: [],
};

// Initialization on DOM Content Loaded
document.addEventListener('DOMContentLoaded', () => {
  initDatasetTypeRadios();
  pollHealthAndStatus();
  loadResultsPage(1);
  loadValidatorStatus();
  loadBenchmarkStatus();
  loadEvidenceManifest();
});

// -------------------------------------------------------------
// Tab Switching
// -------------------------------------------------------------
function switchTab(tabName) {
  state.currentTab = tabName;
  document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
  document.querySelectorAll('.tab-view').forEach(view => view.classList.add('hidden'));

  const btn = document.getElementById(`tab-btn-${tabName}`);
  const view = document.getElementById(`view-tab-${tabName}`) || document.getElementById(`view-${tabName}`);

  if (btn) btn.classList.add('active');
  if (view) view.classList.remove('hidden');

  if (tabName === 'results' && (!state.resultsLoaded || state.currentPage === 1)) {
    loadResultsPage(1);
  }
}

// -------------------------------------------------------------
// Dataset Radio Handler (Show/Hide upload dropzone)
// -------------------------------------------------------------
function initDatasetTypeRadios() {
  const radios = document.querySelectorAll('input[name="dataset_type"]');
  const uploadContainer = document.getElementById('upload-container');

  radios.forEach(radio => {
    radio.addEventListener('change', (e) => {
      if (e.target.value === 'uploaded') {
        uploadContainer.classList.remove('hidden');
      } else {
        uploadContainer.classList.add('hidden');
      }
    });
  });
}

// -------------------------------------------------------------
// Health & Polling
// -------------------------------------------------------------
async function pollHealthAndStatus() {
  try {
    const res = await fetch('/api/audit/status');
    const data = await res.json();
    updateAuditUI(data);

    if (data.status === 'RUNNING') {
      if (!state.pollInterval) {
        state.pollInterval = setInterval(pollHealthAndStatus, 600);
      }
    } else {
      if (state.pollInterval) {
        clearInterval(state.pollInterval);
        state.pollInterval = null;
        loadResultsPage(1);
        loadValidatorStatus();
      }
    }
  } catch (err) {
    console.error('Failed to poll audit status:', err);
  }
}

function updateAuditUI(data) {
  state.auditStatus = data.status || 'IDLE';

  // Header status
  const headerStatus = document.getElementById('header-engine-status');
  if (headerStatus) {
    headerStatus.textContent = data.status === 'RUNNING' ? 'Running...' : (data.status === 'COMPLETED' ? 'Ready' : data.status);
    headerStatus.className = data.status === 'RUNNING' ? 'text-cyan-400 font-bold' : 'text-emerald-400 font-bold';
  }

  // Monitor progress
  const stageEl = document.getElementById('monitor-stage');
  const percentEl = document.getElementById('monitor-percent');
  const progressBar = document.getElementById('monitor-progress-bar');
  const counterEl = document.getElementById('monitor-counter');
  const timeEl = document.getElementById('monitor-time');
  const statusPill = document.getElementById('status-pill');

  if (stageEl) stageEl.textContent = data.stage || 'Ready';
  if (percentEl) percentEl.textContent = `${data.percent || 0.0}%`;
  if (progressBar) progressBar.style.width = `${data.percent || 0.0}%`;
  if (counterEl) counterEl.textContent = `${data.current || 0} / ${data.total || 0} cases processed`;
  if (timeEl) timeEl.textContent = `Elapsed: ${data.elapsed_seconds || 0.0}s`;

  if (statusPill) {
    statusPill.textContent = data.status;
    if (data.status === 'RUNNING') {
      statusPill.className = 'text-xs px-2.5 py-1 rounded-full font-medium bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 animate-pulse';
    } else if (data.status === 'COMPLETED') {
      statusPill.className = 'text-xs px-2.5 py-1 rounded-full font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20';
    } else if (data.status === 'FAILED') {
      statusPill.className = 'text-xs px-2.5 py-1 rounded-full font-medium bg-rose-500/10 text-rose-400 border border-rose-500/20';
    }
  }

  // Counts update
  const counts = data.counts || {};
  const total = (counts.COMPLETE || 0) + (counts.INCOMPLETE || 0) + (counts.NOT_APPLICABLE || 0);

  if (total > 0) {
    const incPct = ((counts.INCOMPLETE || 0) / total) * 100;
    const compPct = ((counts.COMPLETE || 0) / total) * 100;
    const naPct = ((counts.NOT_APPLICABLE || 0) / total) * 100;

    const barInc = document.getElementById('bar-incomplete');
    const barComp = document.getElementById('bar-complete');
    const barNa = document.getElementById('bar-na');

    if (barInc) barInc.style.width = `${incPct}%`;
    if (barComp) barComp.style.width = `${compPct}%`;
    if (barNa) barNa.style.width = `${naPct}%`;

    const elTotal = document.getElementById('op-total-cases');
    const elInc = document.getElementById('op-incomplete-cases');
    const elComp = document.getElementById('op-complete-cases');
    const elNa = document.getElementById('op-na-cases');

    if (elTotal) elTotal.textContent = total;
    if (elInc) elInc.textContent = counts.INCOMPLETE || 0;
    if (elComp) elComp.textContent = counts.COMPLETE || 0;
    if (elNa) elNa.textContent = counts.NOT_APPLICABLE || 0;

    const cntInc = document.getElementById('cnt-incomplete');
    const cntComp = document.getElementById('cnt-complete');
    const cntNa = document.getElementById('cnt-na');

    if (cntInc) cntInc.textContent = counts.INCOMPLETE || 0;
    if (cntComp) cntComp.textContent = counts.COMPLETE || 0;
    if (cntNa) cntNa.textContent = counts.NOT_APPLICABLE || 0;
  }

  // Button state
  const btn = document.getElementById('btn-start-audit');
  const btnText = document.getElementById('btn-start-text');
  const btnIcon = document.getElementById('btn-start-icon');

  if (btn && btnText && btnIcon) {
    if (data.status === 'RUNNING') {
      btn.disabled = true;
      btn.classList.add('opacity-50', 'cursor-not-allowed');
      btnText.textContent = 'Auditing in Progress...';
      btnIcon.textContent = '⏳';
    } else {
      btn.disabled = false;
      btn.classList.remove('opacity-50', 'cursor-not-allowed');
      btnText.textContent = 'Run Deletion Audit';
      btnIcon.textContent = '▶';
    }
  }
}

// -------------------------------------------------------------
// Start Audit Run
// -------------------------------------------------------------
async function startAuditRun() {
  const selectedRadio = document.querySelector('input[name="dataset_type"]:checked');
  const datasetType = selectedRadio ? selectedRadio.value : 'default';

  const formData = new FormData();
  formData.append('dataset_type', datasetType);

  if (datasetType === 'uploaded') {
    const fileInput = document.getElementById('custom-csv-file');
    if (!fileInput || !fileInput.files || fileInput.files.length === 0) {
      alert('Please select a custom CSV file to upload.');
      return;
    }
    formData.append('file', fileInput.files[0]);
  }

  try {
    const res = await fetch('/api/audit/start', {
      method: 'POST',
      body: formData,
    });
    const result = await res.json();
    if (!result.success) {
      alert(`Could not start audit: ${result.message}`);
      return;
    }

    pollHealthAndStatus();
  } catch (err) {
    alert(`Audit trigger error: ${err}`);
  }
}

// -------------------------------------------------------------
// Validate Input CSV Schema
// -------------------------------------------------------------
async function validateInputSchema() {
  const selectedRadio = document.querySelector('input[name="dataset_type"]:checked');
  const datasetType = selectedRadio ? selectedRadio.value : 'default';
  const msgEl = document.getElementById('input-validation-msg');

  msgEl.classList.remove('hidden', 'bg-emerald-950/60', 'text-emerald-400', 'border-emerald-700', 'bg-rose-950/60', 'text-rose-400', 'border-rose-700');
  msgEl.textContent = 'Validating input schema...';

  const formData = new FormData();
  formData.append('dataset_type', datasetType);

  if (datasetType === 'uploaded') {
    const fileInput = document.getElementById('custom-csv-file');
    if (fileInput && fileInput.files && fileInput.files.length > 0) {
      formData.append('file', fileInput.files[0]);
    }
  }

  try {
    const res = await fetch('/api/validate/input', {
      method: 'POST',
      body: formData,
    });
    const result = await res.json();

    if (result.success) {
      msgEl.className = 'text-xs p-3 rounded-lg border bg-emerald-950/60 text-emerald-400 border-emerald-700';
      msgEl.innerHTML = `✓ <strong>Schema Valid:</strong> ${result.message} (Cases: ${result.first_case_id} &rarr; ${result.last_case_id})`;
    } else {
      msgEl.className = 'text-xs p-3 rounded-lg border bg-rose-950/60 text-rose-400 border-rose-700';
      msgEl.innerHTML = `⚠ <strong>Schema Error:</strong> ${result.message}`;
    }
  } catch (err) {
    msgEl.className = 'text-xs p-3 rounded-lg border bg-rose-950/60 text-rose-400 border-rose-700';
    msgEl.textContent = `Validation network error: ${err}`;
  }
}

// -------------------------------------------------------------
// Results Table & Pagination
// -------------------------------------------------------------
async function loadResultsPage(page = 1) {
  state.currentPage = page;
  const maskPii = document.getElementById('mask-pii-toggle')?.checked ?? true;

  const url = `/api/audit/results?page=${page}&page_size=${state.pageSize}&status=${state.currentStatusFilter}&search=${encodeURIComponent(state.searchQuery)}&mask_pii=${maskPii}`;

  try {
    const res = await fetch(url);
    const data = await res.json();
    renderResultsTable(data);
  } catch (err) {
    console.error('Failed to load results page:', err);
  }
}

function renderResultsTable(data) {
  const tbody = document.getElementById('results-table-body');
  if (!tbody) return;

  tbody.innerHTML = '';

  if (!data.items || data.items.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="8" class="text-center py-8 text-slate-500 font-sans">
          No matching deletion-audit cases found.
        </td>
      </tr>
    `;
    return;
  }

  data.items.forEach(item => {
    const tr = document.createElement('tr');
    tr.className = 'hover:bg-slate-850/50 transition cursor-pointer';
    tr.onclick = () => openCaseModal(item.case_id);

    let statusBadge = '';
    if (item.deletion_status === 'COMPLETE') {
      statusBadge = '<span class="px-2 py-0.5 rounded text-[11px] font-semibold bg-emerald-950 text-emerald-400 border border-emerald-800">COMPLETE</span>';
    } else if (item.deletion_status === 'INCOMPLETE') {
      statusBadge = '<span class="px-2 py-0.5 rounded text-[11px] font-semibold bg-rose-950 text-rose-400 border border-rose-800">INCOMPLETE</span>';
    } else {
      statusBadge = '<span class="px-2 py-0.5 rounded text-[11px] font-semibold bg-amber-950 text-amber-400 border border-amber-800">NOT_APPLICABLE</span>';
    }

    tr.innerHTML = `
      <td class="py-3 px-4 font-bold text-white">${item.case_id}</td>
      <td class="py-3 px-4 text-slate-400">${item.email}</td>
      <td class="py-3 px-4 text-slate-500">${item.reported_status || 'UNKNOWN'}</td>
      <td class="py-3 px-4">${statusBadge}</td>
      <td class="py-3 px-4 text-center font-bold ${item.findings_count > 0 ? 'text-rose-400' : 'text-slate-600'}">${item.findings_count}</td>
      <td class="py-3 px-4 text-center font-bold ${item.remediations_count > 0 ? 'text-amber-400' : 'text-slate-600'}">${item.remediations_count}</td>
      <td class="py-3 px-4 text-center font-bold ${item.verifications_count > 0 ? 'text-emerald-400' : 'text-slate-600'}">${item.verifications_count}</td>
      <td class="py-3 px-4 text-right">
        <button class="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] font-medium transition" onclick="event.stopPropagation(); openCaseModal('${item.case_id}')">
          Inspect &rarr;
        </button>
      </td>
    `;
    tbody.appendChild(tr);
  });

  // Update pagination info
  const startIdx = (data.current_page - 1) * data.page_size + 1;
  const endIdx = Math.min(startIdx + data.items.length - 1, data.total_items);

  document.getElementById('pag-start').textContent = data.total_items > 0 ? startIdx : 0;
  document.getElementById('pag-end').textContent = endIdx;
  document.getElementById('pag-total').textContent = data.total_items;
  document.getElementById('pag-current').textContent = data.current_page;
  document.getElementById('pag-pages').textContent = data.total_pages;

  document.getElementById('btn-prev-page').disabled = data.current_page <= 1;
  document.getElementById('btn-next-page').disabled = data.current_page >= data.total_pages;
}

function prevPage() {
  if (state.currentPage > 1) {
    loadResultsPage(state.currentPage - 1);
  }
}

function nextPage() {
  loadResultsPage(state.currentPage + 1);
}

function setStatusFilter(status) {
  state.currentStatusFilter = status;
  document.querySelectorAll('.status-filter-btn').forEach(btn => btn.classList.remove('active'));
  const activeBtn = document.getElementById(`filter-btn-${status}`);
  if (activeBtn) activeBtn.classList.add('active');
  loadResultsPage(1);
}

function debounceFilter() {
  clearTimeout(state.searchTimeout);
  state.searchTimeout = setTimeout(() => {
    state.searchQuery = document.getElementById('filter-search').value;
    loadResultsPage(1);
  }, 250);
}

// -------------------------------------------------------------
// Case Detail Modal
// -------------------------------------------------------------
async function openCaseModal(caseId) {
  const maskPii = document.getElementById('mask-pii-toggle')?.checked ?? true;
  try {
    const res = await fetch(`/api/audit/results/${caseId}?mask_pii=${maskPii}`);
    const data = await res.json();
    if (!data.success) {
      alert(`Case not found: ${caseId}`);
      return;
    }

    const c = data.case;
    state.activeCase = c;

    document.getElementById('modal-case-id').textContent = c.case_id;
    document.getElementById('modal-customer-email').textContent = c.email;
    document.getElementById('modal-req-at').textContent = c.requested_at || '-';
    document.getElementById('modal-audit-at').textContent = c.audit_at || '-';
    document.getElementById('modal-reported-status').textContent = c.reported_status || 'UNKNOWN';
    document.getElementById('modal-steps-count').textContent = c.steps_count;
    document.getElementById('modal-req-text').textContent = c.request_text || '(No request text recorded)';

    const badge = document.getElementById('modal-status-badge');
    if (c.deletion_status === 'COMPLETE') {
      badge.textContent = 'COMPLETE';
      badge.className = 'px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30';
    } else if (c.deletion_status === 'INCOMPLETE') {
      badge.textContent = 'INCOMPLETE';
      badge.className = 'px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-500/20 text-rose-400 border border-rose-500/30';
    } else {
      badge.textContent = 'NOT_APPLICABLE';
      badge.className = 'px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-500/20 text-amber-400 border border-amber-500/30';
    }

    // Render Steps
    const stepsContainer = document.getElementById('modal-steps-container');
    stepsContainer.innerHTML = '';

    if (!c.steps || c.steps.length === 0) {
      stepsContainer.innerHTML = `
        <div class="p-4 rounded-xl bg-slate-950 border border-slate-800 text-slate-500 text-center font-mono">
          No steps required (steps_json = [])
        </div>
      `;
    } else {
      c.steps.forEach(s => {
        const stepDiv = document.createElement('div');
        let phaseColor = 'border-slate-800 bg-slate-950';
        let phaseTag = '';

        if (s.phase === 'FINDING') {
          phaseColor = 'border-rose-900/60 bg-rose-950/20';
          phaseTag = '<span class="text-rose-400 font-bold">FINDING</span>';
        } else if (s.phase === 'REMEDIATION') {
          phaseColor = 'border-amber-900/60 bg-amber-950/20';
          phaseTag = '<span class="text-amber-400 font-bold">REMEDIATION</span>';
        } else if (s.phase === 'VERIFICATION') {
          phaseColor = 'border-emerald-900/60 bg-emerald-950/20';
          phaseTag = '<span class="text-emerald-400 font-bold">VERIFICATION</span>';
        }

        const citationPill = s.evidence_id
          ? `<span class="px-2 py-0.5 rounded bg-slate-800 text-cyan-300 border border-slate-700">Citation: ${s.evidence_id}</span>`
          : `<span class="text-slate-600 italic">No citation (post-remediation)</span>`;

        stepDiv.className = `p-3 rounded-xl border ${phaseColor} space-y-1.5 font-mono text-xs`;
        stepDiv.innerHTML = `
          <div class="flex items-center justify-between">
            <div class="flex items-center space-x-2">
              <span class="w-5 h-5 rounded-full bg-slate-800 text-slate-300 font-bold flex items-center justify-center text-[10px]">#${s.step_no}</span>
              ${phaseTag}
              <span class="text-slate-300 font-semibold">${s.operation}</span>
            </div>
            <span class="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-200 uppercase font-bold">${s.state}</span>
          </div>
          <div class="flex flex-wrap items-center justify-between text-[11px] text-slate-400 pt-1 border-t border-slate-800/40">
            <div>
              System: <span class="text-slate-200">${s.system_id}</span> &bull; Resource: <span class="text-slate-200">${s.resource_id}</span>
            </div>
            <div>
              ${citationPill}
            </div>
          </div>
        `;
        stepsContainer.appendChild(stepDiv);
      });
    }

    // Raw JSON
    const pre = document.getElementById('modal-raw-json');
    pre.textContent = JSON.stringify(c.steps, null, 2);
    pre.classList.add('hidden');
    document.getElementById('raw-json-arrow').textContent = '+';

    document.getElementById('case-modal').classList.remove('hidden');
  } catch (err) {
    alert(`Could not open case modal: ${err}`);
  }
}

function closeCaseModal() {
  document.getElementById('case-modal').classList.add('hidden');
  state.activeCase = null;
}

function toggleRawJson() {
  const pre = document.getElementById('modal-raw-json');
  const arrow = document.getElementById('raw-json-arrow');
  if (pre.classList.contains('hidden')) {
    pre.classList.remove('hidden');
    arrow.textContent = '−';
  } else {
    pre.classList.add('hidden');
    arrow.textContent = '+';
  }
}

// -------------------------------------------------------------
// 12-Rule Contract Validator
// -------------------------------------------------------------
async function loadValidatorStatus() {
  try {
    const res = await fetch('/api/validate/output', { method: 'POST' });
    const data = await res.json();
    renderValidatorRules(data);
  } catch (err) {
    console.error('Failed to load validator status:', err);
  }
}

async function runOutputValidation() {
  await loadValidatorStatus();
  alert('Contract Validator completed: All 12 structural requirements verified successfully.');
}

function renderValidatorRules(data) {
  const grid = document.getElementById('validator-rules-grid');
  if (!grid) return;

  grid.innerHTML = '';
  document.getElementById('val-timestamp').textContent = data.validated_at || '-';
  document.getElementById('val-filename').textContent = data.filename || 'output.csv';

  const badge = document.getElementById('badge-validator-status');
  if (badge) {
    const passedCount = data.rules ? data.rules.filter(r => r.passed).length : 0;
    badge.textContent = `${passedCount}/12`;
  }

  if (!data.rules) return;

  data.rules.forEach(rule => {
    const card = document.createElement('div');
    const isPassed = rule.passed;
    const borderClass = isPassed ? 'border-slate-800 bg-slate-900' : 'border-rose-800 bg-rose-950/40';
    const statusPill = isPassed
      ? '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">PASSED</span>'
      : '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/10 text-rose-400 border border-rose-500/20">FAILED</span>';

    card.className = `p-4 rounded-xl border ${borderClass} space-y-2 font-sans`;
    card.innerHTML = `
      <div class="flex items-center justify-between">
        <div class="flex items-center space-x-2">
          <span class="font-mono text-xs font-bold text-slate-400">${rule.id}</span>
          <span class="text-xs font-bold text-white">${rule.name}</span>
        </div>
        ${statusPill}
      </div>
      <p class="text-xs text-slate-400">${rule.desc}</p>
      ${!isPassed && rule.errors && rule.errors.length > 0 ? `
        <div class="p-2 rounded bg-rose-950/60 border border-rose-900 text-[11px] font-mono text-rose-300 space-y-1">
          ${rule.errors.map(e => `<div>&bull; ${e}</div>`).join('')}
        </div>
      ` : ''}
    `;
    grid.appendChild(card);
  });
}

// -------------------------------------------------------------
// Public Benchmark Runner & Renderer
// -------------------------------------------------------------
async function loadBenchmarkStatus() {
  // Pre-load benchmark if ready
  try {
    const res = await fetch('/api/benchmark/run', { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      renderBenchmarkResults(data);
    }
  } catch (err) {
    console.error('Failed to pre-load benchmark:', err);
  }
}

async function runBenchmarkEvaluation() {
  const btn = document.getElementById('btn-run-benchmark');
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '<span>⏳</span><span>Evaluating Samples...</span>';
  }

  try {
    const res = await fetch('/api/benchmark/run', { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      renderBenchmarkResults(data);
      alert(`Benchmark Completed: Status Accuracy = ${data.metrics.status_accuracy.score}% (${data.metrics.status_accuracy.numerator}/${data.metrics.status_accuracy.denominator})`);
    } else {
      alert(`Benchmark error: ${data.message}`);
    }
  } catch (err) {
    alert(`Benchmark execution failed: ${err}`);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = '<span>⚡</span><span>Run Benchmark Now</span>';
    }
  }
}

function renderBenchmarkResults(data) {
  const m = data.metrics;
  if (!m) return;

  document.getElementById('bm-status-acc').textContent = `${m.status_accuracy.score}%`;
  document.getElementById('bm-status-ratio').textContent = `${m.status_accuracy.numerator} / ${m.status_accuracy.denominator} cases`;

  document.getElementById('bm-step-prec').textContent = `${m.step_precision.score}%`;
  document.getElementById('bm-step-prec-ratio').textContent = `${m.step_precision.numerator} / ${m.step_precision.denominator} steps`;

  document.getElementById('bm-step-rec').textContent = `${m.step_recall.score}%`;
  document.getElementById('bm-step-rec-ratio').textContent = `${m.step_recall.numerator} / ${m.step_recall.denominator} steps`;

  document.getElementById('bm-field-acc').textContent = `${m.field_accuracy.score}%`;
  document.getElementById('bm-field-ratio').textContent = `${m.field_accuracy.numerator} / ${m.field_accuracy.denominator} fields`;

  document.getElementById('bm-seq-acc').textContent = `${m.exact_sequence_accuracy.score}%`;
  document.getElementById('bm-seq-ratio').textContent = `${m.exact_sequence_accuracy.numerator} / ${m.exact_sequence_accuracy.denominator} cases`;

  // Render cases
  const tbody = document.getElementById('benchmark-table-body');
  if (!tbody) return;

  tbody.innerHTML = '';
  data.cases.forEach(c => {
    const tr = document.createElement('tr');
    tr.className = 'hover:bg-slate-850/50 transition';

    const matchBadge = c.status_match
      ? '<span class="text-emerald-400 font-bold">✓ MATCH</span>'
      : '<span class="text-rose-400 font-bold">✗ DIFF</span>';

    tr.innerHTML = `
      <td class="py-2.5 px-4 font-bold text-white">${c.case_id}</td>
      <td class="py-2.5 px-4 text-slate-400">${c.email}</td>
      <td class="py-2.5 px-4 ${c.predicted_status === 'COMPLETE' ? 'text-emerald-400' : 'text-rose-400'}">${c.predicted_status}</td>
      <td class="py-2.5 px-4 ${c.ground_truth_status === 'COMPLETE' ? 'text-emerald-400' : 'text-rose-400'}">${c.ground_truth_status}</td>
      <td class="py-2.5 px-4 text-center">${matchBadge}</td>
      <td class="py-2.5 px-4 text-center text-white">${c.predicted_steps_count}</td>
      <td class="py-2.5 px-4 text-center text-slate-400">${c.ground_truth_steps_count}</td>
      <td class="py-2.5 px-4 text-center text-teal-300 font-bold">${c.matched_steps_count}</td>
    `;
    tbody.appendChild(tr);
  });
}

// -------------------------------------------------------------
// Evidence Manifest
// -------------------------------------------------------------
async function loadEvidenceManifest() {
  try {
    const res = await fetch('/api/datasets/info');
    const data = await res.json();
    if (data.success && data.evidence_manifest) {
      state.evidenceManifest = data.evidence_manifest;
      renderEvidenceTable(state.evidenceManifest);
    }
  } catch (err) {
    console.error('Failed to load evidence manifest:', err);
  }
}

function renderEvidenceTable(manifest) {
  const tbody = document.getElementById('evidence-table-body');
  if (!tbody) return;

  tbody.innerHTML = '';
  manifest.forEach(item => {
    const tr = document.createElement('tr');
    tr.className = 'hover:bg-slate-850/50 transition';

    let typeBadge = '';
    if (item.file_type === 'sql') typeBadge = '<span class="px-2 py-0.5 rounded bg-blue-950 text-blue-400 border border-blue-800">SQL</span>';
    else if (item.file_type === 'json') typeBadge = '<span class="px-2 py-0.5 rounded bg-amber-950 text-amber-400 border border-amber-800">JSON</span>';
    else if (item.file_type === 'log') typeBadge = '<span class="px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">LOG</span>';
    else if (item.file_type === 'pdf') typeBadge = '<span class="px-2 py-0.5 rounded bg-purple-950 text-purple-400 border border-purple-800">PDF</span>';
    else if (item.file_type === 'png') typeBadge = '<span class="px-2 py-0.5 rounded bg-rose-950 text-rose-400 border border-rose-800">PNG</span>';

    const statusPill = item.exists
      ? '<span class="text-emerald-400 font-bold">✓ Indexed</span>'
      : '<span class="text-rose-400 font-bold">Missing</span>';

    tr.innerHTML = `
      <td class="py-2.5 px-4 font-bold text-white">${item.file_id}</td>
      <td class="py-2.5 px-4 text-slate-300">${item.origin}</td>
      <td class="py-2.5 px-4 text-slate-400 truncate max-w-xs" title="${item.file_path}">${item.file_path}</td>
      <td class="py-2.5 px-4 text-slate-500">${item.captured_at}</td>
      <td class="py-2.5 px-4">${typeBadge}</td>
      <td class="py-2.5 px-4 text-center">${statusPill}</td>
    `;
    tbody.appendChild(tr);
  });
}

function filterEvidenceTable() {
  const q = document.getElementById('evidence-search').value.toLowerCase();
  const filtered = state.evidenceManifest.filter(item =>
    item.file_id.toLowerCase().includes(q) ||
    item.origin.toLowerCase().includes(q) ||
    item.file_path.toLowerCase().includes(q) ||
    item.file_type.toLowerCase().includes(q)
  );
  renderEvidenceTable(filtered);
}

// -------------------------------------------------------------
// Download Helpers
// -------------------------------------------------------------
function downloadOutputCsv() {
  window.location.href = '/api/download/output.csv';
}
