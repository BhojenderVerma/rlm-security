/**
 * RLM Security Dashboard — Interactive Report Viewer
 * Pure vanilla JS, no dependencies.
 */

/* ── State ──────────────────────────────────────────────────────────────── */
let reportData = null;
let allFindings = [];
let filteredFindings = [];
let fileData = [];
let sortState = { col: 'finding_count', dir: -1 };
let donutChart = null;

/* ── Boot ───────────────────────────────────────────────────────────────── */
window.addEventListener('DOMContentLoaded', () => {
  // Try to load pre-loaded report (from CLI dashboard command)
  fetch('report_data.json')
    .then(r => r.ok ? r.json() : Promise.reject())
    .then(data => ingestReport(data))
    .catch(() => {/* No pre-loaded data — show empty state */});
});

/* ── Load Functions ─────────────────────────────────────────────────────── */
function loadFromFile(event) {
  const file = event.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = e => {
    try {
      const data = JSON.parse(e.target.result);
      ingestReport(data);
    } catch {
      alert('Invalid JSON file. Please load a valid RLM report.');
    }
  };
  reader.readAsText(file);
}

function loadDemoData() {
  ingestReport(generateDemoData());
}

/* ── Ingest & Render ─────────────────────────────────────────────────────── */
function ingestReport(data) {
  reportData = data;
  allFindings = data.findings || [];
  filteredFindings = [...allFindings];
  fileData = data.files || [];

  // Show dashboard, hide empty state
  document.getElementById('empty-state').classList.add('hidden');
  document.getElementById('dashboard').classList.remove('hidden');

  // Populate category filter
  populateCategoryFilter();

  // Render all sections
  renderScanMeta();
  renderRiskHero();
  renderSeverityBars();
  renderCategoryChart();
  renderFileRiskBars();
  renderFindings();
  renderFileTable();
}

/* ── Scan Meta ────────────────────────────────────────────────────────── */
function renderScanMeta() {
  const el = document.getElementById('scan-meta');
  const ts = reportData.timestamp ? new Date(reportData.timestamp).toLocaleString() : '—';
  el.innerHTML = `
    <strong>Scan ID:</strong> ${reportData.scan_id || '—'} &nbsp;|&nbsp;
    <strong>Source:</strong> ${reportData.source || '—'} &nbsp;|&nbsp;
    <strong>Type:</strong> ${reportData.source_type || '—'} &nbsp;|&nbsp;
    <strong>Scanned:</strong> ${ts}
    ${reportData.metadata?.scan_duration_seconds ? `&nbsp;|&nbsp;<strong>Duration:</strong> ${reportData.metadata.scan_duration_seconds}s` : ''}
  `;
  el.classList.remove('hidden');
}

/* ── Risk Hero ────────────────────────────────────────────────────────── */
function renderRiskHero() {
  const s = reportData.summary;
  const score = s.risk_score || 0;

  const scoreEl = document.getElementById('risk-score-val');
  const barEl   = document.getElementById('risk-bar');
  const ratingEl = document.getElementById('risk-rating');
  const cardEl  = document.getElementById('risk-card');

  scoreEl.textContent = score;

  const { color, rating } = getRiskMeta(score);
  ratingEl.textContent  = rating;
  ratingEl.style.color  = color;
  cardEl.style.setProperty('--accent-glow', color + '25');

  setTimeout(() => { barEl.style.width = score + '%'; }, 100);

  // Stats
  animateNumber('stat-files',    s.total_files);
  animateNumber('stat-issues',   s.files_with_issues);
  animateNumber('stat-findings', s.total_findings);
}

function getRiskMeta(score) {
  if (score >= 70) return { color: '#FF4444', rating: 'CRITICAL RISK' };
  if (score >= 40) return { color: '#FF8C00', rating: 'HIGH RISK' };
  if (score >= 15) return { color: '#FFD700', rating: 'MODERATE RISK' };
  return { color: '#39D353', rating: 'LOW RISK' };
}

function animateNumber(cardId, target) {
  const card = document.getElementById(cardId);
  const numEl = card.querySelector('.stat-num');
  const start = 0;
  const duration = 800;
  const startTime = performance.now();

  function update(now) {
    const elapsed = now - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    numEl.textContent = Math.round(start + (target - start) * eased);
    if (progress < 1) requestAnimationFrame(update);
  }
  requestAnimationFrame(update);
}

/* ── Severity Bars ────────────────────────────────────────────────────── */
function renderSeverityBars() {
  const s = reportData.summary.by_severity || {};
  const container = document.getElementById('severity-bars');
  const sevs = [
    { key: 'CRITICAL', cls: 'critical', emoji: '🔴' },
    { key: 'HIGH',     cls: 'high',     emoji: '🟠' },
    { key: 'MEDIUM',   cls: 'medium',   emoji: '🟡' },
    { key: 'LOW',      cls: 'low',      emoji: '🟢' },
    { key: 'INFO',     cls: 'info',     emoji: '🔵' },
  ];

  container.innerHTML = sevs.map(({ key, cls, emoji }) => `
    <div class="sev-bar-item ${cls}" onclick="filterBySeverity('${key}')" title="Filter by ${key}">
      <div class="sev-count">${s[key] || 0}</div>
      <div class="sev-label">${emoji} ${key}</div>
    </div>
  `).join('');
}

function filterBySeverity(sev) {
  const sel = document.getElementById('filter-severity');
  sel.value = sel.value === sev ? '' : sev;
  applyFilters();
  document.getElementById('findings-list').scrollIntoView({ behavior: 'smooth' });
}

/* ── Category Donut Chart ─────────────────────────────────────────────── */
function renderCategoryChart() {
  const cats = reportData.summary.by_category || {};
  const canvas = document.getElementById('chart-category');
  const ctx = canvas.getContext('2d');
  const W = canvas.width;
  const H = canvas.height;
  const cx = W / 2, cy = H / 2;
  const outerR = Math.min(W, H) / 2 - 16;
  const innerR = outerR * 0.55;

  const palette = [
    '#58A6FF', '#FF4444', '#FF8C00', '#FFD700', '#39D353',
    '#BC8CFF', '#FF6EB4', '#00D4AA',
  ];

  const entries = Object.entries(cats).filter(([, v]) => v > 0);
  const total = entries.reduce((s, [, v]) => s + v, 0);
  if (total === 0) { ctx.clearRect(0, 0, W, H); return; }

  ctx.clearRect(0, 0, W, H);

  // Draw slices
  let angle = -Math.PI / 2;
  entries.forEach(([key, val], i) => {
    const slice = (val / total) * 2 * Math.PI;
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.arc(cx, cy, outerR, angle, angle + slice);
    ctx.closePath();
    ctx.fillStyle = palette[i % palette.length];
    ctx.fill();
    ctx.strokeStyle = '#161B22';
    ctx.lineWidth = 2;
    ctx.stroke();
    angle += slice;
  });

  // Inner circle (donut hole)
  ctx.beginPath();
  ctx.arc(cx, cy, innerR, 0, 2 * Math.PI);
  ctx.fillStyle = '#161B22';
  ctx.fill();

  // Center text
  ctx.fillStyle = '#E6EDF3';
  ctx.font = 'bold 22px Inter';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(total, cx, cy - 10);
  ctx.fillStyle = '#8B949E';
  ctx.font = '11px Inter';
  ctx.fillText('findings', cx, cy + 10);

  // Legend (below canvas — render as DOM)
  renderChartLegend(entries, palette);
}

function renderChartLegend(entries, palette) {
  const existing = document.getElementById('chart-legend');
  if (existing) existing.remove();

  const legend = document.createElement('div');
  legend.id = 'chart-legend';
  legend.style.cssText = 'display:flex;flex-wrap:wrap;gap:6px;margin-top:12px;justify-content:center;';
  entries.forEach(([key, val], i) => {
    const item = document.createElement('div');
    item.style.cssText = `display:flex;align-items:center;gap:5px;font-size:11px;color:#8B949E;cursor:pointer;`;
    item.innerHTML = `
      <span style="width:10px;height:10px;border-radius:2px;background:${palette[i % palette.length]};display:inline-block;flex-shrink:0;"></span>
      ${key.replace(/_/g, ' ')} (${val})
    `;
    item.onclick = () => {
      document.getElementById('filter-category').value = key;
      applyFilters();
    };
    legend.appendChild(item);
  });
  document.querySelector('.chart-card').appendChild(legend);
}

/* ── File Risk Bars ───────────────────────────────────────────────────── */
function renderFileRiskBars() {
  const container = document.getElementById('file-risk-bars');
  const top = [...fileData]
    .filter(f => f.finding_count > 0)
    .sort((a, b) => b.finding_count - a.finding_count)
    .slice(0, 10);

  if (top.length === 0) {
    container.innerHTML = '<p style="color:#8B949E;font-size:13px;">No files with findings.</p>';
    return;
  }

  const max = top[0].finding_count;
  container.innerHTML = top.map(f => {
    const pct = Math.round((f.finding_count / max) * 100);
    const name = f.path.split('/').pop();
    return `
      <div class="file-risk-bar-item" onclick="filterByFile('${escHtml(f.path)}')" title="${escHtml(f.path)}">
        <div class="file-risk-name">${escHtml(name)}</div>
        <div class="file-risk-bar-bg">
          <div class="file-risk-bar-fill" style="width:${pct}%"></div>
        </div>
        <div class="file-risk-count">${f.finding_count}</div>
      </div>
    `;
  }).join('');
}

function filterByFile(path) {
  document.getElementById('filter-search').value = path;
  applyFilters();
  document.getElementById('findings-list').scrollIntoView({ behavior: 'smooth' });
}

/* ── Filters ──────────────────────────────────────────────────────────── */
function populateCategoryFilter() {
  const cats = [...new Set(allFindings.map(f => f.category))].sort();
  const sel = document.getElementById('filter-category');
  const current = sel.value;
  sel.innerHTML = '<option value="">All Categories</option>' +
    cats.map(c => `<option value="${c}">${c.replace(/_/g, ' ')}</option>`).join('');
  sel.value = current;
}

function applyFilters() {
  const sev    = document.getElementById('filter-severity').value;
  const cat    = document.getElementById('filter-category').value;
  const search = document.getElementById('filter-search').value.toLowerCase();

  filteredFindings = allFindings.filter(f => {
    if (sev && f.severity !== sev) return false;
    if (cat && f.category !== cat) return false;
    if (search) {
      const haystack = [f.title, f.file, f.category, f.cwe_id || '', f.description]
        .join(' ').toLowerCase();
      if (!haystack.includes(search)) return false;
    }
    return true;
  });

  renderFindings();
}

/* ── Findings List ────────────────────────────────────────────────────── */
function renderFindings() {
  const container = document.getElementById('findings-list');
  document.getElementById('findings-count').textContent = `${filteredFindings.length} findings`;

  if (filteredFindings.length === 0) {
    container.innerHTML = `
      <div style="text-align:center;padding:40px;color:#8B949E;">
        <div style="font-size:32px;margin-bottom:8px;">🎉</div>
        <div>No findings match your filters.</div>
      </div>
    `;
    return;
  }

  container.innerHTML = filteredFindings.map((f, idx) => {
    const sev = f.severity.toLowerCase();
    const emoji = { critical: '🔴', high: '🟠', medium: '🟡', low: '🟢', info: '🔵' }[sev] || '⚪';
    return `
      <div class="finding-card ${sev}" onclick="openModal(${idx})" id="finding-${idx}">
        <div>
          <span class="severity-badge ${sev}">${emoji} ${f.severity}</span>
        </div>
        <div>
          <div class="finding-title">${escHtml(f.title)}</div>
          <div class="finding-meta">
            <span>📄 ${escHtml(f.file)}${f.line_start ? ':' + f.line_start : ''}</span>
            <span>🏷 ${f.category.replace(/_/g, ' ')}</span>
            ${f.cwe_id ? `<span>🔗 ${f.cwe_id}</span>` : ''}
            <span style="color:#484F58">Confidence: ${f.confidence}</span>
          </div>
        </div>
        <div class="finding-chevron">›</div>
      </div>
    `;
  }).join('');
}

/* ── Modal ────────────────────────────────────────────────────────────── */
function openModal(filteredIdx) {
  const f = filteredFindings[filteredIdx];
  if (!f) return;

  const sev = f.severity.toLowerCase();
  const emoji = { critical: '🔴', high: '🟠', medium: '🟡', low: '🟢', info: '🔵' }[sev] || '⚪';

  const refs = f.references && f.references.length
    ? `<ul class="modal-refs">${f.references.map(r => `<li><a href="${escHtml(r)}" target="_blank" rel="noopener">${escHtml(r)}</a></li>`).join('')}</ul>`
    : '<span style="color:#484F58">None</span>';

  document.getElementById('modal-body').innerHTML = `
    <div class="modal-severity"><span class="severity-badge ${sev}">${emoji} ${f.severity}</span></div>
    <div class="modal-title">${escHtml(f.title)}</div>
    <div class="modal-meta">
      <span>📄 <strong>${escHtml(f.file)}</strong>${f.line_start ? ` : ${f.line_start}` : ''}</span>
      <span>🏷 ${f.category.replace(/_/g, ' ')}</span>
      ${f.cwe_id ? `<span>🔗 ${f.cwe_id}</span>` : ''}
      <span>📊 Confidence: ${f.confidence}</span>
      ${f.id ? `<span style="color:#484F58">ID: ${f.id}</span>` : ''}
    </div>

    <div class="modal-section-label">Description</div>
    <div class="modal-desc">${escHtml(f.description)}</div>

    <div class="modal-section-label">Code Snippet</div>
    <pre class="modal-code">${escHtml(f.code_snippet || '(no snippet available)')}</pre>

    <div class="modal-section-label">Recommendation</div>
    <div class="modal-rec">${escHtml(f.recommendation)}</div>

    <div class="modal-section-label">References</div>
    ${refs}
  `;

  document.getElementById('modal-overlay').classList.remove('hidden');
  document.body.style.overflow = 'hidden';
}

function closeModal(event) {
  if (event && event.target !== document.getElementById('modal-overlay') && event.target !== null) {
    if (!event.target.classList.contains('modal-overlay')) return;
  }
  document.getElementById('modal-overlay').classList.add('hidden');
  document.body.style.overflow = '';
}

document.addEventListener('keydown', e => {
  if (e.key === 'Escape') closeModal();
});

/* ── File Table ───────────────────────────────────────────────────────── */
function renderFileTable() {
  const tbody = document.getElementById('file-tbody');
  const sorted = [...fileData].sort((a, b) => {
    const av = a[sortState.col] ?? '';
    const bv = b[sortState.col] ?? '';
    return av < bv ? sortState.dir : av > bv ? -sortState.dir : 0;
  });

  tbody.innerHTML = sorted.map(f => `
    <tr>
      <td class="file-cell" title="${escHtml(f.path)}">${escHtml(f.path)}</td>
      <td><span class="lang-badge">${escHtml(f.language || '—')}</span></td>
      <td>${f.lines_analyzed || 0}</td>
      <td class="count-cell ${f.finding_count > 0 ? 'has-findings' : 'no-findings'}">${f.finding_count || 0}</td>
      <td style="color:#8B949E;font-size:12px;">${f.scan_duration_ms ? f.scan_duration_ms.toFixed(1) + 'ms' : '—'}</td>
    </tr>
  `).join('');
}

function sortTable(col) {
  if (sortState.col === col) {
    sortState.dir *= -1;
  } else {
    sortState.col = col;
    sortState.dir = -1;
  }
  renderFileTable();
}

/* ── Demo Data ────────────────────────────────────────────────────────── */
function generateDemoData() {
  return {
    scan_id: 'demo-1234abcd',
    timestamp: new Date().toISOString(),
    source: 'github.com/demo/vulnerable-app',
    source_type: 'github',
    summary: {
      total_files: 42,
      files_with_issues: 18,
      total_findings: 27,
      risk_score: 72,
      by_severity: { CRITICAL: 3, HIGH: 8, MEDIUM: 11, LOW: 5, INFO: 0 },
      by_category: {
        SQL_INJECTION: 5,
        XSS: 6,
        HARDCODED_SECRET: 4,
        PATH_TRAVERSAL: 3,
        INSECURE_DEPENDENCY: 7,
        CRYPTO_MISUSE: 2,
      },
    },
    findings: [
      {
        id: 'f001',
        severity: 'CRITICAL',
        category: 'HARDCODED_SECRET',
        title: 'Hardcoded AWS Credential',
        description: 'An AWS access key ID is hardcoded in source code, exposing cloud infrastructure.',
        file: 'config/aws_config.py',
        line_start: 14,
        line_end: 14,
        code_snippet: '   12 | \n→  14 | AWS_ACCESS_KEY_ID = "AKIA4EXAMPLE1234ABCD"\n   15 | AWS_REGION = "us-east-1"',
        recommendation: 'Remove the key and rotate it immediately. Use IAM roles or environment variables.',
        cwe_id: 'CWE-798',
        confidence: 'HIGH',
        references: ['https://nvd.nist.gov/vuln/detail/CVE-2022-0001'],
      },
      {
        id: 'f002',
        severity: 'HIGH',
        category: 'SQL_INJECTION',
        title: 'SQL Injection via f-string',
        description: 'A SQL query is built using an f-string with user-controlled data.',
        file: 'api/users.py',
        line_start: 87,
        line_end: 87,
        code_snippet: '   85 | def get_user(user_id):\n→  87 |     cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n   88 |     return cursor.fetchone()',
        recommendation: 'Use parameterized queries. Replace f-string with "SELECT * FROM users WHERE id = %s" and pass (user_id,) as argument.',
        cwe_id: 'CWE-89',
        confidence: 'HIGH',
        references: ['https://owasp.org/www-community/attacks/SQL_Injection'],
      },
      {
        id: 'f003',
        severity: 'HIGH',
        category: 'XSS',
        title: 'XSS via innerHTML Assignment',
        description: 'User input from request parameters is assigned directly to innerHTML.',
        file: 'frontend/search.js',
        line_start: 42,
        line_end: 42,
        code_snippet: '   40 | const query = new URLSearchParams(window.location.search).get("q");\n   41 | const el = document.getElementById("results");\n→  42 | el.innerHTML = "Search results for: " + query;',
        recommendation: 'Use textContent instead of innerHTML, or sanitize with DOMPurify.',
        cwe_id: 'CWE-79',
        confidence: 'HIGH',
        references: ['https://owasp.org/www-community/attacks/xss/'],
      },
      {
        id: 'f004',
        severity: 'CRITICAL',
        category: 'HARDCODED_SECRET',
        title: 'Embedded PEM Private Key',
        description: 'A PEM-encoded private key is embedded directly in source code.',
        file: 'auth/jwt_utils.py',
        line_start: 3,
        line_end: 3,
        code_snippet: '   1 | # JWT signing key\n   2 | \n→  3 | PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----\n   4 | MIIEowIBAAKCAQEA...',
        recommendation: 'Remove this key, rotate it, and store it in an encrypted secrets manager.',
        cwe_id: 'CWE-321',
        confidence: 'HIGH',
        references: [],
      },
      {
        id: 'f005',
        severity: 'HIGH',
        category: 'INSECURE_DEPENDENCY',
        title: 'Vulnerable Dependency: lodash (4.17.20)',
        description: 'Command injection via template() in lodash 4.17.20 [CVE-2021-23337]',
        file: 'package.json',
        line_start: 12,
        line_end: 12,
        code_snippet: '   10 |   "dependencies": {\n   11 |     "express": "^4.17.1",\n→  12 |     "lodash": "^4.17.20",\n   13 |     "axios": "^0.21.0"',
        recommendation: 'Upgrade to lodash ≥ 4.17.21',
        cwe_id: 'CWE-1395',
        confidence: 'HIGH',
        references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-23337'],
      },
      {
        id: 'f006',
        severity: 'HIGH',
        category: 'CRYPTO_MISUSE',
        title: 'Use of Weak Hash Algorithm: MD5',
        description: 'MD5 is used for password hashing, which is cryptographically broken.',
        file: 'auth/password.py',
        line_start: 22,
        line_end: 22,
        code_snippet: '   20 | def hash_password(password):\n   21 |     import hashlib\n→  22 |     return hashlib.md5(password.encode()).hexdigest()',
        recommendation: 'Replace with bcrypt, argon2, or scrypt for password hashing.',
        cwe_id: 'CWE-327',
        confidence: 'HIGH',
        references: ['https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-131a.pdf'],
      },
      {
        id: 'f007',
        severity: 'MEDIUM',
        category: 'PATH_TRAVERSAL',
        title: 'Path Traversal via open() with User Input',
        description: 'A file is opened using a path derived from request parameters.',
        file: 'api/files.py',
        line_start: 56,
        line_end: 56,
        code_snippet: '   54 | @app.route("/download")\n   55 | def download():\n→  56 |     filename = open(request.args.get("file"), "rb").read()\n   57 |     return filename',
        recommendation: 'Validate the path with os.path.realpath() and ensure it stays within an allowed base directory.',
        cwe_id: 'CWE-22',
        confidence: 'HIGH',
        references: ['https://owasp.org/www-community/attacks/Path_Traversal'],
      },
      {
        id: 'f008',
        severity: 'CRITICAL',
        category: 'HARDCODED_SECRET',
        title: 'Hardcoded Database Connection String',
        description: 'A database URL with credentials is hardcoded in source.',
        file: 'config/database.py',
        line_start: 8,
        line_end: 8,
        code_snippet: '   6 | # Database config\n   7 | \n→  8 | DATABASE_URL = "postgresql://admin:SuperSecret123@db.internal:5432/prod"',
        recommendation: 'Move to DATABASE_URL environment variable. Never commit credentials.',
        cwe_id: 'CWE-798',
        confidence: 'HIGH',
        references: [],
      },
    ],
    files: [
      { path: 'api/users.py', language: 'python', lines_analyzed: 234, finding_count: 4, scan_duration_ms: 12.4 },
      { path: 'auth/jwt_utils.py', language: 'python', lines_analyzed: 89, finding_count: 3, scan_duration_ms: 8.1 },
      { path: 'frontend/search.js', language: 'javascript', lines_analyzed: 156, finding_count: 3, scan_duration_ms: 9.7 },
      { path: 'config/database.py', language: 'python', lines_analyzed: 45, finding_count: 2, scan_duration_ms: 3.2 },
      { path: 'package.json', language: 'json', lines_analyzed: 48, finding_count: 5, scan_duration_ms: 5.8 },
      { path: 'auth/password.py', language: 'python', lines_analyzed: 67, finding_count: 2, scan_duration_ms: 4.1 },
      { path: 'api/files.py', language: 'python', lines_analyzed: 112, finding_count: 2, scan_duration_ms: 6.3 },
      { path: 'config/aws_config.py', language: 'python', lines_analyzed: 31, finding_count: 2, scan_duration_ms: 2.9 },
      { path: 'models/user.py', language: 'python', lines_analyzed: 189, finding_count: 0, scan_duration_ms: 11.2 },
      { path: 'api/products.py', language: 'python', lines_analyzed: 310, finding_count: 0, scan_duration_ms: 18.5 },
    ],
    metadata: { scan_duration_seconds: 3.7, max_workers: 8, analyzer_count: 6 },
  };
}

/* ── Utilities ────────────────────────────────────────────────────────── */
function escHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
