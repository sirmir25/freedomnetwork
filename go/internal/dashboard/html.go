package dashboard

// dashboardHTML is the inline HTML/CSS/JS for the stats dashboard.
// Polls /api/stats and /api/log every 2 seconds.
const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FreedomNet Dashboard</title>
<style>
  :root {
    --bg: #0d1117;
    --surface: #161b22;
    --border: #30363d;
    --text: #e6edf3;
    --muted: #8b949e;
    --green: #3fb950;
    --red: #f85149;
    --blue: #58a6ff;
    --yellow: #d29922;
    --purple: #bc8cff;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
    font-size: 14px;
    min-height: 100vh;
    padding: 24px;
  }
  header {
    display: flex;
    align-items: center;
    gap: 16px;
    margin-bottom: 24px;
    padding-bottom: 16px;
    border-bottom: 1px solid var(--border);
  }
  header .logo {
    font-size: 22px;
    font-weight: 700;
    color: var(--blue);
    letter-spacing: -0.5px;
  }
  header .badge {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 2px 10px;
    font-size: 11px;
    color: var(--green);
  }
  header .uptime {
    margin-left: auto;
    color: var(--muted);
    font-size: 12px;
  }
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 16px;
    margin-bottom: 24px;
  }
  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px 20px;
  }
  .card .label {
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    color: var(--muted);
    margin-bottom: 8px;
  }
  .card .value {
    font-size: 28px;
    font-weight: 700;
    line-height: 1;
  }
  .card .sub {
    font-size: 11px;
    color: var(--muted);
    margin-top: 4px;
  }
  .card.green .value { color: var(--green); }
  .card.blue  .value { color: var(--blue); }
  .card.red   .value { color: var(--red); }
  .card.purple .value { color: var(--purple); }
  .card.yellow .value { color: var(--yellow); }

  .section-title {
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    color: var(--muted);
    margin-bottom: 12px;
  }

  /* Charts */
  .charts {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 16px;
    margin-bottom: 24px;
  }
  .chart-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px;
  }
  .chart-card .chart-title {
    font-size: 11px;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.8px;
    margin-bottom: 12px;
  }
  canvas { width: 100% !important; }

  /* Log pane */
  .log-pane {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px;
    max-height: 320px;
    overflow-y: auto;
  }
  .log-line {
    display: flex;
    gap: 12px;
    padding: 3px 0;
    border-bottom: 1px solid var(--border);
    font-size: 12px;
  }
  .log-line:last-child { border-bottom: none; }
  .log-line .ts   { color: var(--muted); min-width: 60px; }
  .log-line .lvl  { min-width: 50px; font-weight: 600; }
  .log-line .msg  { color: var(--text); }
  .log-line.info  .lvl { color: var(--blue); }
  .log-line.warn  .lvl { color: var(--yellow); }
  .log-line.error .lvl { color: var(--red); }
  .log-line.ok    .lvl { color: var(--green); }

  .status-dot {
    display: inline-block;
    width: 8px; height: 8px;
    border-radius: 50%;
    background: var(--green);
    margin-right: 6px;
    animation: pulse 2s ease-in-out infinite;
  }
  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.4; }
  }

  @media (max-width: 640px) {
    .charts { grid-template-columns: 1fr; }
    .grid { grid-template-columns: repeat(2, 1fr); }
  }
</style>
</head>
<body>
<header>
  <div class="logo">⚡ FreedomNet</div>
  <span class="badge">● LIVE</span>
  <div class="uptime" id="uptime">uptime: —</div>
</header>

<p class="section-title">Connection Statistics</p>
<div class="grid">
  <div class="card green">
    <div class="label">Active</div>
    <div class="value" id="stat-active">—</div>
    <div class="sub">concurrent tunnels</div>
  </div>
  <div class="card blue">
    <div class="label">Total</div>
    <div class="value" id="stat-total">—</div>
    <div class="sub">connections served</div>
  </div>
  <div class="card purple">
    <div class="label">Uploaded</div>
    <div class="value" id="stat-up">—</div>
    <div class="sub">client → server</div>
  </div>
  <div class="card yellow">
    <div class="label">Downloaded</div>
    <div class="value" id="stat-down">—</div>
    <div class="sub">server → client</div>
  </div>
  <div class="card blue">
    <div class="label">TLS Splits</div>
    <div class="value" id="stat-tls">—</div>
    <div class="sub">DPI bypass events</div>
  </div>
  <div class="card green">
    <div class="label">DoH Cache</div>
    <div class="value" id="stat-doh">—</div>
    <div class="sub">hit rate</div>
  </div>
</div>

<p class="section-title" style="margin-bottom:12px">Live Log</p>
<div class="log-pane" id="log-pane">
  <div class="log-line info">
    <span class="ts">--:--:--</span>
    <span class="lvl">INFO</span>
    <span class="msg">Waiting for data...</span>
  </div>
</div>

<script>
const $ = id => document.getElementById(id);

let lastLogCount = 0;

async function fetchStats() {
  try {
    const r = await fetch('/api/stats');
    if (!r.ok) return;
    const s = await r.json();

    $('stat-active').textContent = s.active_connections ?? '—';
    $('stat-total').textContent  = s.total_connections ?? '—';
    $('stat-up').textContent     = s.bytes_up_human ?? '—';
    $('stat-down').textContent   = s.bytes_down_human ?? '—';
    $('stat-tls').textContent    = s.tls_splits ?? '—';
    $('stat-doh').textContent    = s.doh_hit_rate != null
      ? Math.round(s.doh_hit_rate * 100) + '%' : '—';
    $('uptime').textContent      = 'uptime: ' + (s.uptime ?? '—');
  } catch(e) {}
}

async function fetchLog() {
  try {
    const r = await fetch('/api/log');
    if (!r.ok) return;
    const lines = await r.json();
    if (!lines || lines.length === lastLogCount) return;
    lastLogCount = lines.length;
    const pane = $('log-pane');
    pane.innerHTML = '';
    // show newest first
    [...lines].reverse().forEach(l => {
      const div = document.createElement('div');
      div.className = 'log-line ' + (l.level || 'info').toLowerCase();
      div.innerHTML =
        '<span class="ts">' + l.at + '</span>' +
        '<span class="lvl">' + (l.level || 'INFO') + '</span>' +
        '<span class="msg">' + escHtml(l.message) + '</span>';
      pane.appendChild(div);
    });
  } catch(e) {}
}

function escHtml(s) {
  return String(s)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;');
}

setInterval(fetchStats, 2000);
setInterval(fetchLog,   2000);
fetchStats();
fetchLog();
</script>
</body>
</html>`
