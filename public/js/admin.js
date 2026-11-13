/**
 * MorphPot SOC Dashboard Client Logic
 */

let activeTab = 'logs';
let cachedLogs = [];
let cachedTrapped = [];
let cachedCanaries = [];
let cachedBlocklist = { ips: [] };

function getAdminToken() {
  const tokenInput = document.getElementById('adminToken');
  return (tokenInput ? tokenInput.value : 'secretadmin123').trim();
}

function toggleTokenVisibility() {
  const input = document.getElementById('adminToken');
  const eye = document.getElementById('tokenEye');
  if (input.type === 'password') {
    input.type = 'text';
    eye.className = 'fa-solid fa-eye-slash';
  } else {
    input.type = 'password';
    eye.className = 'fa-solid fa-eye';
  }
}

function switchTab(tabId) {
  activeTab = tabId;
  const tabs = ['logs', 'trapped', 'canaries', 'blocklist', 'adaptive'];
  tabs.forEach(t => {
    const section = document.getElementById(`tab-${t}`);
    const btn = document.getElementById(`tabBtn-${t}`);
    if (section && btn) {
      if (t === tabId) {
        section.classList.remove('hidden');
        btn.className = 'py-2.5 px-4 rounded-t-lg border-b-2 border-blue-500 text-blue-400 bg-slate-900/50 flex items-center space-x-2';
      } else {
        section.classList.add('hidden');
        btn.className = 'py-2.5 px-4 rounded-t-lg border-b-2 border-transparent text-slate-400 hover:text-white flex items-center space-x-2';
      }
    }
  });

  if (tabId === 'trapped') renderTrappedTable();
  if (tabId === 'canaries') renderCanaryCards();
  if (tabId === 'blocklist') renderBlocklistTable();
}

// Fetch stats and update KPI counters
async function loadStats() {
  const token = getAdminToken();
  try {
    const res = await fetch(`/admin/stats?token=${encodeURIComponent(token)}`);
    if (!res.ok) return;
    const data = await res.json();

    document.getElementById('statTotalAttacks').textContent = data.total_attacks || 0;
    document.getElementById('statTrapped').textContent = data.trapped_sessions || 0;
    document.getElementById('statUniqueIps').textContent = data.unique_attacker_ips || 0;
    document.getElementById('statCanaries').textContent = data.canary_downloads || 0;
    document.getElementById('statBlocked').textContent = data.blocked_ips_count || 0;

    const tarpitEl = document.getElementById('statTarpit');
    if (data.tarpit_active) {
      tarpitEl.innerHTML = '<span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span><span>ACTIVE (Adaptive)</span>';
      tarpitEl.className = 'text-sm font-bold text-emerald-400 mt-2 flex items-center space-x-1';
    } else {
      tarpitEl.innerHTML = '<span class="w-2 h-2 rounded-full bg-slate-500"></span><span>DISABLED</span>';
      tarpitEl.className = 'text-sm font-bold text-slate-400 mt-2 flex items-center space-x-1';
    }
  } catch (err) {
    console.error("Failed to fetch stats:", err);
  }
}

// Fetch logs
async function loadLogs() {
  const token = getAdminToken();
  try {
    const res = await fetch(`/admin/logs?token=${encodeURIComponent(token)}`);
    if (!res.ok) return;
    cachedLogs = await res.json();
    renderLogsTable();
  } catch (err) {
    console.error("Failed to fetch logs:", err);
  }
}

function renderLogsTable() {
  const tbody = document.getElementById('logsTableBody');
  const search = (document.getElementById('logFilterInput').value || '').toLowerCase();
  const threatFilter = document.getElementById('threatLevelSelect').value;

  const filtered = cachedLogs.filter(log => {
    const str = JSON.stringify(log).toLowerCase();
    const matchesSearch = !search || str.includes(search);
    const matchesThreat = threatFilter === 'ALL' || (log.threat_level || 'LOW') === threatFilter;
    return matchesSearch && matchesThreat;
  });

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="py-8 text-center text-slate-500">No logs match the current filter.</td></tr>`;
    return;
  }

  // Display newest first
  const rows = [...filtered].reverse().map(l => {
    const level = l.threat_level || 'LOW';
    let badgeClass = 'threat-low';
    if (level === 'CRITICAL') badgeClass = 'threat-critical';
    else if (level === 'HIGH') badgeClass = 'threat-high';
    else if (level === 'MEDIUM') badgeClass = 'threat-medium';

    const timeStr = l.ts ? l.ts.replace('T', ' ').replace('Z', '') : 'N/A';
    const target = l.username ? `User: ${escapeHtml(l.username)}` : (l.path ? `Path: ${escapeHtml(l.path)}` : 'N/A');
    const attackType = l.attack_type || 'PROBE';
    const ua = l.user_agent ? escapeHtml(l.user_agent.substring(0, 45)) : 'Unknown';

    return `
      <tr class="table-row-hover hover:bg-slate-900/60 transition">
        <td class="py-3 px-4 text-slate-400">${timeStr}</td>
        <td class="py-3 px-4 font-bold text-white">${escapeHtml(l.ip || '127.0.0.1')}</td>
        <td class="py-3 px-4 text-blue-400 font-semibold">${escapeHtml(attackType)}</td>
        <td class="py-3 px-4 text-slate-300">${target}</td>
        <td class="py-3 px-4">
          <span class="threat-badge ${badgeClass}">${level}</span>
        </td>
        <td class="py-3 px-4 text-slate-400 text-[11px]" title="${escapeHtml(l.user_agent || '')}">${ua}...</td>
        <td class="py-3 px-4 text-right">
          <button onclick="quickBlockIp('${l.ip}')" class="px-2.5 py-1 rounded bg-rose-950/60 hover:bg-rose-900 text-rose-300 border border-rose-800 text-[10px] transition">
            Block IP
          </button>
        </td>
      </tr>
    `;
  }).join('');

  tbody.innerHTML = rows;
}

// Fetch trapped sessions
async function loadTrapped() {
  const token = getAdminToken();
  try {
    const res = await fetch(`/admin/trapped?token=${encodeURIComponent(token)}`);
    if (!res.ok) return;
    cachedTrapped = await res.json();
    if (activeTab === 'trapped') renderTrappedTable();
  } catch (err) {
    console.error("Failed to fetch trapped:", err);
  }
}

function renderTrappedTable() {
  const tbody = document.getElementById('trappedTableBody');
  if (cachedTrapped.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="py-8 text-center text-slate-500">No trapped sessions yet. Trigger the brute-force trap to observe!</td></tr>`;
    return;
  }

  const rows = [...cachedTrapped].reverse().map(t => {
    const pws = Array.isArray(t.passwords) ? t.passwords.map(p => `"${escapeHtml(p)}"`).join(', ') : 'N/A';
    const timeStr = t.time ? t.time.replace('T', ' ').replace('Z', '') : 'N/A';

    return `
      <tr class="hover:bg-slate-900/60 transition">
        <td class="py-3 px-4 text-slate-400">${timeStr}</td>
        <td class="py-3 px-4 font-bold text-rose-400">${escapeHtml(t.ip)}</td>
        <td class="py-3 px-4 text-white font-semibold">${escapeHtml(t.username)}</td>
        <td class="py-3 px-4 text-amber-300 font-mono text-[11px]">${pws}</td>
        <td class="py-3 px-4">
          <span class="threat-badge threat-critical">CRITICAL (95)</span>
        </td>
        <td class="py-3 px-4 text-emerald-400 text-xs">
          <i class="fa-solid fa-lock mr-1"></i> Sandboxed in Decoy
        </td>
        <td class="py-3 px-4 text-right">
          <button onclick="quickBlockIp('${t.ip}')" class="px-2.5 py-1 rounded bg-rose-600 hover:bg-rose-500 text-white text-[10px] font-bold transition">
            Block IP
          </button>
        </td>
      </tr>
    `;
  }).join('');

  tbody.innerHTML = rows;
}

// Fetch canaries
async function loadCanaries() {
  const token = getAdminToken();
  try {
    const res = await fetch(`/admin/canaries?token=${encodeURIComponent(token)}`);
    if (!res.ok) return;
    cachedCanaries = await res.json();
    if (activeTab === 'canaries') renderCanaryCards();
  } catch (err) {
    console.error("Failed to fetch canaries:", err);
  }
}

function renderCanaryCards() {
  const grid = document.getElementById('canaryCardsGrid');
  if (cachedCanaries.length === 0) {
    grid.innerHTML = '<div class="col-span-2 text-center py-8 text-slate-500">No canaries configured.</div>';
    return;
  }

  grid.innerHTML = cachedCanaries.map(c => {
    const isTripped = c.downloads > 0;
    const borderClass = isTripped ? 'border-amber-500/60 bg-amber-950/10' : 'border-slate-800 bg-slate-900/40';

    return `
      <div class="border ${borderClass} rounded-2xl p-5 flex flex-col justify-between">
        <div>
          <div class="flex items-center justify-between mb-3">
            <span class="font-mono text-sm font-bold text-white">${escapeHtml(c.filename)}</span>
            <span class="px-2 py-0.5 rounded text-[10px] font-mono ${isTripped ? 'bg-amber-950 text-amber-300 border border-amber-800' : 'bg-slate-800 text-slate-400'}">
              ${isTripped ? 'TRIPPED (' + c.downloads + 'x)' : 'QUIET'}
            </span>
          </div>
          <p class="text-xs text-slate-400 mb-3">${escapeHtml(c.description)}</p>
          <div class="text-[11px] font-mono text-slate-500">
            Type: <span class="text-slate-300">${c.type}</span> &bull;
            Downloads: <span class="text-white font-bold">${c.downloads}</span>
          </div>
        </div>
        <div class="mt-4 pt-3 border-t border-slate-800 text-[11px] text-slate-400">
          Last Accessed: <span class="text-amber-400 font-mono">${c.last_accessed ? c.last_accessed : 'Never'}</span>
        </div>
      </div>
    `;
  }).join('');
}

// Fetch blocklist
async function loadBlocklist() {
  const token = getAdminToken();
  try {
    const res = await fetch(`/admin/blocklist?token=${encodeURIComponent(token)}`);
    if (!res.ok) return;
    cachedBlocklist = await res.json();
    if (activeTab === 'blocklist') renderBlocklistTable();
  } catch (err) {
    console.error("Failed to fetch blocklist:", err);
  }
}

function renderBlocklistTable() {
  const tbody = document.getElementById('blocklistTableBody');
  const ips = cachedBlocklist.ips || [];

  if (ips.length === 0) {
    tbody.innerHTML = `<tr><td colspan="3" class="py-8 text-center text-slate-500">Firewall blocklist is empty.</td></tr>`;
    return;
  }

  tbody.innerHTML = ips.map(ip => `
    <tr class="hover:bg-slate-900/60 transition">
      <td class="py-3 px-4 font-bold text-rose-400">${escapeHtml(ip)}</td>
      <td class="py-3 px-4 text-slate-400 text-xs">
        <span class="px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800 text-[10px]">
          DROP_TCP_403
        </span>
      </td>
      <td class="py-3 px-4 text-right">
        <button onclick="removeIpFromBlocklist('${ip}')" class="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs transition">
          Unblock
        </button>
      </td>
    </tr>
  `).join('');
}

async function quickBlockIp(ip) {
  if (!confirm(`Are you sure you want to block IP address ${ip}?`)) return;
  const token = getAdminToken();
  try {
    const res = await fetch(`/admin/blocklist?token=${encodeURIComponent(token)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip })
    });
    const data = await res.json();
    if (data.ok) {
      alert(`IP ${ip} has been added to the firewall blocklist.`);
      refreshAllData();
    } else {
      alert(data.message || 'Failed to block IP');
    }
  } catch (err) {
    alert('Network error when attempting to block IP');
  }
}

async function addIpToBlocklist() {
  const ip = document.getElementById('blockIpInput').value.trim();
  if (!ip) return;
  await quickBlockIp(ip);
  document.getElementById('blockIpInput').value = '';
}

async function removeIpFromBlocklist(ip) {
  const token = getAdminToken();
  try {
    const res = await fetch(`/admin/blocklist?token=${encodeURIComponent(token)}`, {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip })
    });
    const data = await res.json();
    if (data.ok) {
      alert(`IP ${ip} has been removed from blocklist.`);
      refreshAllData();
    }
  } catch (err) {
    alert('Failed to remove IP');
  }
}

// Attack Simulator Trigger
async function triggerSimulation(type) {
  const token = getAdminToken();
  try {
    const res = await fetch(`/admin/simulate?token=${encodeURIComponent(token)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type })
    });
    const data = await res.json();
    if (data.ok) {
      alert(`[Simulation Successful]\n${data.message}`);
      refreshAllData();
      if (type === 'brute_force') switchTab('trapped');
      else switchTab('logs');
    } else {
      alert(data.message || 'Simulation error');
    }
  } catch (err) {
    alert('Error running attack simulation');
  }
}

// Save Adaptive Configuration
async function saveAdaptiveConfig() {
  const token = getAdminToken();
  const tarpit = document.getElementById('tarpitToggle').checked;
  const maxDelay = parseFloat(document.getElementById('maxDelayInput').value) || 3.0;
  const persona = document.getElementById('personaSelect').value;

  try {
    const res = await fetch(`/admin/adaptive-config?token=${encodeURIComponent(token)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tarpit_enabled: tarpit,
        max_delay: maxDelay,
        persona: persona
      })
    });
    const data = await res.json();
    if (data.ok) {
      alert("Adaptive Engine settings updated successfully!");
      refreshAllData();
    } else {
      alert(data.message || 'Failed to update configuration');
    }
  } catch (err) {
    alert('Error saving configuration');
  }
}

// Clear all telemetry logs
async function clearAllTelemetry() {
  if (!confirm("Are you sure you want to reset all honeypot telemetry and trapped sessions?")) return;
  const token = getAdminToken();
  try {
    const res = await fetch(`/admin/clear?token=${encodeURIComponent(token)}`, {
      method: 'POST'
    });
    const data = await res.json();
    if (data.ok) {
      alert("All telemetry and trap sessions have been reset.");
      refreshAllData();
    }
  } catch (err) {
    alert("Error clearing telemetry");
  }
}

function refreshAllData() {
  loadStats();
  loadLogs();
  loadTrapped();
  loadCanaries();
  loadBlocklist();
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// Polling initialization
document.addEventListener('DOMContentLoaded', () => {
  refreshAllData();
  // Poll every 3 seconds for live threat feed
  setInterval(() => {
    loadStats();
    loadLogs();
    if (activeTab === 'trapped') loadTrapped();
    if (activeTab === 'canaries') loadCanaries();
  }, 3000);
});
