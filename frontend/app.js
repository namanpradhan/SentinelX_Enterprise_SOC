const API = window.SENTINELX_API || (location.protocol.startsWith('http') ? location.origin : 'http://127.0.0.1:8000');
const VERSION = '4.2.13';
const state = {
  view: 'overview',
  data: { overview:{counts:{}}, alerts:[], incidents:[], events:[], devices:[], rules:[], activity:[], local:{}, trends:[], severity:[], topRules:[], system:null, vulnerabilities:[], vulnSummary:{}, vulnStatus:{}, idsips:null, idsAlerts:[], metasploit:null, msfCatalog:[], aiStatus:null },
  connected: false,
  user: null,
  token: sessionStorage.getItem('sentinelx_token') || '',
  sort: {field:'', dir:'desc'},
  permissions: [],
  autoDiscovery: localStorage.getItem('sentinelx_auto_discovery') === 'true',
  seenAlerts: new Set(),
  lastAlertId: 0,
  session: null,
  warnedSession: false,
  loadInFlight: false,
};

const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmt = t => t ? new Date(t).toLocaleString() : '—';
const ago = t => {
  if (!t) return '—';
  const m = Math.max(0, Math.floor((Date.now() - new Date(t)) / 60000));
  return m < 1 ? 'just now' : m < 60 ? `${m}m ago` : m < 1440 ? `${Math.floor(m/60)}h ago` : `${Math.floor(m/1440)}d ago`;
};
const sev = s => `<span class="pill sev-${esc(s)}">${esc(String(s || 'unknown').toUpperCase())}</span>`;
const status = s => `<span class="pill status-${esc(s)}">${esc(s)}</span>`;
const iconFor = p => ({Windows:'▣','Windows/Server':'▣','Windows Server':'▣',macOS:'●',Linux:'◉',Android:'▤',iOS:'▤',Firewall:'⬢',Router:'⌁',Switch:'▥','Smart TV':'▣',IoT:'◌',Cloud:'☁','Network Discovered':'⌁'}[p] || '◈');
const can = p => state.permissions.includes(p);

function authHeaders(opts = {}) {
  return {
    ...opts,
    headers: {
      'Content-Type': 'application/json',
      ...(state.token ? { Authorization: `Bearer ${state.token}` } : {}),
      ...(opts.headers || {})
    }
  };
}

async function api(path, opts = {}) {
  const timeout = opts.timeout || 12000;
  const fetchOpts = {...opts}; delete fetchOpts.timeout;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  let response;
  try {
    response = await fetch(API + path, {...authHeaders(fetchOpts), signal: controller.signal});
  } catch (e) {
    if (e.name === 'AbortError') throw new Error(`Request timed out: ${path}`);
    throw new Error(`Cannot reach SentinelX API at ${API}`);
  } finally { clearTimeout(timer); }
  if (response.status === 401 && !path.startsWith('/auth/login')) {
    state.token = ''; state.user = null; state.permissions = [];
    sessionStorage.removeItem('sentinelx_token'); showLogin();
    throw new Error('Session expired. Please sign in again.');
  }
  const text = await response.text();
  let data = {};
  try { data = text ? JSON.parse(text) : {}; } catch { throw new Error(`Invalid API response (${response.status})`); }
  if (!response.ok) throw new Error(data.detail || data.message || `API error ${response.status}`);
  return data;
}

async function publicHealth() {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);
    const r = await fetch(`${API}/health`, {signal: controller.signal});
    clearTimeout(timer);
    const d = await r.json();
    const el = document.getElementById('loginBackendState');
    if (el) { el.textContent = r.ok ? `SentinelX API online • v${d.version || VERSION}` : 'SentinelX API unavailable'; el.className = `login-status ${r.ok?'good':'bad'}`; }
    return r.ok;
  } catch {
    const el = document.getElementById('loginBackendState');
    if (el) { el.textContent = `API offline • start SentinelX on ${API}`; el.className = 'login-status bad'; }
    return false;
  }
}

function toast(msg, type='') {
  const e = document.createElement('div');
  e.className = `toast ${type}`;
  e.innerHTML = `<b>${type==='bad'?'Attention':type==='good'?'Success':'SentinelX'}</b><div>${esc(msg)}</div>`;
  document.getElementById('toasts').appendChild(e);
  setTimeout(() => e.remove(), 5000);
}

function liveThreat(a) {
  const e = document.createElement('div');
  e.className = `live-threat ${a.severity}`;
  e.innerHTML = `<div class="lt-top"><span class="pulse-dot"></span><b>LIVE THREAT ALERT</b><button onclick="this.parentElement.parentElement.remove()">×</button></div><strong>${esc(a.rule)}</strong><small>${esc(a.severity).toUpperCase()} • Risk ${a.risk_score} • ${ago(a.created_at)}</small><p>${esc(a.description||'')}</p><div class="hero-actions"><button class="btn" onclick="showAlert(${a.id})">Open alert</button></div>`;
  document.getElementById('liveThreats').prepend(e);
  setTimeout(() => e.remove(), 10000);
  try {
    const Ctx = window.AudioContext || window.webkitAudioContext;
    if (Ctx && document.visibilityState === 'visible') {
      const ctx = new Ctx(); const osc = ctx.createOscillator(); const gain = ctx.createGain();
      osc.frequency.value = a.severity === 'critical' ? 880 : 660; gain.gain.value = 0.045;
      osc.connect(gain); gain.connect(ctx.destination); osc.start(); osc.stop(ctx.currentTime + 0.12);
    }
  } catch {}
}

function saveToken(t) { state.token = t; sessionStorage.setItem('sentinelx_token', t); }

async function login(username, password) {
  let r;
  try {
    r = await fetch(API+'/auth/login', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({username,password})});
  } catch { throw new Error(`Cannot reach SentinelX API at ${API}. Start the backend first.`); }
  const text = await r.text(); let d = {}; try { d = text ? JSON.parse(text) : {}; } catch { throw new Error('The API returned an invalid response.'); }
  if (!r.ok) throw new Error(d.detail || 'Login failed');
  saveToken(d.access_token); state.user = d.user; state.permissions = d.permissions || [];
  return d;
}

async function logout(silent=false) {
  try { if (state.token) await api('/auth/logout',{method:'POST',timeout:5000}); } catch {}
  state.token=''; state.user=null; state.permissions=[]; state.session=null;
  sessionStorage.removeItem('sentinelx_token'); showLogin();
  if (!silent) toast('Signed out securely.','good');
}

async function logoutAll() {
  try { await api('/auth/logout-all',{method:'POST'}); } catch (e) { toast(e.message,'bad'); return; }
  state.token=''; state.user=null; state.permissions=[]; state.session=null; sessionStorage.removeItem('sentinelx_token');
  showLogin(); toast('All active sessions were signed out.','good');
}

async function bootstrapAuth() {
  if (!state.token) { showLogin(); return false; }
  try { const d=await api('/auth/me'); state.user=d.user; state.permissions=d.permissions||[]; sessionStorage.setItem('sentinelx_token', state.token); localStorage.removeItem('sentinelx_token'); return true; }
  catch { state.token=''; sessionStorage.removeItem('sentinelx_token'); showLogin(); return false; }
}

function showLogin() { document.getElementById('loginScreen').classList.remove('hidden'); document.getElementById('app').classList.add('hidden'); publicHealth(); }
function showApp() { document.getElementById('loginScreen').classList.add('hidden'); document.getElementById('app').classList.remove('hidden'); document.getElementById('topUser').textContent=state.user?.display_name||state.user?.username||'—'; document.getElementById('topRole').textContent=(state.user?.role||'').toUpperCase(); }

async function health() {
  try {
    const h = await api('/health', {timeout:5000}); state.connected=true;
    document.getElementById('backendState').textContent='Backend connected'; document.getElementById('collectorDot').classList.remove('bad'); return h;
  } catch (e) {
    state.connected=false; document.getElementById('backendState').textContent='Backend offline'; document.getElementById('collectorDot').classList.add('bad'); return null;
  }
}

async function safe(name, fn, fallback) {
  try { return await fn(); } catch (e) { console.warn(name, e); return fallback; }
}

async function load(forceRender=true) {
  if (!state.token || state.loadInFlight) return;
  state.loadInFlight=true;
  try {
    const h=await health();
    if(!h){ if(forceRender) toast(`Backend unavailable at ${API}. Start the SentinelX API service.`,'bad'); return; }
    const results = await Promise.all([
      safe('overview',()=>api('/soc/overview'),state.data.overview),
      safe('alerts',()=>api('/alerts/?limit=1000'),state.data.alerts),
      safe('incidents',()=>api('/incidents/?limit=500'),state.data.incidents),
      safe('events',()=>api('/events/?limit=1000'),state.data.events),
      safe('devices',()=>api('/devices/?limit=1000'),state.data.devices),
      safe('rules',()=>api('/rules/?sort=risk&direction=desc'),state.data.rules),
      safe('activity',()=>api('/soc/activity?limit=100'),state.data.activity),
      safe('local',()=>api('/network/local'),state.data.local),
      safe('networkLive',()=>api('/network/live',{timeout:15000}),state.data.networkLive),
      safe('trends',()=>api('/dashboard/trends?hours=24'),state.data.trends),
      safe('severity',()=>api('/dashboard/severity'),state.data.severity),
      safe('topRules',()=>api('/dashboard/rules-top'),state.data.topRules),
      safe('system',()=>api('/system/status'),state.data.system),
      safe('vulnerabilities',()=>api('/vulnerabilities/findings?limit=500'),state.data.vulnerabilities),
      safe('vulnSummary',()=>api('/vulnerabilities/summary'),state.data.vulnSummary),
      safe('vulnStatus',()=>api('/vulnerabilities/status'),state.data.vulnStatus),
      safe('idsips',()=>api('/integrations/idsips/status'),state.data.idsips),
      safe('idsAlerts',()=>api('/integrations/idsips/alerts?limit=60'),state.data.idsAlerts),
      safe('metasploit',()=>api('/integrations/metasploit/status'),state.data.metasploit),
      safe('msfCatalog',()=>api('/integrations/metasploit/search?limit=200'),state.data.msfCatalog),
      safe('aiStatus',()=>api('/ai/status'),state.data.aiStatus),
    ]);
    [state.data.overview,state.data.alerts,state.data.incidents,state.data.events,state.data.devices,state.data.rules,state.data.activity,state.data.local,state.data.networkLive,state.data.trends,state.data.severity,state.data.topRules,state.data.system,state.data.vulnerabilities,state.data.vulnSummary,state.data.vulnStatus,state.data.idsips,state.data.idsAlerts,state.data.metasploit,state.data.msfCatalog,state.data.aiStatus]=results;
    detectNewAlerts(state.data.alerts||[]);
    const active=document.activeElement;
    const editing=active && ['INPUT','SELECT','TEXTAREA'].includes(active.tagName);
    const shouldRender = forceRender || (!editing && state.view==='overview');
    if (shouldRender) render();
    await refreshSessionInfo(false);
  } finally { state.loadInFlight=false; }
}

function detectNewAlerts(alerts) {
  for(const a of alerts||[]) {
    if(!state.seenAlerts.has(a.id)) {
      state.seenAlerts.add(a.id);
      if(state.lastAlertId>0 && a.id>state.lastAlertId && ['critical','high'].includes(a.severity)) liveThreat(a);
    }
    state.lastAlertId=Math.max(state.lastAlertId,a.id||0);
  }
  if(state.seenAlerts.size>1500) state.seenAlerts=new Set([...state.seenAlerts].slice(-700));
}

async function refreshSessionInfo(showWarning=true) {
  if(!state.token) return;
  const info=await safe('session',()=>api('/auth/session',{timeout:5000}),null);
  if(!info) return;
  state.session=info; updateSessionClock();
  if(showWarning && info.remaining_seconds<=180 && !state.warnedSession){state.warnedSession=true;toast('Session expires soon. Save your work or sign in again.','bad');}
  if(info.remaining_seconds>300) state.warnedSession=false;
}

function updateSessionClock() {
  const el=document.getElementById('sessionTimer'); if(!el) return;
  const s=state.session?.remaining_seconds;
  if(s==null){el.textContent='—'; return;}
  const h=Math.floor(s/3600), m=Math.floor((s%3600)/60), sec=s%60;
  el.textContent=`${h?`${h}h `:''}${String(m).padStart(2,'0')}:${String(sec).padStart(2,'0')}`;
  el.classList.toggle('warn',s<180);
}

const titles={overview:'Command Center',devices:'Device Fleet',network:'Network Discovery',alerts:'Threat Queue',incidents:'Incident Response',events:'Event Stream',mitre:'ATT&CK Coverage',rules:'Detection Engineering',ai:'AI Analyst',iam:'Identity & Access',vulnerabilities:'Vulnerability Scanner',idsips:'IDS / IPS',metasploit:'Exploit Intelligence',reports:'Reports & Export',security:'Security Center'};
const navItems=[['overview','◈','Command Center'],['devices','▦','Device Fleet'],['network','⌁','Network Discovery'],['alerts','⚠','Threat Queue'],['incidents','◎','Incident Response'],['events','≋','Event Stream'],['mitre','⊞','ATT&CK Coverage'],['rules','◇','Detection Engineering'],['ai','✦','AI Analyst'],['vulnerabilities','◍','Vulnerability Scanner'],['idsips','◈','IDS / IPS'],['metasploit','⌁','Exploit Intelligence'],['iam','♙','Identity & Access'],['reports','▤','Reports & Export'],['security','◈','Security Center']];

function buildNav(){
  const items=navItems.filter(x=>x[0]!=='iam'||can('iam.read'));
  document.getElementById('nav').innerHTML=items.map((x,i)=>`<button class="nav-item ${state.view===x[0]?'active':''}" data-view="${x[0]}"><span>${x[1]}</span>${x[2]}<kbd>${i+1}</kbd>${x[0]==='alerts'?`<em id="navAlertCount">${state.data.overview?.counts?.open_alerts||0}</em>`:''}</button>`).join('');
  document.querySelectorAll('.nav-item').forEach(b=>b.onclick=()=>setView(b.dataset.view));
}
function setView(v){state.view=v;document.getElementById('viewTitle').textContent=titles[v]||v;document.querySelector('.sidebar').classList.remove('open');render();}
function metric(l,v,s){return`<div class="card metric"><div class="label">${l}</div><div class="value">${v}</div><div class="sub">${s}</div></div>`;}
function shell(t,p,b,a=''){return`<div class="hero"><div><div class="eyebrow">SENTINELX / ENTERPRISE SOC</div><h1>${t}</h1><p>${p}</p></div><div class="hero-actions">${a}</div></div>${b}`;}
function render(force=true){buildNav(); const views={overview,devices,network,alerts,incidents,events,mitre,rules,ai,vulnerabilities,idsips,metasploit,iam,reports,security}; document.getElementById('view').innerHTML=(views[state.view]||overview)(); bindView();}

function svgLines(data){
  if(!data?.length) return '<div class="empty">No trend data available.</div>';
  const w=760,h=220,p=34,max=Math.max(1,...data.flatMap(x=>[Number(x.events||0),Number(x.alerts||0)]));
  const points=(key)=>data.map((x,i)=>`${p+(i/Math.max(1,data.length-1))*(w-2*p)},${h-p-(Number(x[key]||0)/max)*(h-2*p)}`).join(' ');
  return `<svg viewBox="0 0 ${w} ${h}" class="chart"><polyline points="${points('events')}" fill="none" stroke="#49dcff" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/><polyline points="${points('alerts')}" fill="none" stroke="#ff5572" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/><line x1="${p}" x2="${w-p}" y1="${h-p}" y2="${h-p}" stroke="#253449"/>${data.filter((_,i)=>i%Math.max(1,Math.floor(data.length/6))===0).map(x=>`<text x="${p}" y="${h-7}" class="chart-label">${esc(x.label)}</text>`).join('')}</svg>`;
}

function overview(){
  const o=state.data.overview||{counts:{},top_rules:[]},c=o.counts||{},r=Math.round(o.posture_score||0),sevData=state.data.severity||[],trend=state.data.trends||[];
  const hasLiveData=Boolean((c.events||0)||(c.open_alerts||0)||(c.devices||0)||(state.data.activity||[]).length);
  const liveBanner=hasLiveData?'':`<div class="card onboarding"><div><div class="eyebrow">LIVE ENVIRONMENT</div><h3>Awaiting authorized telemetry</h3><p class="muted">No synthetic devices, events or alerts are loaded. Start with Network Discovery or connect an endpoint or IDS collector.</p></div><div class="hero-actions"><button class="btn primary" onclick="setView('network')">Discover Network</button><button class="btn" onclick="setView('devices')">Open Device Fleet</button><button class="btn" onclick="setView('idsips')">Configure IDS / IPS</button></div></div>`;
  return shell('Security Command Center','Unified monitoring, identity, network discovery, deterministic detections and response.', liveBanner+
    `<div class="grid metrics">${metric('SECURITY EVENTS',c.events||0,'normalized telemetry')}${metric('OPEN ALERTS',c.open_alerts||0,'analyst queue')}${metric('CRITICAL',c.critical_alerts||0,'priority alerts')}${metric('OPEN INCIDENTS',c.open_incidents||0,'active cases')}${metric('DEVICE FLEET',c.devices||0,`${c.online_devices||0} online`)}${metric('VULNERABILITIES',state.data.vulnSummary?.open||0,'open findings')}${metric('POSTURE',`${r}/100`,r>70?'elevated':r>40?'moderate':'controlled')}</div>
    <div class="grid two"><div class="card"><div class="card-head"><h3>THREAT ACTIVITY · 24 HOURS</h3><span>events vs alerts</span></div><div class="card-body">${svgLines(trend)}<div class="legend"><span><i class="l cyan"></i>Events</span><span><i class="l red"></i>Alerts</span></div></div></div>
    <div class="card"><div class="card-head"><h3>SEVERITY DISTRIBUTION</h3><span>current alert set</span></div><div class="card-body severity-bars">${sevData.map(x=>`<div><div class="split"><span>${esc(x.severity.toUpperCase())}</span><b>${x.count}</b></div><div class="bar"><i style="width:${Math.min(100,(x.count/Math.max(1,...sevData.map(z=>z.count)))*100)}%;background:${x.severity==='critical'?'var(--red)':x.severity==='high'?'#ff7d5a':x.severity==='medium'?'var(--amber)':'var(--green)'}"></i></div></div>`).join('')||'<div class="empty">No alerts.</div>'}</div></div></div>
    <div class="grid three"><div class="card"><div class="card-head"><h3>LIVE ACTIVITY</h3><span>auto refresh</span></div><div class="card-body feed">${(state.data.activity||[]).slice(0,14).map(a=>`<div class="feed-row"><i class="feed-dot ${a.severity}"></i><div><b>${esc(a.title)}</b><small>${esc(a.description)} • ${ago(a.time)}</small></div></div>`).join('')||'<div class="empty">No activity.</div>'}</div></div>
    <div class="card"><div class="card-head"><h3>NETWORK SNAPSHOT</h3><span>${esc(state.data.local?.subnet||'—')}</span></div><div class="card-body"><p class="muted">Local endpoint: <b>${esc(state.data.local?.local_ip||'—')}</b> • ARP neighbors: <b>${state.data.local?.arp_entries||0}</b></p><p class="muted">Gateway: <b>${esc(state.data.local?.gateway||'—')}</b> • Wi-Fi: <b>${state.data.local?.wifi?.connected?esc(state.data.local?.wifi?.ssid||'connected'):'not detected'}</b> • Visible peers: <b>${state.data.networkLive?.visible_peers?.length||0}</b></p><div class="toolbar"><button class="btn primary" id="discoverBtn">⌁ Deep Discover</button><button class="btn" id="openNetwork">Open Network</button></div></div></div>
    <div class="card"><div class="card-head"><h3>TOP DETECTIONS</h3><span>${(state.data.topRules||[]).length}</span></div><div class="card-body">${(state.data.topRules||[]).map(x=>`<div class="split list-row"><span>${esc(x.rule)}</span><b>${x.count}</b></div>`).join('')||'<div class="empty">No detections.</div>'}</div></div></div>`);
}

function controlBar(kind){
  const base='<input id="tableSearch" class="search" placeholder="Search…">';
  if(kind==='alerts') return `<div class="toolbar">${base}<select id="severityFilter" class="select"><option value="">Severity: All</option><option>critical</option><option>high</option><option>medium</option><option>low</option></select><select id="statusFilter" class="select"><option value="">Status: All</option><option>open</option><option>acknowledged</option><option>closed</option></select><select id="mitreFilter" class="select"><option value="">MITRE: All</option>${[...new Set((state.data.alerts||[]).map(x=>x.mitre_technique).filter(Boolean))].sort().map(x=>`<option>${esc(x)}</option>`).join('')}</select><select id="riskFilter" class="select"><option value="0">Risk: Any</option><option value="50">≥ 50</option><option value="70">≥ 70</option><option value="85">≥ 85</option></select><select id="alertSort" class="select"><option value="created_at">Newest</option><option value="risk_score">Risk</option><option value="severity">Severity</option><option value="rule">Rule</option></select><span id="filterCount" class="filter-count"></span><button id="clearFilters" class="btn">Clear</button></div>`;
  if(kind==='events') return `<div class="toolbar">${base}<select id="severityFilter" class="select"><option value="">Severity: All</option><option>critical</option><option>high</option><option>medium</option><option>low</option></select><select id="eventSource" class="select"><option value="">Source: All</option>${[...new Set((state.data.events||[]).map(x=>x.source))].sort().map(x=>`<option>${esc(x)}</option>`).join('')}</select><select id="eventType" class="select"><option value="">Type: All</option>${[...new Set((state.data.events||[]).map(x=>x.event_type))].sort().map(x=>`<option>${esc(x)}</option>`).join('')}</select><select id="eventSort" class="select"><option value="timestamp">Newest</option><option value="severity">Severity</option><option value="event_type">Event type</option></select><span id="filterCount" class="filter-count"></span><button id="clearFilters" class="btn">Clear</button></div>`;
  if(kind==='devices') return `<div class="toolbar">${base}<select id="platformFilter" class="select"><option value="">Platform: All</option>${[...new Set((state.data.devices||[]).map(d=>d.platform))].sort().map(x=>`<option>${esc(x)}</option>`).join('')}</select><select id="deviceType" class="select"><option value="">Type: All</option>${[...new Set((state.data.devices||[]).map(d=>d.device_type))].sort().map(x=>`<option>${esc(x)}</option>`).join('')}</select><select id="deviceSource" class="select"><option value="">Source: All</option>${[...new Set((state.data.devices||[]).map(d=>d.source).filter(Boolean))].sort().map(x=>`<option>${esc(x)}</option>`).join('')}</select><select id="statusFilter" class="select"><option value="">Status: All</option><option>online</option><option>degraded</option><option>offline</option><option>unknown</option></select><select id="deviceRisk" class="select"><option value="0">Risk: Any</option><option value="40">≥ 40</option><option value="70">≥ 70</option></select><select id="deviceSort" class="select"><option value="last_seen">Newest seen</option><option value="risk_score">Risk</option><option value="name">Name</option></select><button id="discoverBtn" class="btn primary">⌁ Deep Discover</button><span id="filterCount" class="filter-count"></span><button id="clearFilters" class="btn">Clear</button></div>`;
  if(kind==='incidents') return `<div class="toolbar">${base}<select id="severityFilter" class="select"><option value="">Severity: All</option><option>critical</option><option>high</option><option>medium</option><option>low</option></select><select id="statusFilter" class="select"><option value="">Status: All</option><option>open</option><option>investigating</option><option>resolved</option></select><select id="incidentSort" class="select"><option value="updated_at">Newest</option><option value="risk_score">Risk</option><option value="severity">Severity</option></select><span id="filterCount" class="filter-count"></span><button id="clearFilters" class="btn">Clear</button></div>`;
  if(kind==='rules') return `<div class="toolbar">${base}<select id="ruleSeverity" class="select"><option value="">Severity: All</option><option>critical</option><option>high</option><option>medium</option><option>low</option></select><select id="ruleCategory" class="select"><option value="">Category: All</option>${[...new Set((state.data.rules||[]).map(x=>x.category))].sort().map(x=>`<option>${esc(x)}</option>`).join('')}</select><select id="ruleTactic" class="select"><option value="">Tactic: All</option>${[...new Set((state.data.rules||[]).map(x=>x.tactic))].sort().map(x=>`<option>${esc(x)}</option>`).join('')}</select><select id="ruleEnabled" class="select"><option value="">State: All</option><option value="true">Enabled</option><option value="false">Disabled</option></select><select id="ruleSort" class="select"><option value="risk">Risk</option><option value="id">Rule</option><option value="severity">Severity</option></select><button id="clearFilters" class="btn">Clear</button><span id="filterCount" class="filter-count"></span></div>`;
  return '';
}

function alerts(){const rows=state.data.alerts||[];return shell('Threat Queue','Prioritized detections with filtering, sorting, response actions and investigation.',controlBar('alerts')+`<div class="card"><div class="table-wrap"><table class="table"><thead><tr><th>ID</th><th>Rule</th><th>Severity</th><th>Risk</th><th>Status</th><th>MITRE</th><th>Created</th><th>Action</th></tr></thead><tbody id="dataRows">${rows.map(a=>`<tr data-search="${esc(`${a.rule} ${a.description} ${a.mitre_technique||''}`)}" data-severity="${a.severity}" data-status="${a.status}" data-mitre="${esc(a.mitre_technique||'')}" data-risk="${a.risk_score}" data-sort-created_at="${a.created_at||''}" data-sort-risk_score="${a.risk_score}" data-sort-rule="${esc(a.rule)}" data-sort-severity="${a.severity}"><td>#${a.id}</td><td><b>${esc(a.rule)}</b><br><small>${esc(a.description)}</small></td><td>${sev(a.severity)}</td><td><b>${a.risk_score}</b></td><td>${status(a.status)}</td><td>${esc(a.mitre_technique||'—')}</td><td>${ago(a.created_at)}</td><td><button class="btn" onclick="showAlert(${a.id})">Open</button></td></tr>`).join('')||'<tr><td colspan="8"><div class="empty">No alerts.</div></td></tr>'}</tbody></table></div></div>`);}

function incidents(){const rows=state.data.incidents||[];return shell('Incident Response','Correlated cases with investigation and operational lifecycle management.',controlBar('incidents')+`<div class="card"><div class="table-wrap"><table class="table"><thead><tr><th>ID</th><th>Incident</th><th>Severity</th><th>Risk</th><th>Status</th><th>Host</th><th>Updated</th><th>Action</th></tr></thead><tbody id="dataRows">${rows.map(i=>`<tr data-search="${esc(`${i.title} ${i.summary} ${i.hostname||''} ${i.username||''}`)}" data-severity="${i.severity}" data-status="${i.status}" data-sort-updated_at="${i.updated_at||''}" data-sort-risk_score="${i.risk_score}" data-sort-severity="${i.severity}"><td>#${i.id}</td><td><b>${esc(i.title)}</b><br><small>${esc(i.summary)}</small></td><td>${sev(i.severity)}</td><td>${i.risk_score}</td><td>${status(i.status)}</td><td>${esc(i.hostname||'—')}</td><td>${ago(i.updated_at)}</td><td><button class="btn" onclick="showIncident(${i.id})">Open</button></td></tr>`).join('')||'<tr><td colspan="8"><div class="empty">No incidents.</div></td></tr>'}</tbody></table></div></div>`);}

function events(){const rows=state.data.events||[];return shell('Event Stream','Normalized telemetry with platform, source, severity and event-type filtering.',controlBar('events')+`<div class="card"><div class="table-wrap"><table class="table"><thead><tr><th>ID</th><th>Time</th><th>Source</th><th>Type</th><th>Severity</th><th>Host</th><th>User</th><th>Message</th></tr></thead><tbody id="dataRows">${rows.map(e=>`<tr data-search="${esc(`${e.source} ${e.event_type} ${e.hostname||''} ${e.username||''} ${e.message||''}`)}" data-severity="${e.severity}" data-source="${esc(e.source)}" data-event-type="${esc(e.event_type)}" data-sort-timestamp="${e.timestamp||''}" data-sort-event_type="${esc(e.event_type)}" data-sort-severity="${e.severity}"><td>#${e.id}</td><td>${fmt(e.timestamp)}</td><td>${esc(e.source)}</td><td>${esc(e.event_type)}</td><td>${sev(e.severity)}</td><td>${esc(e.hostname||'—')}</td><td>${esc(e.username||'—')}</td><td>${esc(e.message||'')}</td></tr>`).join('')||'<tr><td colspan="8"><div class="empty">No events.</div></td></tr>'}</tbody></table></div></div>`);}

function devices(){const rows=state.data.devices||[];return shell('Device Fleet','Asset inventory with deep network discovery, health, source, risk and posture.',controlBar('devices')+`<div class="device-grid" id="deviceRows">${rows.map(d=>`<div class="card device" data-search="${esc(`${d.name} ${d.hostname||''} ${d.ip_address||''} ${d.platform} ${d.device_type} ${d.source||''}`)}" data-platform="${esc(d.platform)}" data-status="${d.status}" data-type="${esc(d.device_type)}" data-source="${esc(d.source||'')}" data-risk="${d.risk_score||0}" data-sort-last_seen="${d.last_seen||''}" data-sort-risk_score="${d.risk_score||0}" data-sort-name="${esc(d.name)}" onclick="showDevice(${d.id})"><div class="device-top"><div class="device-icon">${iconFor(d.platform)}</div>${status(d.status)}</div><h4>${esc(d.name)}</h4><p>${esc(d.hostname||'—')} • ${esc(d.ip_address||'no IP')}</p><p>${esc(d.platform)} • ${esc(d.device_type)} • ${esc(d.source||'—')}</p><div class="risk"><div class="risk-row"><span>Risk</span><b>${d.risk_score}/100</b></div><div class="bar"><i style="width:${Math.min(100,d.risk_score||0)}%;background:${d.risk_score>70?'var(--red)':d.risk_score>40?'var(--amber)':'var(--green)'}"></i></div></div></div>`).join('')||'<div class="empty card">No devices registered.</div>'}</div>`);}

function network(){
  const l=state.data.local||{}, w=l.wifi||{}, live=state.data.networkLive||{};
  const peers4=live.local?.ipv4_neighbors||l.ipv4_neighbors||l.neighbors||[];
  const peers6=live.local?.ipv6_neighbors||l.ipv6_neighbors||[];
  const observed=(state.data.devices||[]).filter(d=>d.source==='network_discovery'&&d.status==='online');
  const wifiLabel=w.connected ? `${w.ssid||'Wi‑Fi'} • ${w.signal||'signal unavailable'}` : 'Wi‑Fi not connected';
  const ipv4=l.wifi_subnet||l.subnet||'—';
  const ipv6=(l.local_ipv6||[]).join('<br>')||'—';
  return shell('Network Discovery','Inspect the network actually visible to this Windows host. SentinelX uses the active Wi‑Fi interface, IPv4 ARP/ICMP/TCP discovery and the IPv6 neighbor table without inventing devices.',
    `<div class="card onboarding network-hero"><div><div class="eyebrow">LOCAL NETWORK VISIBILITY</div><h3>${esc(wifiLabel)}</h3><p class="muted">Interface: <b>${esc(l.primary_interface||w.interface||'—')}</b> • IPv4: <b>${esc(l.local_ipv4||l.local_ip||'—')}</b> • Subnet: <b>${esc(ipv4)}</b></p><p class="muted small">SentinelX never fabricates a device. A device appears only after it is visible to the host network stack or discovered by an installed authorized scanner.</p></div><div class="hero-actions"><button class="btn primary" id="discoverBtn">⌁ Scan Connected Network</button><button class="btn" id="refreshNetworkBtn">↻ Refresh Visibility</button><button class="btn" id="scanIpv6Btn">◇ Scan IPv6 Neighbors</button></div></div>
    <div class="grid metrics compact-metrics"><div class="card metric"><div class="label">VISIBLE IPv4 PEERS</div><div class="value">${peers4.length}</div><div class="sub">ARP / neighbor / active probe</div></div><div class="card metric"><div class="label">VISIBLE IPv6 PEERS</div><div class="value">${peers6.length}</div><div class="sub">Windows IPv6 neighbor table</div></div><div class="card metric"><div class="label">OBSERVED DEVICES</div><div class="value">${observed.length}</div><div class="sub">online network-discovered assets</div></div><div class="card metric"><div class="label">GATEWAY</div><div class="value metric-ip">${esc(l.gateway||'—')}</div><div class="sub">default route</div></div></div>
    <div class="grid three"><div class="card"><div class="card-head"><h3>CONNECTED WI‑FI</h3><span>${w.connected?'CONNECTED':'NOT CONNECTED'}</span></div><div class="card-body"><p><b>SSID:</b> ${esc(w.ssid||'—')}</p><p><b>BSSID:</b> ${esc(w.bssid||'—')}</p><p><b>Signal:</b> ${esc(w.signal||'—')}</p><p><b>Channel:</b> ${esc(w.channel||'—')}</p><p><b>Interface:</b> ${esc(w.interface||l.primary_interface||'—')}</p></div></div><div class="card"><div class="card-head"><h3>IPv4 NETWORK</h3><span>ACTIVE INTERFACE</span></div><div class="card-body"><p><b>Address:</b> ${esc(l.local_ipv4||l.local_ip||'—')}</p><p><b>Subnet:</b> ${esc(ipv4)}</p><p><b>Gateway:</b> ${esc(l.gateway||'—')}</p><p><b>Visible ARP:</b> ${l.arp_entries||0}</p><p><b>Nmap:</b> ${l.nmap_available?'AVAILABLE':'NOT INSTALLED'}</p></div></div><div class="card"><div class="card-head"><h3>IPv6 NETWORK</h3><span>VISIBLE ADDRESSES</span></div><div class="card-body"><p><b>Local IPv6:</b></p><div class="code-list">${ipv6}</div><p class="muted small">A normal IPv6 /64 is not brute-force scanned. SentinelX uses visible neighbor state; explicit small prefixes can be assessed separately.</p></div></div></div>
    <div class="grid two"><div class="card"><div class="card-head"><h3>VISIBLE IPv4 DEVICES</h3><span>${peers4.length}</span></div><div class="table-wrap"><table class="table network-table"><thead><tr><th>IP</th><th>MAC</th><th>State</th><th>Interface</th></tr></thead><tbody>${peers4.map(n=>`<tr><td><b>${esc(n.ip)}</b></td><td>${esc(n.mac||'—')}</td><td>${status(n.state||'unknown')}</td><td>${esc(n.interface||'—')}</td></tr>`).join('')||'<tr><td colspan="4"><div class="empty">No IPv4 peers are currently visible to Windows.</div></td></tr>'}</tbody></table></div></div><div class="card"><div class="card-head"><h3>VISIBLE IPv6 DEVICES</h3><span>${peers6.length}</span></div><div class="table-wrap"><table class="table network-table"><thead><tr><th>IPv6</th><th>MAC</th><th>State</th><th>Interface</th></tr></thead><tbody>${peers6.map(n=>`<tr><td><b>${esc(n.ip)}</b></td><td>${esc(n.mac||'—')}</td><td>${status(n.state||'unknown')}</td><td>${esc(n.interface||'—')}</td></tr>`).join('')||'<tr><td colspan="4"><div class="empty">No IPv6 peers are currently visible to Windows.</div></td></tr>'}</tbody></table></div></div></div>
    <div class="card"><div class="card-head"><h3>OBSERVED NETWORK DEVICES</h3><span>${observed.length}</span></div><div class="card-body"><div class="device-grid">${observed.map(d=>`<div class="card device" onclick="showDevice(${d.id})"><div class="device-top"><div class="device-icon">${iconFor(d.platform)}</div>${status(d.status)}</div><h4>${esc(d.name)}</h4><p>${esc(d.ip_address||'—')} • ${esc(d.device_type||'Network Device')}</p><div class="risk"><div class="risk-row"><span>Last observed</span><b>${esc(ago(d.last_seen))}</b></div><div class="bar"><i style="width:${Math.min(100,d.risk_score||0)}%;background:${(d.risk_score||0)>70?'var(--red)':(d.risk_score||0)>40?'var(--amber)':'var(--green)'}"></i></div></div></div>`).join('')||'<div class="empty card">No network devices have been observed yet. Click <b>Scan Connected Network</b>.</div>'}</div></div></div>`,
    '');
}

function mitre(){const m={};(state.data.alerts||[]).forEach(a=>{const k=a.mitre_technique||'Unmapped';m[k]=(m[k]||0)+1});return shell('ATT&CK Coverage','Observed techniques from current deterministic detections and the enabled rule catalog.',`<div class="grid two"><div class="card"><div class="card-head"><h3>OBSERVED TECHNIQUES</h3><span>${Object.keys(m).length}</span></div><div class="card-body">${Object.entries(m).sort((a,b)=>b[1]-a[1]).map(([k,n])=>`<div class="coverage-row"><div class="split"><b>${esc(k)}</b><span class="pill">${n} alerts</span></div><div class="bar"><i style="width:${Math.min(100,n*18)}%;background:var(--purple)"></i></div></div>`).join('')||'<div class="empty">No mapped activity.</div>'}</div></div><div class="card"><div class="card-head"><h3>TACTIC / TECHNIQUE MAP</h3><span>${(state.data.rules||[]).filter(r=>r.enabled).length} enabled</span></div><div class="card-body">${(state.data.rules||[]).filter(r=>r.enabled).slice(0,120).map(r=>`<div class="list-row split"><span>${esc(r.id)}</span><span>${esc(r.mitre||'—')} · ${esc(r.tactic)}</span></div>`).join('')}</div></div></div>`);}

function rules(){const rows=state.data.rules||[];return shell('Detection Engineering','Deterministic detection catalog with enable/disable controls, MITRE mapping and a built-in test bench.',controlBar('rules')+`<div class="card"><div class="card-head"><h3>RULE CATALOG</h3><span>${rows.length} loaded</span></div><div class="table-wrap"><table class="table"><thead><tr><th>Rule</th><th>Category</th><th>Tactic</th><th>Severity</th><th>Risk</th><th>MITRE</th><th>Description</th><th>State</th><th>Action</th></tr></thead><tbody id="dataRows">${rows.map(r=>`<tr data-search="${esc(`${r.id} ${r.category} ${r.tactic} ${r.description} ${r.mitre||''}`)}" data-severity="${r.severity}" data-category="${esc(r.category)}" data-tactic="${esc(r.tactic)}" data-enabled="${r.enabled}" data-sort-risk="${r.risk}" data-sort-id="${esc(r.id)}" data-sort-severity="${r.severity}"><td><b>${esc(r.id)}</b><br><small>${esc(r.event_type)}</small></td><td>${esc(r.category)}</td><td>${esc(r.tactic)}</td><td>${sev(r.severity)}</td><td>${r.risk}</td><td>${esc(r.mitre||'—')}</td><td>${esc(r.description)}</td><td>${r.enabled?'<span class="pill status-online">Enabled</span>':'<span class="pill sev-medium">Disabled</span>'}</td><td>${can('rules.manage')?`<button class="btn" onclick="toggleRule('${encodeURIComponent(r.id)}')">${r.enabled?'Disable':'Enable'}</button>`:'—'}</td></tr>`).join('')}</tbody></table></div></div><div class="card tester"><div class="card-head"><h3>RULE TESTER</h3><span>evaluate telemetry before deployment</span></div><div class="card-body"><div class="toolbar"><input id="ruleTestType" class="search" placeholder="Event type e.g. powershell_execution"><input id="ruleTestMessage" class="search" placeholder="Message / command line / telemetry"><button id="ruleTestBtn" class="btn primary">Test detection</button></div><pre id="ruleTestOut" class="test-output">Run a test to see matched rules, severity, risk and MITRE mapping.</pre></div></div>`);}

function ai(){const st=state.data.aiStatus||{}; const models=st.models||[]; return shell('AI Analyst','Investigation assistance with deterministic fallbacks. Local model output is advisory and never the primary detection authority.',`<div class="grid three"><div class="card"><div class="card-head"><h3>AI PROVIDER</h3><span>${st.reachable?'Online':'Fallback'}</span></div><div class="card-body"><p><b>Provider:</b> ${esc(st.provider||'SentinelX')}</p><p><b>Endpoint:</b> ${esc(st.base_url||'Local deterministic')}</p><p><b>Models:</b> ${models.length||0}</p><div class="integration-badge ${st.reachable?'online':'offline'}">${st.reachable?'● MODEL SERVICE AVAILABLE':'○ DETERMINISTIC FALLBACK ACTIVE'}</div></div></div><div class="card"><div class="card-head"><h3>LOCAL MODEL OPTIONS</h3><span>configured / installed</span></div><div class="card-body">${models.map(x=>`<div class="list-row"><span>${esc(x)}</span><span class="pill">Local</span></div>`).join('')||'<div class="empty">No model names configured.</div>'}</div></div><div class="card"><div class="card-head"><h3>AI SAFETY</h3><span>analyst assistance</span></div><div class="card-body"><div class="list-row">Deterministic detections remain authoritative.</div><div class="list-row">AI cannot close or contain incidents automatically.</div><div class="list-row">Prompts are built from SentinelX telemetry only.</div></div></div></div><div class="grid two"><div class="card"><div class="card-head"><h3>ALERT INVESTIGATION</h3><span>${(state.data.alerts||[]).length} alerts</span></div><div class="card-body">${(state.data.alerts||[]).slice(0,25).map(a=>`<div class="split list-row"><div><b>${esc(a.rule)}</b><div class="muted">${esc(a.description)}</div></div><button class="btn" onclick="investigate(${a.id})">Investigate</button></div>`).join('')||'<div class="empty">No alerts.</div>'}</div></div><div class="card"><div class="card-head"><h3>ANALYST WORKSPACE</h3><span>live evidence only</span></div><div class="card-body"><p class="muted">Investigations are grounded in telemetry received from SentinelX collectors, network discovery, IDS/IPS sensors and approved connectors. No synthetic telemetry is generated from the analyst console.</p><div class="toolbar"><button class="btn" onclick="setView('network')">Open Network Discovery</button><button class="btn" onclick="setView('idsips')">Open IDS / IPS</button></div></div></div></div>`);}

function iam(){return shell('Identity & Access Management','Role-based access, user lifecycle, password security, active sessions and audit evidence.',`<div class="grid two"><div class="card"><div class="card-head"><h3>USERS</h3><span>admin / employee / user</span></div><div class="card-body">${can('iam.manage')?`<div class="toolbar"><input id="newU" class="search" placeholder="username"><input id="newP" class="search" placeholder="temporary password"><select id="newR" class="select"><option>user</option><option>employee</option><option>admin</option></select><button class="btn primary" id="createUser">Create user</button></div>`:''}<div id="iamUsers"></div></div></div><div class="card"><div class="card-head"><h3>MY SESSION</h3><span>server-enforced expiry</span></div><div class="card-body"><div class="statline"><div class="mini-stat"><b id="iamRemaining">—</b><span>REMAINING</span></div><div class="mini-stat"><b id="iamSessions">—</b><span>ACTIVE SESSIONS</span></div></div><div class="toolbar"><button class="btn" id="changePasswordBtn">Change password</button><button class="btn" id="diagnosticsBtn">Run diagnostics</button><button class="btn danger" id="logoutAllBtn">Sign out all sessions</button></div></div><div class="card-head"><h3>ROLE PERMISSIONS</h3><span>least privilege</span></div><div class="card-body"><div class="permission-grid"><div><b>ADMIN</b>${['iam.manage','rules.manage','network.discover','alerts.manage','incidents.manage','system.read'].map(x=>`<span>✓ ${x}</span>`).join('')}</div><div><b>EMPLOYEE</b>${['dashboard.read','alerts.manage','incidents.manage','devices.manage','network.discover'].map(x=>`<span>✓ ${x}</span>`).join('')}</div><div><b>USER</b>${['dashboard.read','events.read','alerts.read','devices.read','ai.investigate'].map(x=>`<span>✓ ${x}</span>`).join('')}</div></div></div></div></div>${can('audit.read')?`<div class="card"><div class="card-head"><h3>AUDIT TRAIL</h3><span>authentication + administrative actions</span></div><div class="table-wrap"><table class="table"><thead><tr><th>Time</th><th>User</th><th>Action</th><th>Result</th><th>IP</th><th>Details</th></tr></thead><tbody id="auditRows"></tbody></table></div></div>`:''}`);}

async function loadIAM(){
  try{
    if(can('iam.manage')){const users=await api('/auth/users');const el=document.getElementById('iamUsers');if(el)el.innerHTML=`<table class="table"><thead><tr><th>User</th><th>Role</th><th>Status</th><th>Last login</th><th>Action</th></tr></thead><tbody>${users.map(u=>`<tr><td><b>${esc(u.display_name)}</b><br><small>${esc(u.username)}</small></td><td>${esc(u.role)}</td><td>${u.is_active?status('online'):status('offline')}</td><td>${fmt(u.last_login)}</td><td><button class="btn" onclick="toggleUser(${u.id},${u.is_active})">${u.is_active?'Disable':'Enable'}</button></td></tr>`).join('')}</tbody></table>`;}
    else {const el=document.getElementById('iamUsers');if(el)el.innerHTML='<div class="empty">IAM user administration is restricted to administrators.</div>';}
    if(can('audit.read')){const rows=await api('/auth/audit?limit=200');const el=document.getElementById('auditRows');if(el)el.innerHTML=rows.map(x=>`<tr><td>${fmt(x.timestamp)}</td><td>${esc(x.username||'anonymous')}</td><td>${esc(x.action)}</td><td>${status(x.result==='success'?'online':'offline')}</td><td>${esc(x.ip_address||'—')}</td><td>${esc(x.details||'')}</td></tr>`).join('');}
    const info=state.session||await safe('session',()=>api('/auth/session'),null);if(info){document.getElementById('iamRemaining').textContent=formatRemaining(info.remaining_seconds);document.getElementById('iamSessions').textContent=info.active_sessions;}
  }catch(e){toast(e.message,'bad');}
}

function formatRemaining(sec){if(sec==null)return'—';const h=Math.floor(sec/3600),m=Math.floor((sec%3600)/60);return `${h?`${h}h `:''}${m}m`;}
async function toggleUser(id,active){try{await api(`/auth/users/${id}`,{method:'PATCH',body:JSON.stringify({is_active:!active})});toast('User status updated','good');await loadIAM();}catch(e){toast(e.message,'bad');}}
async function createUser(){try{await api('/auth/users',{method:'POST',body:JSON.stringify({username:document.getElementById('newU').value,password:document.getElementById('newP').value,display_name:document.getElementById('newU').value,role:document.getElementById('newR').value})});toast('User created','good');await loadIAM();}catch(e){toast(e.message,'bad');}}

function reports(){
  const c=state.data.overview?.counts||{};
  return shell('Reports & Export','Operational and executive views of the current SentinelX data set.',`<div class="grid three"><div class="card"><div class="card-head"><h3>EXECUTIVE SNAPSHOT</h3><span>current state</span></div><div class="card-body"><div class="statline"><div class="mini-stat"><b>${c.events||0}</b><span>EVENTS</span></div><div class="mini-stat"><b>${c.open_alerts||0}</b><span>OPEN ALERTS</span></div><div class="mini-stat"><b>${c.open_incidents||0}</b><span>OPEN INCIDENTS</span></div><div class="mini-stat"><b>${c.devices||0}</b><span>DEVICES</span></div></div><button class="btn primary" id="printReport">Print executive report</button></div></div><div class="card"><div class="card-head"><h3>DATA EXPORTS</h3><span>client-side CSV</span></div><div class="card-body"><div class="toolbar"><button class="btn" data-export="alerts">Export alerts</button><button class="btn" data-export="events">Export events</button><button class="btn" data-export="devices">Export devices</button><button class="btn" data-export="incidents">Export incidents</button><button class="btn" data-export="rules">Export rules</button></div></div></div><div class="card"><div class="card-head"><h3>READINESS</h3><span>baseline</span></div><div class="card-body">${(state.data.system?.security_controls||[]).map(x=>`<div class="list-row">✓ ${esc(x)}</div>`).join('')||'<div class="empty">No readiness data.</div>'}</div></div></div><div class="card"><div class="card-head"><h3>TOP RISK ASSETS</h3><span>from device fleet</span></div><div class="card-body">${(state.data.devices||[]).slice().sort((a,b)=>(b.risk_score||0)-(a.risk_score||0)).slice(0,10).map(d=>`<div class="split list-row"><span>${iconFor(d.platform)} ${esc(d.name)}</span><b>${d.risk_score}/100</b></div>`).join('')||'<div class="empty">No devices.</div>'}</div></div>`);
}

function security(){const s=state.data.system||{};return shell('Security Center','Runtime posture, control status, session state and deployment checks.',`<div class="grid three"><div class="card"><div class="card-head"><h3>RUNTIME</h3><span>v${esc(s.version||VERSION)}</span></div><div class="card-body"><div class="statline"><div class="mini-stat"><b>${esc(s.database||'—')}</b><span>DATABASE</span></div><div class="mini-stat"><b>${s.rules?.enabled||0}</b><span>RULES ENABLED</span></div><div class="mini-stat"><b>${s.sessions||0}</b><span>ACTIVE SESSIONS</span></div></div><p class="muted">DB: ${esc(s.database_file||'—')}</p></div></div><div class="card"><div class="card-head"><h3>HOST NETWORK</h3><span>local visibility</span></div><div class="card-body"><p><b>IP:</b> ${esc(s.network?.local_ip||'—')}</p><p><b>Subnet:</b> ${esc(s.network?.subnet||'—')}</p><p><b>Gateway:</b> ${esc(s.network?.gateway||'—')}</p><p><b>Wi-Fi:</b> ${s.network?.wifi?.connected?esc(s.network?.wifi?.ssid||'connected'):'not detected'}</p></div></div><div class="card"><div class="card-head"><h3>SECURITY CONTROLS</h3><span>${(s.security_controls||[]).length}</span></div><div class="card-body">${(s.security_controls||[]).map(x=>`<div class="list-row">✓ ${esc(x)}</div>`).join('')}</div></div></div><div class="card"><div class="card-head"><h3>SESSION</h3><span>server controlled</span></div><div class="card-body"><div class="statline"><div class="mini-stat"><b>${formatRemaining(state.session?.remaining_seconds)}</b><span>REMAINING</span></div><div class="mini-stat"><b>${state.session?.active_sessions??'—'}</b><span>ACTIVE</span></div><div class="mini-stat"><b>${esc(state.user?.role||'—')}</b><span>ROLE</span></div></div><div class="toolbar"><button class="btn" id="changePasswordBtn">Change password</button><button class="btn" id="diagnosticsBtn">Run diagnostics</button><button class="btn danger" id="logoutAllBtn">Sign out all sessions</button></div></div></div>`);}


function vulnerabilities(){
  const rows=state.data.vulnerabilities||[], sum=state.data.vulnSummary||{};
  return shell('Vulnerability Scanner','Authorized internal asset assessment using service discovery, safe exposure analysis and optional Nmap vulnerability checks.',
    `<div class="grid metrics">${metric('OPEN FINDINGS',sum.open||0,'current assessment')}${metric('CRITICAL',sum.critical||0,'priority remediation')}${metric('HIGH',sum.high||0,'high-risk exposure')}${metric('MEDIUM',sum.medium||0,'review queue')}${metric('LOW',sum.low||0,'informational risk')}${metric('NMAP',state.data.vulnStatus?.status?.installed?'READY':'NOT INSTALLED','optional assessment engine')}</div>
    <div class="card"><div class="card-head"><h3>AUTHORIZED TARGET ASSESSMENT</h3><span>private/local IPv4 only</span></div><div class="card-body"><div class="toolbar"><input id="vulnTarget" class="search" placeholder="192.168.1.25"><label class="toggle"><input id="deepVuln" type="checkbox"> <span>Deep vulnerability scripts</span></label><button class="btn primary" id="scanVulnTarget">Assess target</button></div><p class="muted small">Deep checks are limited to private/local addresses and require explicit authorization confirmation. SentinelX records evidence; it does not exploit targets.</p><pre id="vulnScanOut" class="test-output">Assessment output will appear here.</pre></div></div>
    <div class="card"><div class="card-head"><h3>FINDINGS</h3><span>${rows.length}</span></div><div class="toolbar"><input id="vulnSearch" class="search" placeholder="Search finding, IP, service, CVE…"><select id="vulnSeverity" class="select"><option value="">Severity: All</option><option>critical</option><option>high</option><option>medium</option><option>low</option></select><select id="vulnStatus" class="select"><option value="">Status: All</option><option>open</option><option>accepted</option><option>resolved</option></select></div><div class="table-wrap"><table class="table"><thead><tr><th>Asset</th><th>Finding</th><th>Service</th><th>Severity</th><th>Risk</th><th>Evidence</th><th>Status</th></tr></thead><tbody id="vulnRows">${rows.map(v=>`<tr data-vsearch="${esc(`${v.ip_address} ${v.title} ${v.service||''} ${v.product||''} ${v.version||''} ${v.cve||''}`)}" data-vseverity="${esc(v.severity)}" data-vstatus="${esc(v.status)}"><td>${esc(v.ip_address)}${v.port?`<br><small>${v.port}/${esc(v.protocol||'tcp')}</small>`:''}</td><td><b>${esc(v.title)}</b>${v.cve?`<br><small>${esc(v.cve)}</small>`:''}</td><td>${esc(v.service||v.product||'—')} ${esc(v.version||'')}</td><td>${sev(v.severity)}</td><td><b>${v.risk_score}</b></td><td><small>${esc((v.evidence||'').slice(0,220))}</small></td><td>${status(v.status)}</td></tr>`).join('')||'<tr><td colspan="7"><div class="empty">No vulnerability findings yet. Run an authorized assessment.</div></td></tr>'}</tbody></table></div></div>`);
}

function idsips(){
  const s=state.data.idsips||{}, a=state.data.idsAlerts||[];
  return shell('IDS / IPS','Defensive integration for Suricata and Snort 3. Monitor sensor health, ingest alerts and map network detections into SentinelX.',
    `<div class="grid two"><div class="card"><div class="card-head"><h3>SURICATA</h3><span>${s.suricata?.installed?'Detected':'Not detected'}</span></div><div class="card-body"><p><b>Binary:</b> ${esc(s.suricata?.path||'—')}</p><p><b>Version:</b> ${esc(s.suricata?.version||'—')}</p><p><b>EVE JSON:</b> ${esc(s.suricata?.eve_log||'Not configured')}</p><div class="integration-badge ${s.suricata?.installed?'online':'offline'}">${s.suricata?.installed?'● SENSOR AVAILABLE':'○ CONNECT SENSOR'}</div></div></div><div class="card"><div class="card-head"><h3>SNORT 3</h3><span>${s.snort?.installed?'Detected':'Not detected'}</span></div><div class="card-body"><p><b>Binary:</b> ${esc(s.snort?.path||'—')}</p><p><b>Version:</b> ${esc(s.snort?.version||'—')}</p><p><b>Alert feed:</b> ${esc(s.snort?.alert_log||'Not configured')}</p><div class="integration-badge ${s.snort?.installed?'online':'offline'}">${s.snort?.installed?'● SENSOR AVAILABLE':'○ CONNECT SENSOR'}</div></div></div></div>
    <div class="card"><div class="card-head"><h3>RECENT SENSOR ALERTS</h3><span>${a.length}</span></div><div class="table-wrap"><table class="table"><thead><tr><th>Sensor</th><th>Time</th><th>Signature</th><th>Severity</th><th>Source</th><th>Destination</th></tr></thead><tbody>${a.map(x=>`<tr><td>${esc(x.sensor)}</td><td>${fmt(x.timestamp)}</td><td><b>${esc(x.signature)}</b></td><td>${sev(String(x.severity).toLowerCase())}</td><td>${esc(x.src_ip||'—')}${x.src_port?':'+x.src_port:''}</td><td>${esc(x.dest_ip||'—')}${x.dest_port?':'+x.dest_port:''}</td></tr>`).join('')||'<tr><td colspan="6"><div class="empty">No configured sensor alerts. Configure EVE JSON / Snort alert ingestion in .env.</div></td></tr>'}</tbody></table></div></div>
    <div class="card"><div class="card-head"><h3>SENTINELX DEFENSIVE RULE PACK</h3><span>local rules</span></div><div class="card-body"><p class="muted">Example defensive signatures are available in <code>rules/suricata/local.rules</code> and <code>rules/snort/local.rules</code>. Third-party feeds remain separate and are not redistributed by SentinelX.</p><pre class="test-output">Suricata: include rules/suricata/local.rules\nSnort 3: include rules/snort/local.rules</pre></div></div>`);
}

function metasploit(){
  const m=state.data.metasploit||{}, rows=state.data.msfCatalog||[];
  return shell('Exploit Intelligence','Metasploit-aware module intelligence for authorized assessment planning. SentinelX does not expose exploit execution, payload delivery or destructive actions.',
    `<div class="grid three">${metric('FRAMEWORK',m.installed?'CONNECTED':'NOT DETECTED',m.version?'local msfconsole':'install separately')}${metric('MODULE CATALOG',m.catalog_size||rows.length,'defensive references')}${metric('EXECUTION','DISABLED','UI safety control')}</div>
    <div class="card"><div class="card-head"><h3>MODULE INTELLIGENCE</h3><span>${rows.length} references</span></div><div class="toolbar"><input id="msfSearch" class="search" placeholder="Search module, family, CVE…"><select id="msfKind" class="select"><option value="">Type: All</option><option>exploit</option><option>auxiliary</option><option>post</option><option>payload</option></select><button class="btn primary" id="msfSearchBtn">Search</button></div><div class="table-wrap"><table class="table"><thead><tr><th>Type</th><th>Module</th><th>Family</th><th>Reference</th><th>Safety</th></tr></thead><tbody id="msfRows">${rows.map(x=>`<tr><td>${esc(x.type)}</td><td><b>${esc(x.module)}</b></td><td>${esc(x.family)}</td><td>${esc(x.cve||x.purpose)}</td><td>${esc(x.safe_mode)}</td></tr>`).join('')||'<tr><td colspan="5"><div class="empty">No module references.</div></td></tr>'}</tbody></table></div></div>
    <div class="card"><div class="card-head"><h3>AUTHORIZED WORKFLOW</h3></div><div class="card-body"><div class="workflow"><span>Asset discovery</span><b>→</b><span>Service/version detection</span><b>→</b><span>CVE / exposure correlation</span><b>→</b><span>Human approval</span><b>→</b><span>Remediation</span></div><p class="muted small">Use Metasploit separately in a controlled lab or explicitly authorized assessment. SentinelX consumes results and module intelligence; it is not an exploitation console.</p></div></div>`);
}

function filterElements(){return document.querySelectorAll('#dataRows tr,.device-grid .device');}
function rowSearchText(el){return (el.dataset.search||el.textContent||'').toLowerCase();}
function applyFilters(){
  const get=id=>document.getElementById(id)?.value||''; const term=get('tableSearch').toLowerCase(); const sf=get('severityFilter'); const st=get('statusFilter'); const pf=get('platformFilter'); const dt=get('deviceType'); const src=get('eventSource')||get('deviceSource'); const et=get('eventType'); const mt=get('mitreFilter'); const rf=Number(get('riskFilter')||0); const dr=Number(get('deviceRisk')||0); const rc=get('ruleCategory'); const rt=get('ruleTactic'); const re=get('ruleEnabled'); const rs=get('ruleSeverity');
  let total=0,shown=0;
  filterElements().forEach(el=>{
    if(el.querySelector && el.querySelector('td')?.textContent.includes('No alerts')) return;
    total++;
    const ok=!term||rowSearchText(el).includes(term);
    const ok2=!sf||el.dataset.severity===sf;
    const ok3=!st||el.dataset.status===st;
    const ok4=!pf||el.dataset.platform===pf;
    const ok5=!dt||el.dataset.type===dt;
    const ok6=!src||el.dataset.source===src;
    const ok7=!et||el.dataset.eventType===et;
    const ok8=!mt||el.dataset.mitre===mt;
    const ok9=!rf||Number(el.dataset.risk||0)>=rf;
    const ok10=!dr||Number(el.dataset.risk||0)>=dr;
    const ok11=!rc||el.dataset.category===rc;
    const ok12=!rt||el.dataset.tactic===rt;
    const ok13=!re||el.dataset.enabled===re;
    const ok14=!rs||el.dataset.severity===rs;
    const visible=ok&&ok2&&ok3&&ok4&&ok5&&ok6&&ok7&&ok8&&ok9&&ok10&&ok11&&ok12&&ok13&&ok14;
    el.style.display=visible?'':'none'; if(visible)shown++;
  });
  const fc=document.getElementById('filterCount'); if(fc)fc.textContent=`Showing ${shown} of ${total}`;
}
function clearFilters(){['tableSearch','severityFilter','statusFilter','platformFilter','deviceType','deviceSource','eventSource','eventType','mitreFilter','riskFilter','deviceRisk','ruleCategory','ruleTactic','ruleEnabled','ruleSeverity'].forEach(id=>{const e=document.getElementById(id);if(e)e.value=''});applyFilters();}
const SEV_ORDER={critical:4,high:3,medium:2,low:1,info:0};
function compare(a,b,field,asc){let A=a??'',B=b??''; if(field==='severity'){A=SEV_ORDER[String(A).toLowerCase()]??0;B=SEV_ORDER[String(B).toLowerCase()]??0;}else if(field.includes('time')||field.includes('created')||field.includes('updated')||field.includes('seen')){A=Date.parse(A)||0;B=Date.parse(B)||0;}else if(field.includes('risk')){A=Number(A)||0;B=Number(B)||0;}else{A=String(A).toLowerCase();B=String(B).toLowerCase();} if(A<B)return asc?-1:1;if(A>B)return asc?1:-1;return 0;}
function sortDom(kind,field){const key=kind==='alerts'?`data-sort-${field}`:kind==='events'?`data-sort-${field}`:kind==='devices'?`data-sort-${field}`:kind==='incidents'?`data-sort-${field}`:kind==='rules'?`data-sort-${field}`:null;if(!key)return;const asc=state.sort.field===field&&state.sort.dir==='asc';state.sort={field,dir:asc?'desc':'asc'};const parent=kind==='devices'?document.getElementById('deviceRows'):document.getElementById('dataRows');if(!parent)return;[...parent.children].sort((a,b)=>compare(a.getAttribute(key)||'',b.getAttribute(key)||'',field,asc)).forEach(x=>parent.appendChild(x));applyFilters();}

function bindSort(){
  const map=[['alertSort','alerts'],['eventSort','events'],['deviceSort','devices'],['incidentSort','incidents'],['ruleSort','rules']];
  map.forEach(([id,kind])=>document.getElementById(id)?.addEventListener('change',e=>sortDom(kind,e.target.value)));
  document.getElementById('ruleTestBtn')?.addEventListener('click',testRule);
}

function bindView(){
  ['tableSearch','severityFilter','statusFilter','platformFilter','deviceType','deviceSource','eventSource','eventType','mitreFilter','riskFilter','deviceRisk','ruleCategory','ruleTactic','ruleEnabled','ruleSeverity'].forEach(id=>{const e=document.getElementById(id);if(e)e.addEventListener(e.tagName==='SELECT'?'change':'input',applyFilters);});
  document.getElementById('clearFilters')?.addEventListener('click',clearFilters);
  document.getElementById('discoverBtn')?.addEventListener('click',()=>discover(true));
document.getElementById('refreshNetworkBtn')?.addEventListener('click',async()=>{await load(false);setView('network');toast('Network visibility refreshed.','good');});
document.getElementById('scanIpv6Btn')?.addEventListener('click',discoverIpv6);
  document.getElementById('openNetwork')?.addEventListener('click',()=>setView('network'));
  document.getElementById('autoDiscover')?.addEventListener('change',e=>{state.autoDiscovery=e.target.checked;localStorage.setItem('sentinelx_auto_discovery',String(state.autoDiscovery));toast(state.autoDiscovery?'Automatic discovery enabled':'Automatic discovery disabled',state.autoDiscovery?'good':'');});
  document.getElementById('createUser')?.addEventListener('click',createUser);
  document.getElementById('changePasswordBtn')?.addEventListener('click',openChangePassword);
  document.getElementById('logoutAllBtn')?.addEventListener('click',logoutAll);
  document.getElementById('diagnosticsBtn')?.addEventListener('click',runDiagnostics);
  document.getElementById('scanVulnTarget')?.addEventListener('click',assessVulnTarget);
  document.getElementById('msfSearchBtn')?.addEventListener('click',searchMetasploit);
  ['vulnSearch','vulnSeverity','vulnStatus'].forEach(id=>document.getElementById(id)?.addEventListener(document.getElementById(id)?.tagName==='SELECT'?'change':'input',filterVulnerabilities));
  document.querySelectorAll('[data-export]').forEach(b=>b.addEventListener('click',()=>exportData(b.dataset.export)));
  document.getElementById('printReport')?.addEventListener('click',()=>window.print());
  if(state.view==='iam')loadIAM();
  applyFilters(); bindSort();
}


function filterVulnerabilities(){
  const q=(document.getElementById('vulnSearch')?.value||'').toLowerCase(); const sevv=document.getElementById('vulnSeverity')?.value||''; const st=document.getElementById('vulnStatus')?.value||''; let shown=0,total=0;
  document.querySelectorAll('#vulnRows tr').forEach(r=>{if(!r.dataset.vsearch)return;total++;const ok=(!q||r.dataset.vsearch.toLowerCase().includes(q))&&(!sevv||r.dataset.vseverity===sevv)&&(!st||r.dataset.vstatus===st);r.style.display=ok?'':'none';if(ok)shown++;});
  const f=document.getElementById('filterCount'); if(f)f.textContent=`Showing ${shown} of ${total}`;
}

async function testRule(){const type=document.getElementById('ruleTestType')?.value||'';const message=document.getElementById('ruleTestMessage')?.value||'';if(!type){toast('Enter an event type before testing.','bad');return;}try{const r=await api(`/rules/test?event_type=${encodeURIComponent(type)}&message=${encodeURIComponent(message)}`,{method:'POST'});document.getElementById('ruleTestOut').textContent=JSON.stringify(r,null,2);}catch(e){toast(e.message,'bad');}}
async function discover(manual=true){
  const b=document.getElementById('discoverBtn');
  if(b){b.disabled=true;b.textContent='Scanning connected network…';}
  try{
    const sub=document.getElementById('discoverSubnet')?.value?.trim()||null;
    const family=sub?.includes(':')?'ipv6':'auto';
    const r=await api('/network/discover',{method:'POST',timeout:180000,body:JSON.stringify({subnet:sub,deep:true,max_hosts:254,family})});
    if(manual)toast(`Network scan complete • ${r.found} visible devices • ${r.methods.join(', ')}`,'good');
    await load(false);
    if(manual)setView('network');
  }catch(e){if(manual)toast(e.message,'bad');}
  finally{if(b){b.disabled=false;b.textContent='⌁ Scan Connected Network';}}
}

async function discoverIpv6(){
  const b=document.getElementById('scanIpv6Btn');
  if(b){b.disabled=true;b.textContent='Reading IPv6 neighbors…';}
  try{
    const r=await api('/network/discover',{method:'POST',timeout:30000,body:JSON.stringify({subnet:null,deep:false,max_hosts:254,family:'ipv6'})});
    toast(`IPv6 neighbor discovery complete • ${r.found} visible peers`,'good');
    await load(false);setView('network');
  }catch(e){toast(e.message,'bad');}
  finally{if(b){b.disabled=false;b.textContent='◇ Scan IPv6 Neighbors';}}
}

async function toggleRule(id){try{await api(`/rules/${id}/toggle`,{method:'POST'});toast('Detection rule state changed','good');await load();setView('rules');}catch(e){toast(e.message,'bad');}}


async function scanDeviceVulnerability(id){
  openModal('<div class="eyebrow">VULNERABILITY ASSESSMENT</div><h2>Assessing asset…</h2><p class="muted">SentinelX is collecting service/version evidence. This is a defensive assessment only.</p><div class="loading-ring"></div>');
  try{const r=await api(`/vulnerabilities/scan/device/${id}`,{method:'POST',timeout:180000,body:JSON.stringify({deep:false,confirm_authorized:false})});openModal(`<button class="close" onclick="closeModal()">×</button><div class="eyebrow">VULNERABILITY ASSESSMENT</div><h2>${esc(r.device.name)} — Assessment Complete</h2><p class="muted">${esc(r.device.ip_address)} • ${esc(r.scan.scanner)} • ${r.findings.length} current findings</p><div class="statline"><div class="mini-stat"><b>${r.scan.ports.length}</b><span>OPEN PORTS</span></div><div class="mini-stat"><b>${r.findings.filter(x=>x.severity==='critical').length}</b><span>CRITICAL</span></div><div class="mini-stat"><b>${r.findings.filter(x=>x.severity==='high').length}</b><span>HIGH</span></div></div><div class="card-body">${r.findings.map(x=>`<div class="list-row"><b>${esc(x.title)}</b><span>${sev(x.severity)} ${x.port?`port ${x.port}`:''}</span><small class="muted">${esc(x.remediation||'Review finding and remediate.')}</small></div>`).join('')||'<div class="empty">No findings were observed by the selected assessment mode.</div>'}</div>`);await load(false);}catch(e){openModal(`<button class="close" onclick="closeModal()">×</button><div class="eyebrow">ASSESSMENT ERROR</div><h2>Assessment could not complete</h2><p class="muted">${esc(e.message)}</p>`);}
}

async function assessVulnTarget(){
  const ip=document.getElementById('vulnTarget')?.value.trim(); const deep=document.getElementById('deepVuln')?.checked; if(!ip){toast('Enter a private IPv4 address.','bad');return;}
  try{const r=await api('/vulnerabilities/scan/target',{method:'POST',timeout:180000,body:JSON.stringify({ip_address:ip,deep,confirm_authorized:deep})});document.getElementById('vulnScanOut').textContent=JSON.stringify(r,null,2);toast(`Assessment completed • ${r.findings.length} findings`,'good');await load(false);}catch(e){document.getElementById('vulnScanOut').textContent=e.message;toast(e.message,'bad');}
}

async function searchMetasploit(){const q=document.getElementById('msfSearch')?.value||'',kind=document.getElementById('msfKind')?.value||'';try{const r=await api(`/integrations/metasploit/search?q=${encodeURIComponent(q)}&kind=${encodeURIComponent(kind)}&limit=200`);state.data.msfCatalog=r;setView('metasploit');}catch(e){toast(e.message,'bad');}}

function openModal(html){document.getElementById('modalCard').innerHTML=html;document.getElementById('modal').classList.remove('hidden');}
function closeModal(){document.getElementById('modal').classList.add('hidden');}
function showAlert(id){const a=(state.data.alerts||[]).find(x=>x.id===id);if(!a)return;openModal(`<button class="close" onclick="closeModal()">×</button><div class="eyebrow">ALERT #${a.id}</div><h2>${esc(a.rule)}</h2><p class="muted">${esc(a.description)}</p><div class="statline"><div class="mini-stat"><b>${a.risk_score}</b><span>RISK</span></div><div class="mini-stat"><b>${esc(a.severity)}</b><span>SEVERITY</span></div><div class="mini-stat"><b>${esc(a.status)}</b><span>STATUS</span></div></div><p><b>MITRE:</b> ${esc(a.mitre_technique||'Unmapped')}</p><p><b>Created:</b> ${fmt(a.created_at)}</p><div class="hero-actions">${can('ai.investigate')?`<button class="btn primary" onclick="investigate(${a.id})">✦ AI Investigate</button>`:''}${can('alerts.manage')?`<button class="btn" onclick="changeAlert(${a.id},'acknowledged')">Acknowledge</button><button class="btn danger" onclick="changeAlert(${a.id},'closed')">Close</button>`:''}</div>`);}
async function changeAlert(id,s){try{await api(`/alerts/${id}/status?status=${s}`,{method:'PATCH'});toast(`Alert #${id} → ${s}`,'good');closeModal();await load();}catch(e){toast(e.message,'bad');}}
function showIncident(id){const i=(state.data.incidents||[]).find(x=>x.id===id);if(!i)return;openModal(`<button class="close" onclick="closeModal()">×</button><div class="eyebrow">INCIDENT #${i.id}</div><h2>${esc(i.title)}</h2><p>${esc(i.summary)}</p><div class="statline"><div class="mini-stat"><b>${i.risk_score}</b><span>RISK</span></div><div class="mini-stat"><b>${esc(i.severity)}</b><span>SEVERITY</span></div><div class="mini-stat"><b>${esc(i.status)}</b><span>STATUS</span></div></div><p class="muted">Asset: ${esc(i.hostname||'—')} • User: ${esc(i.username||'—')}</p><div class="hero-actions">${can('incidents.manage')?`<button class="btn" onclick="changeIncident(${i.id},'investigating')">Investigating</button><button class="btn danger" onclick="changeIncident(${i.id},'resolved')">Resolve</button>`:''}</div>`);}
async function changeIncident(id,s){try{await api(`/incidents/${id}/status?status=${s}`,{method:'PATCH'});toast(`Incident #${id} → ${s}`,'good');closeModal();await load();}catch(e){toast(e.message,'bad');}}
async function investigate(id){try{const r=await api(`/ai/investigate/${id}`,{method:'POST',timeout:30000});openModal(`<button class="close" onclick="closeModal()">×</button><div class="eyebrow">AI ANALYST / ALERT #${id}</div><h2>Investigation Brief</h2><pre style="white-space:pre-wrap;color:var(--text);line-height:1.65;background:#091019;border:1px solid var(--line);padding:15px;border-radius:10px">${esc(r.analysis||r.summary||JSON.stringify(r,null,2))}</pre><p class="muted">Analyst assistance only. Validate conclusions against telemetry and deterministic detections.</p>`);}catch(e){toast(e.message,'bad');}}
function showDevice(id){const d=(state.data.devices||[]).find(x=>x.id===id);if(!d)return;openModal(`<button class="close" onclick="closeModal()">×</button><div class="eyebrow">ASSET / ${esc(d.platform)}</div><h2>${iconFor(d.platform)} ${esc(d.name)}</h2><p class="muted">${esc(d.hostname||'')} • ${esc(d.ip_address||'no IP')}</p><div class="statline"><div class="mini-stat"><b>${d.risk_score}</b><span>RISK</span></div><div class="mini-stat"><b>${esc(d.status)}</b><span>HEALTH</span></div><div class="mini-stat"><b>${esc(d.source||'—')}</b><span>SOURCE</span></div></div><p><b>OS:</b> ${esc(d.os_version||'—')}</p><p><b>Type:</b> ${esc(d.device_type)}</p><p><b>Last seen:</b> ${fmt(d.last_seen)}</p><p><b>Tags:</b> ${esc(d.tags||'—')}</p><p><b>Open vulnerability findings:</b> ${d.open_vulnerabilities||0}</p><div class="hero-actions">${can('devices.manage')?`<button class="btn primary" onclick="scanDeviceVulnerability(${d.id})">Assess vulnerabilities</button><button class="btn" onclick="changeDevice(${d.id},'online')">Online</button><button class="btn" onclick="changeDevice(${d.id},'degraded')">Degraded</button><button class="btn danger" onclick="changeDevice(${d.id},'offline')">Offline</button>`:''}</div>`);}
async function changeDevice(id,s){try{await api(`/devices/${id}/status?status=${s}`,{method:'PATCH'});toast(`Device → ${s}`,'good');closeModal();await load();}catch(e){toast(e.message,'bad');}}

function openChangePassword(){openModal(`<button class="close" onclick="closeModal()">×</button><div class="eyebrow">ACCOUNT SECURITY</div><h2>Change Password</h2><p class="muted">Use at least 10 characters with upper/lowercase letters, a number and a special character.</p><label>Current password<input id="curPwd" type="password" autocomplete="current-password"></label><label>New password<input id="newPwd" type="password" autocomplete="new-password"></label><label>Confirm new password<input id="newPwd2" type="password" autocomplete="new-password"></label><div class="hero-actions"><button class="btn primary" id="savePwd">Update password</button></div><div id="pwdError" class="login-error"></div>`);document.getElementById('savePwd').onclick=async()=>{const cur=document.getElementById('curPwd').value,n1=document.getElementById('newPwd').value,n2=document.getElementById('newPwd2').value,err=document.getElementById('pwdError');if(n1!==n2){err.textContent='Passwords do not match.';return;}try{const r=await api('/auth/change-password',{method:'POST',body:JSON.stringify({current_password:cur,new_password:n1})});toast(r.message,'good');closeModal();}catch(e){err.textContent=e.message;}};}

function exportData(kind){
  const map={alerts:state.data.alerts,events:state.data.events,devices:state.data.devices,incidents:state.data.incidents,rules:state.data.rules};const rows=map[kind]||[];if(!rows.length){toast(`No ${kind} data to export.`,'bad');return;}
  const keys=[...new Set(rows.flatMap(x=>Object.keys(x)))];const csv=[keys.join(','),...rows.map(row=>keys.map(k=>`"${String(row[k]??'').replace(/"/g,'""')}"`).join(','))].join('\n');
  const blob=new Blob([csv],{type:'text/csv;charset=utf-8'});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=`sentinelx_${kind}_${new Date().toISOString().slice(0,10)}.csv`;a.click();URL.revokeObjectURL(a.href);toast(`${kind} export created.`,'good');
}

function openCommand(){document.getElementById('command').classList.remove('hidden');document.getElementById('commandInput').value='';document.getElementById('commandInput').focus();renderCommand('');}
function closeCommand(){document.getElementById('command').classList.add('hidden');}
function renderCommand(q){const opts=navItems.filter(x=>(x[2]+' '+x[0]).toLowerCase().includes(q.toLowerCase())&&(x[0]!=='iam'||can('iam.read')));document.getElementById('commandResults').innerHTML=opts.map(x=>`<div class="command-result" onclick="setView('${x[0]}');closeCommand()"><b>${x[2]}</b><div class="muted">Open workspace</div></div>`).join('')||'<div class="empty">No workspace found.</div>';}


async function runDiagnostics(){
  const checks=[
    ['API health','/health'],
    ['System status','/system/status'],
    ['Network visibility','/network/local'],
    ['Alert feed','/alerts/?limit=1'],
    ['Device inventory','/devices/?limit=1'],
  ];
  const out=[];
  for(const [name,path] of checks){
    const t=Date.now();
    try{ const r=await api(path,{timeout:path.includes('network')?15000:7000}); out.push({name,status:'PASS',ms:Date.now()-t,detail:r}); }
    catch(e){ out.push({name,status:'FAIL',ms:Date.now()-t,detail:e.message}); }
  }
  openModal(`<button class="close" onclick="closeModal()">×</button><div class="eyebrow">SYSTEM DIAGNOSTICS</div><h2>SentinelX Service Health</h2><div class="card-body">${out.map(x=>`<div class="split list-row"><span><b>${esc(x.name)}</b><small class="muted">${esc(String(x.detail?.status||x.detail||''))}</small></span><span>${x.status==='PASS'?'<span class="pill status-online">PASS</span>':'<span class="pill sev-critical">FAIL</span>'} <small>${x.ms} ms</small></span></div>`).join('')}</div>`);
}

function boot(){
  document.getElementById('loginForm').addEventListener('submit',async e=>{e.preventDefault();document.getElementById('loginError').textContent='';try{await login(document.getElementById('loginUser').value,document.getElementById('loginPass').value);showApp();await load(true);}catch(err){document.getElementById('loginError').textContent=err.message;publicHealth();}});
  document.getElementById('logoutBtn').onclick=()=>logout(false);document.getElementById('securityBtn').onclick=()=>setView('security');document.getElementById('refreshBtn').onclick=()=>load(true);document.getElementById('themeBtn').onclick=()=>document.body.classList.toggle('light');document.getElementById('mobileMenu').onclick=()=>document.querySelector('.sidebar').classList.toggle('open');document.getElementById('globalSearch').onclick=openCommand;document.getElementById('commandInput').oninput=e=>renderCommand(e.target.value);
  document.getElementById('modal').addEventListener('click',e=>{if(e.target.classList.contains('modal-backdrop'))closeModal();});
  document.addEventListener('keydown',e=>{if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='k'){e.preventDefault();openCommand();}if(e.key==='Escape'){closeModal();closeCommand();}const n=Number(e.key);const available=navItems.filter(x=>x[0]!=='iam'||can('iam.read'));if(n>=1&&n<=available.length&&!e.ctrlKey&&!e.metaKey&&!['INPUT','SELECT','TEXTAREA'].includes(document.activeElement.tagName))setView(available[n-1][0]);});
  setInterval(()=>document.getElementById('clock').textContent=new Date().toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'}),1000);
  setInterval(()=>updateSessionClock(),1000);
  setInterval(()=>{if(state.token&&state.connected)load(false);},15000);
  setInterval(()=>{if(state.token)refreshSessionInfo();},15000);
  setInterval(()=>{if(state.autoDiscovery&&state.token)discover(false);},60000);
  bootstrapAuth().then(async ok=>{if(ok){showApp();await load(true);}else showLogin();});
}

Object.assign(window,{showAlert,changeAlert,showIncident,changeIncident,investigate,showDevice,changeDevice,scanDeviceVulnerability,closeModal,setView,closeCommand,toggleRule,runDiagnostics});
boot();
