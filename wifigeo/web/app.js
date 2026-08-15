/* WGF operator interface.
   Vanilla JS, no framework, no map library. The slippy map at the bottom of
   this file is about 90 lines and does everything we need, which is cheaper
   than shipping Leaflet in a portable build. */

'use strict';

/* This page is served by WGF's own local server and talks to it over HTTP.
   Opening the HTML file directly from disk loads no styling and no API, which
   looks like the tool is broken when it simply has not been started. Say so
   plainly rather than presenting a dead page. */
if (location.protocol === 'file:') {
  document.documentElement.innerHTML = `
    <body style="font:15px/1.65 -apple-system,Segoe UI,Roboto,sans-serif;
                 background:#0a0e14;color:#e6edf6;margin:0;
                 display:flex;align-items:center;justify-content:center;
                 min-height:100vh;padding:32px">
      <div style="max-width:560px">
        <div style="font-size:15px;font-weight:700;letter-spacing:.22em;
                    color:#38bdf8;margin-bottom:20px">WGF</div>
        <h1 style="font-size:24px;margin:0 0 14px;font-weight:640">
          Start WGF, don't open this file</h1>
        <p style="color:#9fb0c6;margin:0 0 14px">
          This page is the front end of a local application. Opened straight
          from disk it has no stylesheet and no server to talk to, which is
          what you are seeing now.</p>
        <p style="color:#9fb0c6;margin:0 0 8px">Run one of these instead:</p>
        <pre style="background:#121924;border:1px solid #2a3547;border-radius:8px;
                    padding:14px 16px;color:#e6edf6;font-size:13px;overflow:auto"
        >WGF.cmd

python -m wifigeo</pre>
        <p style="color:#6b7b91;font-size:13px;margin:14px 0 0">
          It will start a server bound to 127.0.0.1 and open your browser on
          the right address automatically.</p>
      </div></body>`;
  throw new Error('WGF must be served by its own local server.');
}

const TOKEN = document.documentElement.dataset.token;
const $  = (s, r) => (r || document).querySelector(s);
const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));

const api = (path, opts = {}) => {
  const sep = path.includes('?') ? '&' : '?';
  return fetch(path + sep + 'token=' + encodeURIComponent(TOKEN), {
    ...opts,
    headers: { 'Content-Type': 'application/json', 'X-WGF-Token': TOKEN,
               ...(opts.headers || {}) }
  });
};

const esc = (s) => String(s == null ? '' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;');

const num = (v, d = 1) => (v === null || v === undefined || v === '')
  ? '&mdash;' : (typeof v === 'number' ? (+v.toFixed(d)).toLocaleString() : esc(v));

/* ------------------------------------------------------------------ boot */
api('/api/meta').then(r => r.json()).then(m => {
  $('#verPill').textContent = 'v' + m.version;
  const pill = $('#envPill');
  if (m.windows) {
    pill.textContent = 'radio available';
  } else {
    pill.textContent = 'no radio - manual BSSID only';
    pill.classList.add('bad');
  }
}).catch(() => {});

/* ---------------------------------------------------------------- ranges */
const bind = (id, out, fmt = v => v) => {
  const el = $('#' + id), o = $('#' + out);
  const sync = () => { o.textContent = fmt(el.value); };
  el.addEventListener('input', sync); sync();
};
bind('neighbours', 'neighboursOut');
bind('tile_zoom', 'zoomOut');
bind('replicates', 'replicatesOut');

/* ------------------------------------------------------------ scan picker */
$('#scanBtn').addEventListener('click', async () => {
  const btn = $('#scanBtn'), list = $('#netList');
  btn.classList.add('busy');
  $('#targetHint').textContent = 'Scanning the air around you…';
  try {
    const r = await api('/api/scan');
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || 'scan failed');

    if (!d.networks.length) {
      $('#targetHint').textContent = 'No networks were observed. '
        + (d.warnings || []).join(' ');
      list.hidden = true;
      return;
    }
    list.innerHTML = d.networks.map(n => {
      const bars = [ -80, -70, -60, -50 ]
        .map(t => `<i class="${n.best_rssi >= t ? 'on' : ''}"></i>`).join('');
      const name = n.hidden ? 'hidden network' : esc(n.ssid);
      const meta = [
        n.radios + ' radio' + (n.radios > 1 ? 's' : ''),
        (n.bands || []).join(' / ')
      ].filter(Boolean).join(' · ');
      return `<div class="netrow${n.hidden ? ' hidden-net' : ''}"
                   data-v="${esc(n.hidden ? n.bssids[0] : n.ssid)}">
        <span class="sig">${bars}</span>
        <span class="nm"><b>${name}</b><i>${esc(meta)}</i></span>
        <span class="dbm">${n.best_rssi} dBm</span></div>`;
    }).join('');
    list.hidden = false;
    $('#targetHint').textContent =
      `${d.beacon_count} access points observed via ${d.active_scan ? 'an active scan' : 'the cached list'}. Pick one.`;
    $$('.netrow', list).forEach(row => row.addEventListener('click', () => {
      $('#target').value = row.dataset.v;
      list.hidden = true;
      $('#targetHint').textContent = 'Picked. Press Locate.';
      if (typeof updatePlan === 'function') updatePlan();
    }));
  } catch (e) {
    $('#targetHint').textContent = 'Scan failed: ' + e.message;
  } finally {
    btn.classList.remove('busy');
  }
});

/* ----------------------------------------------------------- artefacts */
let IMPORTED = [];   // observations carried into the next run

function showObservations(obs, note) {
  IMPORTED = obs;
  if (typeof updatePlan === 'function') updatePlan();
  const box = $('#obsList');
  if (!obs.length) { box.hidden = true; return; }
  const rand = o => {
    const first = parseInt(o.bssid.slice(0, 2), 16);
    return (first & 0x02) !== 0;
  };
  box.innerHTML = obs.slice(0, 400).map(o => `
    <div class="obsrow${rand(o) ? ' rand' : ''}">
      <b>${esc(o.bssid)}</b>
      <span>${esc(o.ssid || o.context || '')}</span>
      <em>${rand(o) ? 'randomised' : esc((o.last_seen || '').slice(0, 10))}</em>
    </div>`).join('');
  box.hidden = false;
  const randomised = obs.filter(rand).length;
  $('#importHint').innerHTML = esc(note) +
    ` <b>${obs.length} address(es) staged.</b>` +
    (randomised ? ` ${randomised} use a randomised address and are weak
      identifiers &mdash; they are kept, but flagged.` : '');
}

$('#importBtn').addEventListener('click', async () => {
  const path = $('#artefactPath').value.trim();
  const text = $('#bssids').value.trim();
  if (!path && !text) {
    $('#importHint').textContent = 'Give a file path, or paste addresses above.';
    return;
  }
  $('#importBtn').disabled = true;
  try {
    const r = await api('/api/ingest', {
      method: 'POST', body: JSON.stringify({ path, text })
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || 'import failed');
    showObservations(d.observations || [], `Read as ${d.format}. ${d.note || ''}`);
  } catch (e) {
    $('#importHint').textContent = 'Import failed: ' + e.message;
  } finally {
    $('#importBtn').disabled = false;
  }
});


/* --------------------------------------------------------------- run flow */
let poller = null;

$('#runForm').addEventListener('submit', async (ev) => {
  ev.preventDefault();

  // An enquiry needs one of three things, and the operator may legitimately
  // use any of them. Saying which are empty beats a silent no-op.
  const typed = MODE === 'single' ? $('#target').value.trim() : '';
  const pasted = MODE === 'bulk' ? $('#bssids').value.trim() : '';
  if (!typed && !pasted && !(MODE === 'bulk' && IMPORTED.length)) {
    $('#idle').hidden = true;
    $('#results').hidden = true;
    $('#progress').hidden = false;
    setProgress('nothing to do',
                'Type a network name or address in Target, paste one or more ' +
                'access point addresses, or import an artefact.', 100);
    $('#target').focus();
    return;
  }

  const body = {
    // Only the active mode contributes, so switching away from a pane cannot
    // smuggle its contents into the run.
    target: MODE === 'single' ? $('#target').value.trim() : '',
    // Meaningless in bulk: each network is named by the artefact.
    known_ssid: MODE === 'single' ? $('#known_ssid').value.trim() : '',
    // Parsed observations are sent instead; the raw field stays only as a
    // fallback for a paste the parser has not finished reading.
    bssids: (MODE === 'bulk' && !IMPORTED.length)
      ? $('#bssids').value.trim() : '',
    observations: MODE === 'bulk' ? IMPORTED : [],
    context: MODE === 'single' ? CONTEXT : [],
    examiner: $('#examiner').value.trim(),
    organisation: $('#organisation').value.trim(),
    reference: $('#reference').value.trim(),
    notes: $('#notes').value.trim(),
    neighbours: +$('#neighbours').value,
    tile_zoom: +$('#tile_zoom').value,
    poi_radius_m: +$('#poi_radius_m').value,
    replicates: +$('#replicates').value,
    observed_at: $('#observed_at').value.trim(),
    msft_api_version: $('#msft_api_version').value,
    send_device_profile: $('#send_device_profile').checked,
    redact: $('#redact').checked,
    active_scan: $('#active_scan').checked,
    use_microsoft: $('#use_microsoft').checked,
    use_enrichment: $('#use_enrichment').checked,
    fetch_tiles: $('#fetch_tiles').checked,
    use_corroborating: $('#use_corroborating').checked
  };

  $('#runBtn').disabled = true;
  $('#idle').hidden = true;
  $('#results').hidden = true;
  $('#progress').hidden = false;
  $('#log').innerHTML = '';
  setProgress('start', 'Opening case', 0);

  try {
    const r = await api('/api/run', { method: 'POST', body: JSON.stringify(body) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || 'could not start');
    watch(d.id);
  } catch (e) {
    setProgress('error', e.message, 100);
    $('#runBtn').disabled = false;
  }
});

function setProgress(phase, msg, pct) {
  $('#progPhase').textContent = phase.replace(/[_-]/g, ' ');
  $('#progMsg').textContent = msg;
  $('#progPct').textContent = Math.round(pct) + '%';
  $('#progBar').style.width = pct + '%';
}

function watch(id) {
  let since = 0;
  clearInterval(poller);
  poller = setInterval(async () => {
    try {
      const r = await api(`/api/status?id=${id}&since=${since}`);
      const s = await r.json();
      since = s.event_count;
      for (const e of s.events) {
        setProgress(e.phase, e.message, e.percent);
        const li = document.createElement('li');
        li.innerHTML = `<span class="ph">${esc(e.phase)}</span><span>${esc(e.message)}</span>`;
        $('#log').appendChild(li);
        $('#log').parentElement.scrollTop = 1e9;
      }
      if (s.done) {
        clearInterval(poller);
        $('#runBtn').disabled = false;
        if (s.error) { setProgress('error', s.error, 100); return; }
        const rr = await api('/api/result?id=' + id);
        const doc = await rr.json();
        if (!rr.ok) { setProgress('error', doc.error || 'failed', 100); return; }
        setTimeout(() => render(doc), 380);
      }
    } catch (e) { /* transient; next tick retries */ }
  }, 420);
}

/* ---------------------------------------------------------------- render */
// A tab badge showing "0" reads as a broken counter rather than an empty
// section, so an empty count is omitted entirely.
const cnt = (n) => (n ? `<span class="cnt">${n}</span>` : '');

const VCLASS = {
  'CORROBORATED': 'v-strong', 'SUPPORTED': 'v-good', 'SINGLE-SOURCE': 'v-mid',
  'INDICATIVE': 'v-mid', 'SINGLE-SOURCE (WEAK)': 'v-low', 'WEAK': 'v-low',
  'UNRESOLVED': 'v-none'
};

function render(doc) {
  $('#progress').hidden = true;
  const el = $('#results');
  el.hidden = false;

  const v = doc.validation || {};
  const pos = doc.position;
  const co = doc.coordinates || {};
  const ev = doc.evidence || {};
  const addr = (doc.enrichment || {}).address || {};
  const ms = (doc.microsoft || {}).result || {};
  const ap = doc.apple || {};
  const cl = doc.cluster || {};
  const score = v.score || 0;
  const dash = 2 * Math.PI * 40;

  el.innerHTML = `
  <div class="hero ${VCLASS[v.verdict] || 'v-none'}">
    <div class="hero-main">
      <div class="hero-kicker">Assessment &middot; case ${esc(doc.case_id)}</div>
      <div class="hero-verdict">${esc(v.verdict || 'UNRESOLVED')}</div>
      <div class="hero-text">${esc(v.verdict_statement || '')}</div>
    </div>
    <div class="hero-score">
      <div class="ring-wrap">
        <svg viewBox="0 0 92 92"><circle class="ring-bg" cx="46" cy="46" r="40"/>
        <circle class="ring-fg" cx="46" cy="46" r="40"
          stroke-dasharray="${dash}" stroke-dashoffset="${dash}"
          style="stroke:var(--${score >= 85 ? 'ok' : score >= 50 ? 'warn' : 'bad'})"/></svg>
        <span class="ring-num">${Math.round(score)}</span>
      </div>
      <div class="ring-cap">${num(v.coverage, 0)}% of checks run</div>
    </div>
  </div>

  ${(doc.places || []).length > 1 ? placesBlock(doc) : ''}

  ${!pos && (doc.places || []).length > 1 ? '' : !pos ? `<div class="note bad"><b>No position established.</b>
     ${esc(doc.failure || 'No provider returned a usable position.')}</div>` : `
  <div class="cards">
    <div class="card"><div class="k">Position</div>
      <div class="v mono">${esc(co.decimal_precise || co.decimal || '')}</div>
      <div class="s">&plusmn;${num(pos.accuracy_m)} m &middot; ${esc(pos.method)}</div></div>
    <div class="card"><div class="k">Plus Code</div>
      <div class="v mono">${esc(co.plus_code || '')}</div>
      <div class="s">MGRS ${esc(co.mgrs || '')}</div></div>
    <div class="card"><div class="k">Locality</div>
      <div class="v" style="font-size:14px">${esc(addr.road || addr.neighbourhood || addr.city || 'not resolved')}</div>
      <div class="s">${esc([addr.city, addr.state, addr.country].filter(Boolean).join(', '))}</div></div>
    <div class="card"><div class="k">Access points</div>
      <div class="v">${num(ap.total_located, 0)}</div>
      <div class="s">${num(cl.kept_count, 0)} support &middot; ${num(cl.rejected_count, 0)} excluded</div></div>
  </div>` }

  ${pos ? `<div class="maplinks">
    <span class="mll">Open this position:</span>
    <a href="https://www.google.com/maps/search/?api=1&query=${pos.latitude.toFixed(8)},${pos.longitude.toFixed(8)}"
       target="_blank" rel="noopener noreferrer">Google Maps</a>
    <a href="https://www.google.com/maps/@${pos.latitude.toFixed(8)},${pos.longitude.toFixed(8)},19z/data=!3m1!1e3"
       target="_blank" rel="noopener noreferrer">Satellite</a>
    <a href="https://www.google.com/maps/@?api=1&map_action=pano&viewpoint=${pos.latitude.toFixed(8)},${pos.longitude.toFixed(8)}"
       target="_blank" rel="noopener noreferrer">Street View</a>
    <a href="https://www.openstreetmap.org/?mlat=${pos.latitude.toFixed(8)}&mlon=${pos.longitude.toFixed(8)}#map=19/${pos.latitude.toFixed(8)}/${pos.longitude.toFixed(8)}"
       target="_blank" rel="noopener noreferrer">OpenStreetMap</a>
    <a href="https://www.bing.com/maps?cp=${pos.latitude.toFixed(8)}~${pos.longitude.toFixed(8)}&lvl=19&style=a"
       target="_blank" rel="noopener noreferrer">Bing</a>
    <button class="mini copyco" data-c="${pos.latitude.toFixed(8)}, ${pos.longitude.toFixed(8)}">Copy coordinates</button>
  </div>` : ''}

  ${pos ? `<div class="mapcard">
    <div class="map" id="map"></div>
    <div class="mapbar">
      <span class="lg"><i style="background:var(--bad)"></i>Reported</span>
      <span class="lg"><i style="background:var(--accent)"></i>Target AP</span>
      <span class="lg"><i style="background:var(--warn)"></i>Microsoft</span>
      <span class="lg"><i style="background:rgba(56,189,248,.55)"></i>Neighbours</span>
      <span class="attrib">&copy; OpenStreetMap contributors</span>
      <span class="zoombtns"><button id="zo">&minus;</button><button id="zi">+</button></span>
    </div></div>` : ''}

  <div class="tabs" id="tabs">
    <button class="tab on" data-p="p-sig">Confidence</button>
    <button class="tab" data-p="p-dev">Devices${cnt((ap.queried || []).length)}</button>
    <button class="tab" data-p="p-int">Intelligence</button>
    <button class="tab" data-p="p-air">Radio survey${cnt((doc.survey || {}).beacon_count)}</button>
    <button class="tab" data-p="p-cus">Chain of custody${cnt(ev.file_count)}</button>
  </div>

  <div class="pane on" id="p-sig">${paneSignals(doc)}</div>
  <div class="pane" id="p-dev">${paneDevices(doc)}</div>
  <div class="pane" id="p-int">${paneIntel(doc)}</div>
  <div class="pane" id="p-air">${paneAir(doc)}</div>
  <div class="pane" id="p-cus">${paneCustody(doc)}</div>

  <div class="actions">
    <a class="btn primary" href="#" id="openReport">Open full report</a>
    ${doc.report_pdf_path ? '<button class="btn" id="openPdf">Open PDF</button>' : ''}
    ${doc.report_redacted_path
        ? '<button class="btn" id="openRedacted">Open redacted copy</button>' : ''}
    <button class="btn" id="openZip">Reveal evidence package</button>
    <button class="btn" id="copyJson">Copy result JSON</button>
  </div>`;

  // animate the score ring after layout
  requestAnimationFrame(() => {
    const c = $('.ring-fg');
    if (c) c.style.strokeDashoffset = dash * (1 - score / 100);
    $$('.trk span').forEach(s => { s.style.width = s.dataset.w + '%'; });
  });

  $('#tabs').addEventListener('click', e => {
    const b = e.target.closest('.tab'); if (!b) return;
    $$('.tab').forEach(t => t.classList.toggle('on', t === b));
    $$('.pane').forEach(p => p.classList.toggle('on', p.id === b.dataset.p));
  });

  $('#openReport').addEventListener('click', e => {
    e.preventDefault();
    api('/api/reveal?path=' + encodeURIComponent(doc.report_path || ''));
  });
  // Rendered only when the run produced them, so guard each lookup: asking for
  // a redacted copy and then having no way to open it is the whole reason
  // these are here.
  const reveal = (id, path) => {
    const el = $('#' + id);
    if (el) el.addEventListener('click', () =>
      api('/api/reveal?path=' + encodeURIComponent(path || '')));
  };
  reveal('openPdf', doc.report_pdf_path);
  reveal('openRedacted', doc.report_redacted_path);
  $('#openZip').addEventListener('click', () =>
    api('/api/reveal?path=' + encodeURIComponent((doc.evidence || {}).zip_path || '')));
  const cc = $('.copyco');
  if (cc) cc.addEventListener('click', ev =>
    copyToClipboard(ev.target.dataset.c, ev.target));
  $('#copyJson').addEventListener('click', ev =>
    copyToClipboard(JSON.stringify(doc, null, 2), ev.target));

  if (pos) drawMap(doc);
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

/* ------------------------------------------------------------- panes */
function paneSignals(doc) {
  const v = doc.validation || {};
  const row = (s, pen) => {
    const pct = pen ? 100 : (s.weight ? Math.max(0, s.awarded / s.weight) * 100 : 0);
    const cls = pen ? 'pen' : ({ pass: 'ok', warn: 'warn', fail: 'bad' }[s.status] || 'na');
    const tag = s.available === false ? '<span class="tagx na">not run</span>'
              : (pen ? '<span class="tagx bad">penalty</span>' : '');
    return `<div class="sigrow ${cls === 'na' ? 'na' : ''}">
      <div><div class="nm">${esc(s.name)}${tag}</div>
        <div class="de">${esc(s.detail)}</div></div>
      <div><div class="trk ${cls}"><span data-w="${pct.toFixed(0)}" style="width:0"></span></div></div>
      <div class="sc">${pen ? (s.awarded > 0 ? '+' : '') + num(s.awarded)
                            : num(s.awarded) + ' / ' + num(s.weight, 0)}</div></div>`;
  };
  const cov = (v.coverage || 100) < 100
    ? `<div class="note warn">${esc(v.coverage_note)}</div>` : '';
  const sep = v.separation_m != null
    ? `<div class="note">The two providers' fused positions are
       <b>${num(v.separation_m)} m</b> apart, bearing ${num((v.separation_bearing || {}).degrees)}&deg;
       (${esc((v.separation_bearing || {}).compass)}).</div>` : '';
  return cov + sep
    + (v.signals || []).map(s => row(s, false)).join('')
    + (v.penalties || []).map(s => row(s, true)).join('');
}

function paneDevices(doc) {
  const ap = doc.apple || {};
  const pairs = ((doc.validation || {}).context || {}).per_ap_pairs || [];
  const cols = doc.collisions || [];
  let out = '';

  if (cols.length) {
    out += `<div class="note bad"><b>${cols.length} conflicting record(s) excluded.</b>
      ${cols.map(c => esc(c.explanation)).join(' ')}</div>`;
  }

  out += '<h3 class="sh">Queried access points &mdash; Apple</h3>';
  out += `<table class="t"><thead><tr><th>BSSID</th><th>Latitude</th>
    <th>Longitude</th><th class="r">Acc m</th><th class="r">Alt m</th>
    <th>Status</th></tr></thead><tbody>${
    (ap.queried || []).map(a => `<tr class="${a.located ? 'hit' : ''}">
      <td class="mono">${esc(a.bssid)}</td>
      <td class="mono">${a.located ? a.latitude.toFixed(6) : '&mdash;'}</td>
      <td class="mono">${a.located ? a.longitude.toFixed(6) : '&mdash;'}</td>
      <td class="r">${num(a.accuracy_m, 0)}</td><td class="r">${num(a.altitude_m, 0)}</td>
      <td class="${a.located ? 'ok-t' : 'muted'}">${a.located ? 'located' : 'no record'}</td>
    </tr>`).join('') || '<tr><td colspan="6" class="muted">none</td></tr>'}</tbody></table>`;

  if (pairs.length) {
    out += `<h3 class="sh">Device-level cross-check &mdash; both providers, same device</h3>
      <div class="note">Each access point below was put to Apple and Microsoft
      individually. Agreement here is far stronger evidence than two aggregate
      positions happening to coincide.</div>
      <table class="t"><thead><tr><th>BSSID</th><th>Apple</th><th>Microsoft</th>
      <th class="r">Separation</th><th>Assessment</th></tr></thead><tbody>${
      pairs.map(p => `<tr class="${p.within_uncertainty ? 'hit' : ''}">
        <td class="mono">${esc(p.bssid)}</td>
        <td class="mono">${p.apple.latitude.toFixed(5)}, ${p.apple.longitude.toFixed(5)}</td>
        <td class="mono">${p.microsoft.latitude.toFixed(5)}, ${p.microsoft.longitude.toFixed(5)}</td>
        <td class="r"><b>${num(p.separation_m)} m</b></td>
        <td class="${p.within_uncertainty ? 'ok-t' : 'warn-t'}">
          ${p.within_uncertainty ? 'agree' : 'outside uncertainty'}</td></tr>`).join('')
      }</tbody></table>`;
  }

  const per = doc.microsoft_per_ap || {};
  if (per.discarded_ip_fallback) {
    out += `<div class="note warn"><b>${per.discarded_ip_fallback} IP-fallback
      answer(s) discarded.</b> Where Microsoft holds no record for an access
      point it returns a position derived from the querying connection's IP
      address rather than saying so. Those answers describe this machine's
      internet connection, not the target, and were rejected.</div>`;
  }

  const vend = doc.vendors || {};
  if (Object.keys(vend).length) {
    out += `<h3 class="sh">Hardware attribution</h3><table class="t"><thead><tr>
      <th>BSSID</th><th>Vendor</th><th>Address type</th><th>Source</th>
      </tr></thead><tbody>${Object.entries(vend).map(([m, d]) => `<tr>
        <td class="mono">${esc(m)}</td>
        <td>${esc(d.vendor || 'not attributed')}</td>
        <td class="${d.locally_administered ? 'warn-t' : ''}">${
          d.locally_administered ? 'locally administered (randomised)' : 'universally administered'}</td>
        <td class="muted">${esc(d.vendor_source || '')}</td></tr>`).join('')}</tbody></table>`;
  }
  return out;
}

function paneIntel(doc) {
  const e = doc.enrichment || {};
  const a = e.address || {}, env = e.environment || {}, day = e.daylight || {};
  const places = (e.places || {}).places || [];
  const co = doc.coordinates || {};
  let out = '';

  out += '<h3 class="sh">Coordinates</h3><table class="t"><tbody>'
    + Object.entries({
        'Decimal degrees': co.decimal_precise, 'Deg / min / sec': co.dms,
        'Plus Code': co.plus_code, 'MGRS': co.mgrs, 'UTM': co.utm,
        'Geohash': co.geohash
      }).map(([k, val]) => `<tr><td class="muted" style="width:34%">${k}</td>
        <td class="mono">${esc(val || '')}</td></tr>`).join('') + '</tbody></table>';

  if (a.display_name) {
    out += '<h3 class="sh">Address</h3><table class="t"><tbody>'
      + Object.entries({
          'Full address': a.display_name, 'Feature': a.name, 'Road': a.road,
          'Neighbourhood': a.neighbourhood, 'City': a.city, 'District': a.district,
          'State': a.state, 'Postcode': a.postcode, 'Country': a.country
        }).filter(([, val]) => val)
        .map(([k, val]) => `<tr><td class="muted" style="width:34%">${k}</td>
          <td>${esc(val)}</td></tr>`).join('') + '</tbody></table>';
  }

  if (env.elevation_m != null || day.sunrise) {
    out += '<h3 class="sh">Environment</h3><table class="t"><tbody>'
      + Object.entries({
          'Elevation': env.elevation_m != null ? env.elevation_m + ' m' : null,
          'Timezone': env.timezone, 'Sunrise (UTC)': day.sunrise,
          'Sunset (UTC)': day.sunset, 'Day length': day.day_length
        }).filter(([, val]) => val)
        .map(([k, val]) => `<tr><td class="muted" style="width:34%">${k}</td>
          <td class="mono">${esc(val)}</td></tr>`).join('') + '</tbody></table>';
  }

  if (places.length) {
    out += `<h3 class="sh">Nearby places (${places.length})</h3>
      <table class="t"><thead><tr><th>Name</th><th>Type</th>
      <th class="r">Distance</th><th>Bearing</th></tr></thead><tbody>${
      places.slice(0, 40).map(p => `<tr><td>${esc(p.name)}</td>
        <td class="muted">${esc(p.kind)}</td><td class="r">${num(p.distance_m, 0)} m</td>
        <td class="muted">${esc(p.bearing)}</td></tr>`).join('')}</tbody></table>`;
  }
  return out || '<p class="muted">Enrichment was not requested for this run.</p>';
}

function paneAir(doc) {
  const s = doc.survey || {};
  const targets = new Set((doc.target || {}).bssids || []);
  let out = '';
  if ((s.warnings || []).length) {
    out += `<div class="note warn">${s.warnings.map(esc).join('<br>')}</div>`;
  }
  out += `<div class="note">Collected via ${esc(s.method)}.
    ${s.active_scan ? 'An active scan was performed.'
                    : 'The cached beacon list was used; data may be stale.'}</div>`;
  out += `<table class="t"><thead><tr><th>BSSID</th><th>SSID</th>
    <th class="r">RSSI</th><th class="r">Ch</th><th>Band</th><th>PHY</th>
    <th>Enc</th></tr></thead><tbody>${
    (s.beacons || []).map(b => `<tr class="${targets.has(b.bssid) ? 'hit' : ''}">
      <td class="mono">${esc(b.bssid)}</td>
      <td>${b.hidden ? '<i class="muted">hidden</i>' : esc(b.ssid)}</td>
      <td class="r">${num(b.rssi_dbm, 0)} dBm</td><td class="r">${num(b.channel, 0)}</td>
      <td class="muted">${esc(b.band)}</td><td class="muted">${esc(b.phy)}</td>
      <td class="muted">${b.privacy === true ? 'yes' : b.privacy === false ? 'no' : '&mdash;'}</td>
    </tr>`).join('')}</tbody></table>`;
  return out;
}

function paneCustody(doc) {
  const ev = doc.evidence || {};
  const ex = ((doc.apple || {}).batches || []);
  return `<div class="note"><b>Every network transaction was captured in full</b>
    &mdash; request headers, request body, response headers and the response body
    exactly as it came off the wire &mdash; and written to disk before analysis.</div>
  <table class="t"><tbody>
    <tr><td class="muted" style="width:34%">Evidence package</td>
      <td class="mono" style="word-break:break-all">${esc(ev.zip_path || '')}</td></tr>
    <tr><td class="muted">Package size</td><td>${num(ev.zip_bytes, 0)} bytes</td></tr>
    <tr><td class="muted">Package SHA-256</td>
      <td class="mono" style="word-break:break-all;font-size:11px">${esc(ev.zip_sha256 || '')}</td></tr>
    <tr><td class="muted">Manifest root hash</td>
      <td class="mono" style="word-break:break-all;font-size:11px">${esc(ev.root_hash || '')}</td></tr>
    <tr><td class="muted">Files sealed</td><td>${num(ev.file_count, 0)}</td></tr>
    <tr><td class="muted">Verify with</td>
      <td class="mono">python verify_evidence.py</td></tr>
  </tbody></table>`;
}

/* ------------------------------------------------------------ slippy map */
const TILE = 'https://tile.openstreetmap.org/{z}/{x}/{y}.png';

function lonToX(lon, z) { return (lon + 180) / 360 * Math.pow(2, z); }
function latToY(lat, z) {
  const r = lat * Math.PI / 180;
  return (1 - Math.asinh(Math.tan(r)) / Math.PI) / 2 * Math.pow(2, z);
}

function drawMap(doc) {
  const host = $('#map');
  if (!host) return;
  const pos = doc.position;
  const state = { z: 17, cx: lonToX(pos.longitude, 17), cy: latToY(pos.latitude, 17) };

  const layer = document.createElement('div');
  layer.style.cssText = 'position:absolute;inset:0';
  host.appendChild(layer);

  const points = [];
  for (const a of ((doc.apple || {}).access_points || [])) {
    if (a.located && !a.queried) points.push({ lat: a.latitude, lon: a.longitude, c: 'n' });
  }
  for (const a of ((doc.apple || {}).queried || [])) {
    if (a.located) points.push({ lat: a.latitude, lon: a.longitude, c: 't' });
  }
  const ms = (doc.microsoft || {}).result || {};
  if (ms.located) points.push({ lat: ms.latitude, lon: ms.longitude, c: 'm' });
  points.push({ lat: pos.latitude, lon: pos.longitude, c: 'c' });

  function paint() {
    const w = host.clientWidth, h = host.clientHeight;
    const n = Math.pow(2, state.z);
    const originX = state.cx * 256 - w / 2, originY = state.cy * 256 - h / 2;
    const x0 = Math.floor(originX / 256), y0 = Math.floor(originY / 256);
    const cols = Math.ceil(w / 256) + 1, rows = Math.ceil(h / 256) + 1;

    let html = '';
    for (let dy = 0; dy <= rows; dy++) {
      for (let dx = 0; dx <= cols; dx++) {
        const tx = x0 + dx, ty = y0 + dy;
        if (ty < 0 || ty >= n) continue;
        const wx = ((tx % n) + n) % n;
        const url = TILE.replace('{z}', state.z).replace('{x}', wx).replace('{y}', ty);
        html += `<img src="${url}" style="position:absolute;width:256px;height:256px;
          left:${tx * 256 - originX}px;top:${ty * 256 - originY}px" alt="">`;
      }
    }
    // metres per pixel at this latitude, for the accuracy circle
    const mpp = 156543.03392 * Math.cos(pos.latitude * Math.PI / 180) / n;
    if (pos.accuracy_m) {
      const r = pos.accuracy_m / mpp;
      const px = lonToX(pos.longitude, state.z) * 256 - originX;
      const py = latToY(pos.latitude, state.z) * 256 - originY;
      html += `<div class="mk acc" style="left:${px - r}px;top:${py - r}px;
        width:${r * 2}px;height:${r * 2}px;transform:none"></div>`;
    }
    for (const p of points) {
      const px = lonToX(p.lon, state.z) * 256 - originX;
      const py = latToY(p.lat, state.z) * 256 - originY;
      if (px < -40 || py < -40 || px > w + 40 || py > h + 40) continue;
      html += `<div class="mk ${p.c}" style="left:${px}px;top:${py}px"></div>`;
    }
    layer.innerHTML = html;
  }

  let drag = null;
  host.addEventListener('pointerdown', e => {
    drag = { x: e.clientX, y: e.clientY }; host.classList.add('drag');
    host.setPointerCapture(e.pointerId);
  });
  host.addEventListener('pointermove', e => {
    if (!drag) return;
    state.cx -= (e.clientX - drag.x) / 256;
    state.cy -= (e.clientY - drag.y) / 256;
    drag = { x: e.clientX, y: e.clientY };
    paint();
  });
  const stop = () => { drag = null; host.classList.remove('drag'); };
  host.addEventListener('pointerup', stop);
  host.addEventListener('pointercancel', stop);
  host.addEventListener('wheel', e => {
    e.preventDefault();
    zoom(e.deltaY < 0 ? 1 : -1);
  }, { passive: false });

  function zoom(d) {
    const nz = Math.max(3, Math.min(19, state.z + d));
    if (nz === state.z) return;
    const f = Math.pow(2, nz - state.z);
    state.cx *= f; state.cy *= f; state.z = nz;
    paint();
  }
  $('#zi').addEventListener('click', () => zoom(1));
  $('#zo').addEventListener('click', () => zoom(-1));
  new ResizeObserver(paint).observe(host);
  paint();
}

// Copy to the clipboard and report honestly whether it worked.
//
// writeText rejects when the document is not focused, when the clipboard
// permission is refused, and on any non-secure origin. Every call site here
// used to set the label to "Copied" before knowing, so a failed copy still
// told the operator it had succeeded - and left an unhandled rejection in the
// console. Confirming something that did not happen is the one behaviour this
// tool should not have.
function copyToClipboard(text, el, okLabel) {
  const was = el.textContent;
  const restore = () => setTimeout(() => { el.textContent = was; }, 1500);
  const fail = () => { el.textContent = 'Press Ctrl+C'; restore(); };
  if (!navigator.clipboard || !navigator.clipboard.writeText) return fail();
  navigator.clipboard.writeText(text).then(() => {
    el.textContent = okLabel || 'Copied';
    restore();
  }, fail);
}

// Copy buttons on the "Where do I find an address?" commands. Delegated, so it
// works for the block whether or not it has been opened yet.
document.addEventListener('click', e => {
  const btn = e.target.closest('.cmd .copy');
  if (!btn) return;
  const code = btn.parentElement.querySelector('code');
  if (!code) return;
  copyToClipboard(code.textContent.trim(), btn);
});


/* ------------------------------------------------------- single vs bulk */
/* The first thing the operator chooses, because it was the first thing they
 * could not work out. Only the matching input is shown, and the plan below
 * describes whichever one is active. */
let MODE = 'single';

function setMode(m) {
  MODE = m;
  $('#modeSingle').classList.toggle('on', m === 'single');
  $('#modeBulk').classList.toggle('on', m === 'bulk');
  $('#modeSingle').setAttribute('aria-selected', String(m === 'single'));
  $('#modeBulk').setAttribute('aria-selected', String(m === 'bulk'));
  $('#paneSingle').hidden = m !== 'single';
  $('#paneBulk').hidden = m !== 'bulk';
  updatePlan();
}
$('#modeSingle').addEventListener('click', () => setMode('single'));
$('#modeBulk').addEventListener('click', () => setMode('bulk'));

/* ------------------------------------------------------------ file picker */
/* A browser will not reveal a file's location, so the bytes are sent instead
 * and the server writes a temporary copy for the parser. That is what lets one
 * control accept every format, including the ones the parser has to open
 * as a file rather than read as text. */
$('#pickBtn').addEventListener('click', () => $('#artefactFile').click());

$('#artefactFile').addEventListener('change', async (ev) => {
  const file = ev.target.files && ev.target.files[0];
  if (!file) return;
  $('#fileName').textContent = file.name;
  $('#importHint').textContent = 'Reading ' + file.name + '…';
  try {
    const buf = await file.arrayBuffer();
    let bin = '';
    const bytes = new Uint8Array(buf);
    for (let i = 0; i < bytes.length; i += 0x8000) {
      bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    }
    const r = await api('/api/ingest', {
      method: 'POST',
      body: JSON.stringify({ data_b64: btoa(bin), filename: file.name })
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || 'could not read that file');
    showObservations(d.observations || [], `Read as ${d.format}. ${d.note || ''}`);
  } catch (e) {
    $('#importHint').textContent = 'Could not read it: ' + e.message;
    $('#fileName').textContent = 'no file chosen';
  }
});


/* ----------------------------------------------- co-observed context */
/* The rest of the scan the target was seen in. Parsed by the same endpoint as
 * any other artefact, but kept apart from IMPORTED: these are beacons that
 * sharpen the position, not further access points to locate and report on. */
let CONTEXT = [];

function setContext(obs, note) {
  CONTEXT = obs || [];
  $('#ctxHint').textContent = CONTEXT.length
    ? `${CONTEXT.length} access point(s) added as context. ${note || ''}`
    : (note || 'No addresses were found in that.');
  updatePlan();
}

async function readContext(payload, label) {
  $('#ctxHint').textContent = 'Reading' + (label ? ' ' + label : '') + '…';
  try {
    const r = await api('/api/ingest', { method: 'POST', body: JSON.stringify(payload) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || 'could not read that');
    setContext(d.observations || [], `Read as ${d.format}.`);
  } catch (e) {
    setContext([], 'Could not read it: ' + e.message);
  }
}

$('#ctxReadBtn').addEventListener('click', () => {
  const text = $('#contextText').value.trim();
  if (!text) { setContext([], 'Paste a scan first.'); return; }
  readContext({ text });
});

$('#ctxPickBtn').addEventListener('click', () => $('#contextFile').click());
$('#contextFile').addEventListener('change', async (ev) => {
  const file = ev.target.files && ev.target.files[0];
  if (!file) return;
  $('#ctxFileName').textContent = file.name;
  const buf = await file.arrayBuffer();
  let bin = '';
  const bytes = new Uint8Array(buf);
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  readContext({ data_b64: btoa(bin), filename: file.name }, file.name);
});


/* ----------------------------------------------- pasted bulk input */
/* Sent to the same parser as a chosen file, rather than counted with a regex
 * here. The browser cannot know which MAC-shaped strings the parser will keep -
 * a WLAN event log is mostly the host's own adapter, which is excluded - so
 * counting locally made the plan claim more addresses than would be used. */
let pasteTimer = null;

async function parsePasted() {
  const text = $('#bssids').value.trim();
  if (!text) {
    IMPORTED = [];
    $('#pasteHint').textContent = 'Whatever you paste is read the same way a ' +
                                  'chosen file is; it will say what it found.';
    $('#obsList').hidden = true;
    updatePlan();
    return;
  }
  $('#pasteHint').textContent = 'Reading…';
  try {
    const r = await api('/api/ingest', { method: 'POST',
                                         body: JSON.stringify({ text }) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || 'could not read that');
    showObservations(d.observations || [], `Read as ${d.format}.`);
    $('#pasteHint').textContent =
      `Read as ${d.format} — ${d.count} address(es).` +
      (d.note ? ' ' + d.note : '');
  } catch (e) {
    IMPORTED = [];
    $('#pasteHint').textContent = 'Could not read that: ' + e.message;
    updatePlan();
  }
}

$('#bssids').addEventListener('input', () => {
  clearTimeout(pasteTimer);
  pasteTimer = setTimeout(parsePasted, 400);
});


/* ---------------------------------------------------------------- the plan */
/* What will be looked up, and what comes back, stated before the run rather
 * than inferable from the result afterwards. */

/* Saved profiles describe a machine's history: many places, months apart. A
 * scan is one moment in one place. They produce different reports. */
function historicalSources(obs) {
  const live = /scan|netsh/i;
  return [...new Set(obs.map(o => o.source || '').filter(s => s && !live.test(s)))];
}

function updatePlan() {
  const what = $('#planWhat'), gets = $('#planGets'), plan = $('#plan');
  if (!what) return;
  plan.classList.remove('plan-ready', 'plan-bulk', 'plan-history');

  if (MODE === 'single') {
    const typed = $('#target').value.trim();
    if (!typed) {
      what.textContent = 'Nothing to look up yet';
      gets.textContent = 'Paste an access point address, or use “Find it by ' +
                         'name” to have the radio look one up.';
      return;
    }
    plan.classList.add('plan-ready');
    const isMac = /^[0-9a-fA-F]{2}([:\-.][0-9a-fA-F]{2}){5}$|^[0-9a-fA-F]{12}$/
      .test(typed.replace(/\s/g, ''));
    if (!isMac) {
      // Saying "one network name" implied it could be looked up. It cannot.
      plan.classList.remove('plan-ready');
      plan.classList.add('plan-history');
      what.textContent = 'That is a network name, not an address';
      gets.textContent =
        'Neither Apple nor Microsoft accepts a network name. Use ' +
        '“Find it by name” to have this machine’s radio look it up — the ' +
        'network has to be in range — or paste its BSSID.';
      return;
    }
    what.textContent = CONTEXT.length
      ? `One access point, with ${CONTEXT.length} seen alongside it`
      : 'One access point address';
    gets.textContent = CONTEXT.length
      ? 'A single position for that address. The extra beacons go to Microsoft ' +
        'with it, which tightens the answer; they are not located or reported ' +
        'as subjects themselves.'
      : 'A single position, cross-checked against both providers. Adding the ' +
        'rest of the scan below makes it tighter.';
    return;
  }

  const imported = IMPORTED.length;
  if (!imported) {
    what.textContent = 'Nothing to look up yet';
    gets.textContent = $('#bssids').value.trim()
      ? 'Nothing in that could be read as an access point address.'
      : 'Choose a file, or paste the output of a scan or an event log.';
    return;
  }
  plan.classList.add('plan-ready', 'plan-bulk');

  {
    const hist = historicalSources(IMPORTED);
    what.textContent = `${imported} address${imported === 1 ? '' : 'es'} to look up`;
    if (hist.length) {
      plan.classList.add('plan-history');
      gets.textContent =
        `Saved profiles (${hist.join(', ')}) — networks this machine joined at ` +
        `different times, so they may be in different places. Each is located ` +
        `separately and you get a location history: every place, its networks, ` +
        `and the dates from the file.`;
    } else {
      gets.textContent =
        'Seen together, so they go to Microsoft as one fingerprint. You get a ' +
        'single position, and more addresses make it tighter.';
    }
    return;
  }

}

['#target', '#bssids'].forEach(sel => {
  const el = $(sel);
  if (el) el.addEventListener('input', updatePlan);
});
updatePlan();


/* ------------------------------------------------- location history block */
/* Shown when the enquiry resolved several places. Without it a bulk run
 * reported "No position established" on screen while the saved report carried
 * the whole history, so the answer was only visible in a file. */
function placesBlock(doc) {
  const places = doc.places || [];
  const dates = places.flatMap(p => [p.earliest_seen, p.latest_seen].filter(Boolean));
  const span = dates.length
    ? `${dates.slice().sort()[0].slice(0, 10)} to ${dates.slice().sort().pop().slice(0, 10)}`
    : '';
  const nets = places.reduce((n, p) => n + (p.network_count || 0), 0);

  const rows = places.map(p => {
    const level = (p.corroboration || {}).level || '';
    const cls = { strong: 'v-good', moderate: 'v-mid' }[level] || 'v-low';
    const when = (p.earliest_seen || p.latest_seen)
      ? `${(p.earliest_seen || '?').slice(0, 10)} &ndash; ${(p.latest_seen || '?').slice(0, 10)}`
      : '&mdash;';
    return `<tr>
      <td class="mono">${p.index}</td>
      <td><b>${esc(p.locality || '')}</b>${p.address
        ? `<i class="sub">${esc(p.address)}</i>` : ''}</td>
      <td class="mono">${esc(fmtPair(p.latitude, p.longitude))}</td>
      <td>${p.network_count}</td>
      <td>${when}</td>
      <td><span class="pill ${cls}">${esc(level || 'unrated')}</span></td>
    </tr>`;
  }).join('');

  return `<div class="note"><b>${places.length} distinct places.</b>
    ${nets} network(s)${span ? `, ${esc(span)}` : ''}. Averaging them would
    describe nowhere, so each is reported separately. The saved report carries
    the timeline, the scale diagram and the access points at each.</div>
  <table class="data places-t">
    <tr><th>#</th><th>Place</th><th>Position</th><th>Networks</th>
        <th>Seen</th><th>Support</th></tr>
    ${rows}
  </table>`;
}

function fmtPair(lat, lon) {
  if (lat === null || lat === undefined) return '';
  return `${Number(lat).toFixed(6)}, ${Number(lon).toFixed(6)}`;
}
