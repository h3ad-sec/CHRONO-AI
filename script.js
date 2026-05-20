// CHRONO-AI — Attack Timeline Reconstructor

const PROVIDERS = {
  anthropic: { name:'Claude', defaultModel:'claude-sonnet-4-6',      storageKey:'chrono_key_anthropic', modelKey:'chrono_model_anthropic' },
  openai:    { name:'GPT',    defaultModel:'gpt-4o',                  storageKey:'chrono_key_openai',   modelKey:'chrono_model_openai'   },
  gemini:    { name:'Gemini', defaultModel:'gemini-2.0-flash',        storageKey:'chrono_key_gemini',   modelKey:'chrono_model_gemini'   },
  groq:      { name:'Groq',   defaultModel:'llama-3.3-70b-versatile', storageKey:'chrono_key_groq',    modelKey:'chrono_model_groq'    }
};
const PROVIDER_KEY = 'chrono_active_provider';

const SYSTEM_PROMPT = `You are an L3 incident responder and forensic analyst specializing in attack timeline reconstruction.
CRITICAL: Return ONLY raw JSON. No markdown fences, no preamble, no explanation. Invalid JSON breaks the tool.

STRICT DATA DISCIPLINE:
- Only include events explicitly present in the input — never fabricate events
- Timestamps: use exactly as they appear, do not normalize
- Stage mapping: map to the most accurate kill chain stage based on the actual event
- MITRE technique: only include if the event directly evidences a specific technique; use null if uncertain
- Significance: explain what this event means in the attack context — not generic descriptions
- Gaps: only list gaps apparent from the provided sequence
- Next steps: specific and actionable, grounded in what the timeline reveals

Kill chain stages — use these exact values for "stage":
Reconnaissance, Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact, Unknown

Return JSON with exactly these five keys:
{
  "summary": "2-3 sentences describing the attack pattern, scope, and likely objective — based only on the provided events.",
  "events": [
    {
      "timestamp": "Exact timestamp from input",
      "event": "Concise description using exact values (process names, IPs, usernames, paths) from the input",
      "stage": "One of the kill chain stages listed above",
      "technique": "TXXXX.XXX or null",
      "significance": "1 sentence: why this event matters in the attack context"
    }
  ],
  "attack_progression": "Narrative of attack stages in order — only stages evidenced by the events. 2-4 sentences.",
  "gaps": ["Specific timeline gap — e.g., 'No pre-execution logs between 03:12 and 03:14 — possible staging activity unlogged'"],
  "next_steps": ["Specific investigative or containment action — verb-first, reference specific events/accounts/systems from input"]
}
Order events chronologically. Map every event from the input. Write 2-4 gaps and 3-5 next steps.`;

let activeProvider = localStorage.getItem(PROVIDER_KEY) || 'anthropic';
let currentResult  = null;

async function callAI(userMessage) {
  const p      = PROVIDERS[activeProvider];
  const apiKey = localStorage.getItem(p.storageKey) || '';
  const model  = localStorage.getItem(p.modelKey) || p.defaultModel;
  if (!apiKey) throw new Error('No API key set for ' + p.name + '. Click ⚙ to add your key.');

  if (activeProvider === 'anthropic') {
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type':'application/json', 'x-api-key':apiKey, 'anthropic-version':'2023-06-01', 'anthropic-dangerous-direct-browser-access':'true' },
      body: JSON.stringify({ model, max_tokens:3000, system:SYSTEM_PROMPT, messages:[{role:'user',content:userMessage}] })
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error?.message || r.statusText);
    return d.content[0].text;
  }
  if (activeProvider === 'openai') {
    const r = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type':'application/json', 'Authorization':'Bearer '+apiKey },
      body: JSON.stringify({ model, max_tokens:3000, messages:[{role:'system',content:SYSTEM_PROMPT},{role:'user',content:userMessage}] })
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error?.message || r.statusText);
    return d.choices[0].message.content;
  }
  if (activeProvider === 'gemini') {
    const r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`, {
      method: 'POST',
      headers: { 'Content-Type':'application/json' },
      body: JSON.stringify({ contents:[{parts:[{text:SYSTEM_PROMPT+'\n\n'+userMessage}]}], generationConfig:{maxOutputTokens:3000} })
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error?.message || r.statusText);
    return d.candidates[0].content.parts[0].text;
  }
  if (activeProvider === 'groq') {
    const r = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type':'application/json', 'Authorization':'Bearer '+apiKey },
      body: JSON.stringify({ model, max_tokens:3000, messages:[{role:'system',content:SYSTEM_PROMPT},{role:'user',content:userMessage}] })
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error?.message || r.statusText);
    return d.choices[0].message.content;
  }
}

function parseJSON(raw) {
  let s = raw.trim();
  s = s.replace(/^```(?:json)?\n?/i,'').replace(/\n?```$/,'');
  return JSON.parse(s);
}

function esc(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function stageToClass(stage) {
  const map = {
    'reconnaissance':'stage-recon','initial access':'stage-initial','execution':'stage-execution',
    'persistence':'stage-persistence','privilege escalation':'stage-priv-esc',
    'defense evasion':'stage-defense','credential access':'stage-credential',
    'discovery':'stage-discovery','lateral movement':'stage-lateral','collection':'stage-collection',
    'command and control':'stage-c2','exfiltration':'stage-exfil','impact':'stage-impact'
  };
  return map[(stage||'').toLowerCase()] || 'stage-unknown';
}

function makeCard(icon, title, bodyHTML, open) {
  const cls = open ? 'section-card' : 'section-card collapsed';
  return `<div class="${cls}">
    <div class="section-header" onclick="this.closest('.section-card').classList.toggle('collapsed')">
      <div class="section-title"><span class="section-icon">${icon}</span>${esc(title)}</div>
      <div class="section-actions">
        <button class="copy-btn" onclick="event.stopPropagation();copyCard(this)">⧉ Copy</button>
        <span class="collapse-icon">▾</span>
      </div>
    </div>
    <div class="section-body">${bodyHTML}</div>
  </div>`;
}

function renderTimeline(events) {
  if (!events?.length) return '<p class="summary-text" style="color:var(--muted)">No events found.</p>';
  return events.map(ev => {
    const sc = stageToClass(ev.stage||'');
    const mitreId = ev.technique && ev.technique !== 'null' ? ev.technique : null;
    return `<div class="chrono-event">
      <div class="chrono-gutter ${sc}"></div>
      <div class="chrono-body">
        <div class="chrono-ts">${esc(ev.timestamp||'')}</div>
        <div class="chrono-event-text">${esc(ev.event||'')}</div>
        ${ev.significance ? `<div class="chrono-sig">${esc(ev.significance)}</div>` : ''}
        <div class="chrono-badges">
          <span class="stage-badge ${sc}">${esc(ev.stage||'Unknown')}</span>
          ${mitreId ? `<span class="mitre-id-badge">${esc(mitreId)}</span>` : ''}
        </div>
      </div>
    </div>`;
  }).join('');
}

function renderOutput(result) {
  currentResult = result;
  const ctx = document.getElementById('incident-context').value.trim();
  document.getElementById('output-title').textContent = ctx || 'Reconstructed';
  const c = document.getElementById('cards-container');
  c.innerHTML = [
    makeCard('⏱', 'Timeline Summary',        `<p class="summary-text">${esc(result.summary)}</p>`, true),
    makeCard('▶', 'Event Timeline',           renderTimeline(result.events), true),
    makeCard('◉', 'Attack Progression',       `<div class="progression-text">${esc(result.attack_progression)}</div>`, false),
    makeCard('○', 'Gaps & Blind Spots',       (result.gaps||[]).map(g=>`<div class="gap-item">${esc(g)}</div>`).join(''), false),
    makeCard('◱', 'Recommended Next Steps',   (result.next_steps||[]).map((s,i)=>`<div class="next-step-item"><span class="next-step-num">${i+1}</span><span style="font-size:var(--fs-sm);line-height:1.6;">${esc(s)}</span></div>`).join(''), false)
  ].join('');
}

function copyCard(btn) {
  const body = btn.closest('.section-card').querySelector('.section-body');
  navigator.clipboard.writeText(body.innerText);
  const orig = btn.textContent;
  btn.textContent = '✓';
  setTimeout(() => { btn.textContent = orig; }, 1500);
}

function buildExportText(fmt) {
  if (!currentResult) return '';
  const lines = [];
  const sec = (title, content) => lines.push(fmt==='md' ? `## ${title}\n\n${content}\n` : `=== ${title} ===\n\n${content}\n`);
  sec('Timeline Summary', currentResult.summary||'');
  if (currentResult.events?.length) sec('Event Timeline', currentResult.events.map(ev=>`[${ev.timestamp}] ${ev.stage}${ev.technique&&ev.technique!=='null'?' ('+ev.technique+')':''}\n${ev.event}\n${ev.significance||''}`).join('\n\n'));
  sec('Attack Progression', currentResult.attack_progression||'');
  if (currentResult.gaps?.length) sec('Gaps & Blind Spots', currentResult.gaps.map(g=>`- ${g}`).join('\n'));
  if (currentResult.next_steps?.length) sec('Recommended Next Steps', currentResult.next_steps.map((s,i)=>`${i+1}. ${s}`).join('\n'));
  return lines.join('\n');
}

// ── DOM
const generateBtn  = document.getElementById('generate-btn');
const clearBtn     = document.getElementById('clear-btn');
const eventsInput  = document.getElementById('events-input');
const loadingEl    = document.getElementById('loading-state');
const errorEl      = document.getElementById('error-state');
const outputEl     = document.getElementById('output-section');

function getActiveKey() { return localStorage.getItem(PROVIDERS[activeProvider].storageKey)||''; }
function updateBtn()    { generateBtn.disabled = !eventsInput.value.trim() || !getActiveKey(); }

generateBtn.addEventListener('click', async () => {
  const events = eventsInput.value.trim();
  if (!events) return;
  errorEl.classList.add('hidden');
  outputEl.classList.add('hidden');
  loadingEl.classList.remove('hidden');
  generateBtn.disabled = true;
  try {
    const ctx = document.getElementById('incident-context').value.trim();
    const msg = `Raw events:\n${events}${ctx?'\n\nIncident context: '+ctx:''}`;
    const raw    = await callAI(msg);
    const result = parseJSON(raw);
    loadingEl.classList.add('hidden');
    renderOutput(result);
    outputEl.classList.remove('hidden');
  } catch(e) {
    loadingEl.classList.add('hidden');
    document.getElementById('error-message').textContent = e.message;
    errorEl.classList.remove('hidden');
  } finally { updateBtn(); }
});

clearBtn.addEventListener('click', () => {
  eventsInput.value = '';
  document.getElementById('incident-context').value = '';
  errorEl.classList.add('hidden');
  outputEl.classList.add('hidden');
  updateBtn();
});
eventsInput.addEventListener('input', updateBtn);

document.getElementById('copy-all-btn').addEventListener('click', () => navigator.clipboard.writeText(buildExportText('md')));
document.getElementById('export-btn').addEventListener('click', () => {
  const fmt  = document.querySelector('.export-tab.active')?.dataset.fmt||'md';
  const blob = new Blob([buildExportText(fmt)],{type:'text/plain'});
  const a    = document.createElement('a'); a.href=URL.createObjectURL(blob); a.download=`chrono-${Date.now()}.${fmt}`; a.click();
});
document.querySelectorAll('.export-tab').forEach(t=>t.addEventListener('click',()=>{document.querySelectorAll('.export-tab').forEach(x=>x.classList.remove('active'));t.classList.add('active');}));
document.getElementById('new-btn').addEventListener('click',()=>{outputEl.classList.add('hidden');eventsInput.focus();});

// ── Settings modal
const overlay = document.getElementById('modal-overlay');
document.getElementById('settings-btn').addEventListener('click',()=>{overlay.classList.remove('hidden');loadModal();});
document.getElementById('close-modal').addEventListener('click',()=>overlay.classList.add('hidden'));
overlay.addEventListener('click',e=>{if(e.target===overlay)overlay.classList.add('hidden');});

function loadModal(){Object.entries(PROVIDERS).forEach(([id,p])=>{const k=document.getElementById('key-'+id);const m=document.getElementById('model-'+id);if(k)k.value=localStorage.getItem(p.storageKey)||'';if(m)m.value=localStorage.getItem(p.modelKey)||p.defaultModel;});document.querySelectorAll('.provider-tab').forEach(t=>t.classList.toggle('active',t.dataset.provider===activeProvider));}
document.getElementById('save-key-btn').addEventListener('click',()=>{Object.entries(PROVIDERS).forEach(([id,p])=>{const k=document.getElementById('key-'+id);const m=document.getElementById('model-'+id);if(k)localStorage.setItem(p.storageKey,k.value.trim());if(m)localStorage.setItem(p.modelKey,m.value);});localStorage.setItem(PROVIDER_KEY,activeProvider);overlay.classList.add('hidden');updateKeyStatus();updateBtn();updateBadge();updateNotice();});
document.querySelectorAll('.provider-tab').forEach(tab=>tab.addEventListener('click',()=>{activeProvider=tab.dataset.provider;document.querySelectorAll('.provider-tab').forEach(t=>t.classList.toggle('active',t.dataset.provider===activeProvider));}));
document.querySelectorAll('.toggle-key-btn').forEach(btn=>btn.addEventListener('click',()=>{const inp=document.getElementById(btn.dataset.target);inp.type=inp.type==='password'?'text':'password';}));

function updateKeyStatus(){const el=document.getElementById('key-status');const ok=!!getActiveKey();el.textContent=ok?'API Key Set':'No API Key';el.className='key-status '+(ok?'has-key':'no-key');}
function updateBadge(){const b=document.getElementById('active-provider-badge');const names={anthropic:'Claude',openai:'GPT-4o',gemini:'Gemini',groq:'Groq'};b.textContent=names[activeProvider]||activeProvider;b.className='provider-badge '+activeProvider;}
function updateNotice(){const el=document.getElementById('notice-provider');if(el)el.textContent=PROVIDERS[activeProvider]?.name||activeProvider;}

function applyTheme(t){document.body.classList.toggle('light',t==='light');document.body.classList.toggle('dark',t!=='light');const logo=document.getElementById('navLogo');if(logo)logo.src=`https://raw.githubusercontent.com/h3ad-sec/h3ad-sec.github.io/main/logo-${t==='light'?'light':'dark'}.png`;}
applyTheme(localStorage.getItem('h3ad-theme')||'dark');
document.getElementById('theme-toggle').addEventListener('click',()=>{const next=document.body.classList.contains('light')?'dark':'light';localStorage.setItem('h3ad-theme',next);applyTheme(next);});

window.addEventListener('scroll',()=>document.body.classList.toggle('scrolled',window.scrollY>40),{passive:true});
function toggleDrawer(){document.getElementById('navDrawer').classList.toggle('open');}
function closeDrawer(){document.getElementById('navDrawer').classList.remove('open');}

updateKeyStatus(); updateBadge(); updateNotice(); updateBtn(); loadModal();
