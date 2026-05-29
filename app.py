#!/usr/bin/env python3
# Run: python app.py
from flask import Flask, render_template_string, request, jsonify, send_file
import re, json
from pathlib import Path
from io import BytesIO

app = Flask(__name__)

# Projects store: { project_name: mapping_dict }
store = {
    "projects": {"default": {"by_type": {}, "reverse": {}, "words": [], "word_map": {}, "exclusions": []}},
    "active_project": "default"
}

MAPPING_FILE = Path("mapping_state.json")
PLACE_FMT = "ANON_{type}_{n}"

def save_to_disk():
    with open(MAPPING_FILE, "w") as f:
        json.dump(store, f, indent=2)

def get_mapping():
    active = store.get("active_project", "default")
    if active not in store["projects"]:
        store["projects"][active] = {"by_type": {}, "reverse": {}, "words": [], "word_map": {}, "exclusions": []}
    return store["projects"][active]

if MAPPING_FILE.exists():
    try:
        data = json.loads(MAPPING_FILE.read_text())
        if "projects" in data:
            store.update(data)
    except: pass

PATTERNS = [
    ("EMAIL", re.compile(r"\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")),
    ("PHONE", re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")),
    ("CREDIT_CARD", re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")),
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("IBAN", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b")),
    ("UUID", re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")),
    # IPv4: require each octet to be 0-255, and exclude date-like patterns (dd.mm.yyyy etc.)
    ("IPv4", re.compile(r"\b(?!(?:\d{1,2}|\d{4})[./]\d{1,2}[./]\d{2,4}\b)(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")),
    ("IPv6", re.compile(r"\b([0-9a-fA-F:]{2,})\b")),
    # WINPATH: unchanged
    ("WINPATH", re.compile(r"[A-Za-z]:\\[^\s\"'<>]+")),
    # UNIXPATH: exclude date-like yyyy/mm/dd, dd/mm/yyyy, mm/dd/yyyy patterns
    ("UNIXPATH", re.compile(r"(?<![\w<:/.-])(?!\d{1,4}/\d{1,2}/\d{1,4}(?:\b|[^/]))(?:(?:\.{1,2}|~)?/[^ \n\t\"'<>]+|[a-zA-Z0-9_-]+(?:/[^ \n\t\"'<>]+){2,}|[a-zA-Z0-9_-]+(?:/[^ \n\t\"'<>]+)+\.[a-zA-Z0-9]{2,10}(?:#[^ \n\t\"'<>]+)?)")),
    ("DOMAIN", re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|io|dev|local|xyz|gov|edu)\b")),
    ("HEXSECRET", re.compile(r"\b[a-fA-F0-9]{32,}\b")),
    ("USERNAME", re.compile(r"\buser(?:[:=]\s*|\s+)([A-Za-z0-9._-]+)\b", re.IGNORECASE)),
    ("IDNUM", re.compile(r"\bID(?:[:=]\s*|\s+)([0-9]{3,})\b", re.IGNORECASE)),
]

# Date/time patterns to explicitly skip (never anonymize these)
DATE_TIME_PATTERNS = [
    # ISO 8601: 2025-03-12, 2025-03-12T14:30:00, 2025-03-12T14:30:00Z, 2025-03-12T14:30:00+02:00
    re.compile(r"\b\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])(?:[T ]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)?\b"),
    # dd/mm/yyyy or mm/dd/yyyy or dd-mm-yyyy etc.
    re.compile(r"\b(?:0?[1-9]|[12]\d|3[01])[/\-.](?:0?[1-9]|1[0-2])[/\-.](?:\d{2}|\d{4})\b"),
    # yyyy/mm/dd
    re.compile(r"\b\d{4}[/\-.](0?[1-9]|1[0-2])[/\-.](0?[1-9]|[12]\d|3[01])\b"),
    # Time only: HH:MM, HH:MM:SS, HH:MM:SS.mmm
    re.compile(r"\b(?:[01]\d|2[0-3]):\d{2}(?::\d{2}(?:\.\d+)?)?\b"),
    # Month name dates: 12 January 2025, January 12 2025, Jan 12 2025, 12 Jan 2025
    re.compile(r"\b(?:\d{1,2}\s+)?(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)(?:\s+\d{1,2})?(?:,?\s+\d{4})?\b", re.IGNORECASE),
]

def _collect_date_spans(text):
    """Return a set of character positions that are part of a date/time match."""
    protected = set()
    for pat in DATE_TIME_PATTERNS:
        for m in pat.finditer(text):
            protected.update(range(m.start(), m.end()))
    return protected

def anonymize_text(text, mapping_obj):
    # First, collect all character positions covered by date/time patterns
    protected = _collect_date_spans(text)

    out_chars = list(text)  # work on a char list so we can track positions
    # We'll do replacements on the string but skip matches that overlap protected spans

    def safe_sub(pat, label, text_in, capture_group=None):
        result = []
        prev = 0
        for m in pat.finditer(text_in):
            start, end = m.start(), m.end()
            # Skip if any character of this match is in a protected (date/time) span
            if protected.intersection(range(start, end)):
                result.append(text_in[prev:end])
                prev = end
                continue
            result.append(text_in[prev:start])
            if capture_group is not None:
                orig = m.group(capture_group)
                result.append(m.group(0).replace(orig, next_name(mapping_obj, label, orig)))
            elif label == "IPv6":
                orig = m.group(0)
                replacement = orig if ":" not in orig or len(orig) < 5 else next_name(mapping_obj, "IPv6", orig)
                result.append(replacement)
            else:
                result.append(next_name(mapping_obj, label, m.group(0)))
            prev = end
        result.append(text_in[prev:])
        return "".join(result)

    out = text
    for label, pat in PATTERNS:
        if label in ("USERNAME", "IDNUM"):
            out = safe_sub(pat, label, out, capture_group=1)
        else:
            out = safe_sub(pat, label, out)

    words = mapping_obj.get("words", [])
    exclusions = mapping_obj.get("exclusions", [])
    if words:
        ex_set = {x.lower() for x in exclusions}
        all_items = sorted(words + exclusions, key=len, reverse=True)
        pattern = re.compile(r"\b(" + "|".join(re.escape(w) for w in all_items) + r")", re.IGNORECASE)

        # Recompute protected spans on the partially-anonymized text
        protected2 = _collect_date_spans(out)

        def sub_word(m):
            if protected2.intersection(range(m.start(), m.end())):
                return m.group(0)
            orig = m.group(0)
            if orig.lower() in ex_set:
                return orig
            return make_word_token(mapping_obj, orig)
        out = pattern.sub(sub_word, out)
    return out

def deanonymize_text(text, mapping_obj):
    rev = mapping_obj.get("reverse", {})
    for token in sorted(rev.keys(), key=len, reverse=True):
        text = text.replace(token, rev[token])
    return text

def next_name(mapping_obj, typ, original):
    by_type = mapping_obj.setdefault("by_type", {})
    typ_map = by_type.setdefault(typ, {})
    if original in typ_map:
        return typ_map[original]
    n = len(typ_map) + 1
    token = PLACE_FMT.format(type=typ, n=n)
    typ_map[original] = token
    mapping_obj.setdefault("reverse", {})[token] = original
    return token

def make_word_token(mapping_obj, word):
    wm = mapping_obj.setdefault("word_map", {})
    if word in wm:
        return wm[word]
    n = len(wm) + 1
    token = f"ANON_WORD_{n}"
    wm[word] = token
    mapping_obj.setdefault("reverse", {})[token] = word
    return token

HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>Anonymizer UI</title><style>
body{font-family:system-ui,Segoe UI,Roboto,Arial;margin:0;display:flex;height:100vh;overflow:hidden}
.sidebar{width:240px;background:#f5f5f5;border-right:1px solid #ddd;display:flex;flex-direction:column;transition:margin-left 0.3s}
.sidebar.collapsed{margin-left:-240px}
.sidebar-header{padding:12px;font-weight:bold;border-bottom:1px solid #ddd;display:flex;justify-content:space-between;align-items:center}
.project-list{flex:1;overflow-y:auto;padding:8px}
.project-item{padding:8px;margin-bottom:4px;cursor:pointer;border-radius:4px;display:flex;justify-content:space-between;align-items:center}
.project-item:hover{background:#e0e0e0}
.project-item.active{background:#0078d4;color:white}
.main-content{flex:1;display:flex;flex-direction:column;padding:12px;overflow:hidden}
.container{display:grid;grid-template-columns:1fr 1fr 280px;gap:12px;flex:1;overflow:hidden}
textarea, .output-box{width:100%;height:70vh;font-family:monospace;font-size:13px;line-height:1.5;padding:8px;box-sizing:border-box;border:1px solid #767676;border-radius:2px;}
.output-box{overflow-y:auto;white-space:pre-wrap;background:#fff;word-wrap:break-word;height:calc(70vh - 24px);}
mark{background:#fff3cd;color:#856404;font-weight:bold;padding:0 2px;border-radius:2px;border:1px solid #ffeeba; cursor:pointer; transition:background 0.2s;}
mark:hover{background:#ffeeba; border-color:#f5c6cb;}
.controls{display:flex;gap:8px;margin-bottom:8px}button{padding:6px 10px; cursor:pointer;}.right-col{display:flex;flex-direction:column}.small{font-size:12px;color:#444;margin-top:6px}
.btn-del{background:none;border:none;color:inherit;cursor:pointer;font-weight:bold;padding:0 4px}
.btn-del:hover{color:#ff4d4d}
</style></head><body>
<div id="sidebar" class="sidebar">
  <div class="sidebar-header"><span>Projects</span></div>
  <div id="project-list" class="project-list"></div>
  <div style="padding:12px;border-top:1px solid #ddd">
    <input id="new-project" type="text" placeholder="New project..." style="width:100%;margin-bottom:8px;padding:4px;box-sizing:border-box">
    <button id="add-project" style="width:100%">+ Add Project</button>
  </div>
</div>
<div class="main-content">
  <div class="controls">
    <button id="toggle-sb">☰</button>
    <button id="anon">Anonymize →</button>
    <button id="deanon">← Deanonymize</button>
    <button id="download">Download mapping</button>
    <input type="file" id="loadmap" style="display:none"/>
    <button id="loadbtn">Load JSON</button>
    <button id="clear">Clear Mapping</button>
    <span id="active-name" style="margin-left:auto;font-weight:bold;align-self:center;color:#0078d4"></span>
  </div>
  <div class="container">
    <div><label><strong>Input</strong></label><textarea id="input" spellcheck="false"></textarea></div>
    
    <div style="display: flex; flex-direction: column;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 2px;">
         <label><strong>Output (Click tags to locate in input)</strong></label>
         <button id="copy-btn" style="padding: 2px 8px; font-size: 12px; height: 22px;">Copy</button>
      </div>
      <div id="output" class="output-box" spellcheck="false"></div>
    </div>
    
    <div class="right-col">
      <label><strong>Custom words</strong></label>
      <textarea id="words" spellcheck="false" style="height:30vh"></textarea>
      <label style="margin-top:12px"><strong>Exclusions</strong></label>
      <textarea id="exclusions" style="height:30vh" spellcheck="false"></textarea>
      <div class="small">Settings are saved per project to browser storage and disk.</div>
    </div>
  </div>
</div>
<script>
async function post(path, body){ const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}); return r.json(); }

let currentProject = 'default';
let appMapping = null;
let lastOutputText = ''; 

function renderOutput(text) {
  lastOutputText = text || '';
  const outEl = document.getElementById('output');
  if(!text) { outEl.innerHTML = ''; return; }
  
  let escaped = text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  escaped = escaped.replace(/(ANON_[A-Za-z0-9_]+)/g, '<mark>$1</mark>');
  outEl.innerHTML = escaped;
}

// Click listener to find tags in the original text and visually scroll to them
document.getElementById('output').addEventListener('click', (e) => {
  if (e.target.tagName === 'MARK') {
    const token = e.target.textContent;
    if (appMapping && appMapping.reverse && appMapping.reverse[token]) {
      const originalText = appMapping.reverse[token];
      const inputEl = document.getElementById('input');
      const idx = inputEl.value.indexOf(originalText);
      
      if (idx !== -1) {
        // Highlight the text in the input box
        inputEl.focus();
        inputEl.setSelectionRange(idx, idx + originalText.length);
        
        // --- SCROLL CALCULATION TRICK ---
        // We create an invisible container with the exact same width and text formatting 
        // as the input box to perfectly calculate the height of the text up to your clicked word.
        const clone = document.createElement('div');
        clone.style.width = inputEl.clientWidth + 'px';
        clone.style.fontFamily = 'monospace';
        clone.style.fontSize = '13px';
        clone.style.lineHeight = '1.5';
        clone.style.padding = '8px';
        clone.style.boxSizing = 'border-box';
        clone.style.whiteSpace = 'pre-wrap';
        clone.style.wordWrap = 'break-word';
        clone.style.position = 'absolute';
        clone.style.visibility = 'hidden';
        
        // We add an 'X' to ensure the height is accurate even if the word is on a new line
        clone.textContent = inputEl.value.substring(0, idx) + 'X';
        document.body.appendChild(clone);
        
        // Automatically scroll the textarea so the word appears directly in the middle of the box
        inputEl.scrollTop = clone.offsetHeight - (inputEl.clientHeight / 2);
        clone.remove();
      }
    }
  }
});

document.getElementById('copy-btn').addEventListener('click', async () => {
  if (!lastOutputText) return;
  try {
    await navigator.clipboard.writeText(lastOutputText);
    showCopied();
  } catch (err) {
    const textArea = document.createElement("textarea");
    textArea.value = lastOutputText;
    document.body.appendChild(textArea);
    textArea.select();
    document.execCommand("Copy");
    textArea.remove();
    showCopied();
  }
});

function showCopied() {
  const btn = document.getElementById('copy-btn');
  btn.textContent = 'Copied!';
  setTimeout(() => btn.textContent = 'Copy', 2000);
}

async function loadState() {
  const state = await (await fetch('/get_state')).json();
  appMapping = state.mapping;
  currentProject = state.active_project;

  document.getElementById('input').value = appMapping.last_input || '';
  renderOutput(appMapping.last_output || '');
  document.getElementById('active-name').textContent = `Project: ${currentProject}`;

  document.getElementById('words').value = localStorage.getItem(`words_${currentProject}`) || '';
  document.getElementById('exclusions').value = localStorage.getItem(`exs_${currentProject}`) || '';
  
  renderProjects(state.projects);
}

function renderProjects(projects) {
  const list = document.getElementById('project-list');
  list.innerHTML = '';
  Object.keys(projects).forEach(name => {
    const div = document.createElement('div');
    div.className = `project-item ${name === currentProject ? 'active' : ''}`;
    div.onclick = () => switchProject(name);
    div.innerHTML = `<span>${name}</span>${name !== 'default' ? `<button class="btn-del" onclick="event.stopPropagation(); deleteProject('${name}')">×</button>` : ''}`;
    list.appendChild(div);
  });
}

async function switchProject(name) {
  await post('/switch_project', {name});
  await loadState();
}

async function addProject() {
  const name = document.getElementById('new-project').value.trim();
  if(!name) return;
  await post('/add_project', {name});
  document.getElementById('new-project').value = '';
  await loadState();
}

async function deleteProject(name) {
  if(!confirm(`Delete project "${name}"?`)) return;
  await post('/delete_project', {name});
  await loadState();
}

window.onload = async () => {
  await loadState();
  const w=document.getElementById('words'), ex=document.getElementById('exclusions');
  const s=()=>{ localStorage.setItem(`words_${currentProject}`, w.value); localStorage.setItem(`exs_${currentProject}`, ex.value); };
  w.oninput=s; w.onblur=s; ex.oninput=s; ex.onblur=s;
};

document.getElementById('toggle-sb').onclick = () => document.getElementById('sidebar').classList.toggle('collapsed');
document.getElementById('add-project').onclick = addProject;

document.getElementById('anon').onclick = async ()=>{
  const inp = document.getElementById('input').value;
  const words = document.getElementById('words').value.split(/\\r?\\n/).map(s=>s.trim()).filter(Boolean);
  const exclusions = document.getElementById('exclusions').value.split(/\\r?\\n/).map(s=>s.trim()).filter(Boolean);
  const res = await post('/anonymize',{text:inp, words: words, exclusions: exclusions});
  
  const state = await (await fetch('/get_state')).json();
  appMapping = state.mapping;
  
  renderOutput(res.result);
};

document.getElementById('deanon').onclick = async ()=>{
  const inp = document.getElementById('input').value;
  const res = await post('/deanonymize',{text:inp});
  renderOutput(res.result);
};

document.getElementById('download').onclick = async ()=>{
  const r = await fetch('/download_mapping');
  const blob = await r.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = 'mapping.json'; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
};

document.getElementById('loadbtn').onclick = ()=> document.getElementById('loadmap').click();
document.getElementById('loadmap').onchange = async (e)=>{
  const f = e.target.files[0]; if(!f) return;
  const txt = await f.text();
  try{ const parsed = JSON.parse(txt); const resp = await post('/load_mapping', {mapping: parsed}); alert(resp.status); }catch(err){ alert('Invalid JSON'); }
};

document.getElementById('clear').onclick = async ()=>{
  if(!confirm('Clear mapping (irreversible in this session)?')) return;
  await post('/clear_mapping', {}); alert('Mapping cleared.');
  await loadState();
};
</script></body></html>
"""

@app.route('/')
def index():
    return render_template_string(HTML)

@app.route('/get_state')
def get_state():
    return jsonify({"mapping": get_mapping(), "projects": store["projects"], "active_project": store["active_project"]})

@app.route('/switch_project', methods=['POST'])
def switch_project():
    name = request.get_json().get('name', 'default')
    store["active_project"] = name
    save_to_disk()
    return jsonify({"status": "switched"})

@app.route('/add_project', methods=['POST'])
def add_project():
    name = request.get_json().get('name')
    if name and name not in store["projects"]:
        store["projects"][name] = {"by_type": {}, "reverse": {}, "words": [], "word_map": {}, "exclusions": []}
        store["active_project"] = name
        save_to_disk()
    return jsonify({"status": "added"})

@app.route('/delete_project', methods=['POST'])
def delete_project():
    name = request.get_json().get('name')
    if name in store["projects"] and name != "default":
        del store["projects"][name]
        if store["active_project"] == name:
            store["active_project"] = "default"
        save_to_disk()
    return jsonify({"status": "deleted"})

@app.route('/anonymize', methods=['POST'])
def api_anonymize():
    mapping = get_mapping()
    data = request.get_json() or {}
    text = data.get('text', '')
    words = data.get('words', [])
    exclusions = data.get('exclusions', [])

    mapping["words"] = list(set(mapping.get("words", []) + words))
    mapping["exclusions"] = list(set(mapping.get("exclusions", []) + exclusions))

    out = anonymize_text(text, mapping)
    mapping["last_input"] = text
    mapping["last_output"] = out
    save_to_disk()
    return jsonify({"result": out})

@app.route('/deanonymize', methods=['POST'])
def api_deanonymize():
    mapping = get_mapping()
    data = request.get_json() or {}
    text = data.get('text', '')
    out = deanonymize_text(text, mapping)
    mapping["last_input"] = text
    mapping["last_output"] = out
    save_to_disk()
    return jsonify({"result": out})

@app.route('/download_mapping')
def download_mapping():
    mapping = get_mapping()
    bio = BytesIO()
    bio.write(json.dumps(mapping, indent=2).encode('utf-8'))
    bio.seek(0)
    return send_file(bio, download_name='mapping.json', as_attachment=True, mimetype='application/json')

@app.route('/load_mapping', methods=['POST'])
def load_mapping_route():
    mapping = get_mapping()
    data = request.get_json() or {}
    new_map = data.get('mapping')
    if not isinstance(new_map, dict):
        return jsonify({"status": "mapping must be an object"}), 400
    mapping.clear()
    mapping.update(new_map)
    mapping.setdefault("by_type", {})
    mapping.setdefault("reverse", {})
    mapping.setdefault("words", [])
    mapping.setdefault("word_map", {})
    mapping.setdefault("exclusions", [])
    save_to_disk()
    return jsonify({"status": "mapping loaded"})

@app.route('/clear_mapping', methods=['POST'])
def clear_mapping_route():
    active = store["active_project"]
    store["projects"][active] = {"by_type": {}, "reverse": {}, "words": [], "word_map": {}, "exclusions": []}
    save_to_disk()
    return jsonify({"status": "cleared"})

if __name__ == '__main__':
    app.run(debug=True)