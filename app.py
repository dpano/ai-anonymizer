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
    ("UUID", re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")),
    ("IPv4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("IPv6", re.compile(r"\b([0-9a-fA-F:]{2,})\b")),
    ("WINPATH", re.compile(r"[A-Za-z]:\\[^\s\"']+")),
    ("UNIXPATH", re.compile(r"(?:/[^ \n\t\"']+)+")),
    ("DOMAIN", re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|io|dev|local|xyz|gov|edu)\b")),
    ("HEXSECRET", re.compile(r"\b[a-fA-F0-9]{32,}\b")),
    ("USERNAME", re.compile(r"\buser[:=]?[ \t]*([A-Za-z0-9._-]+)\b", re.IGNORECASE)),
    ("IDNUM", re.compile(r"\bID[:=]?[ \t]*([0-9]{3,})\b", re.IGNORECASE)),
]

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

def anonymize_text(text, mapping_obj):
    out = text
    for label, pat in PATTERNS:
        if label in ("USERNAME", "IDNUM"):
            def sub_labeled(m, lbl=label):
                orig = m.group(1)
                return m.group(0).replace(orig, next_name(mapping_obj, lbl, orig))
            out = pat.sub(sub_labeled, out)
        elif label == "IPv6":
            def sub_v6(m):
                orig = m.group(0)
                return orig if ":" not in orig or len(orig) < 5 else next_name(mapping_obj, "IPv6", orig)
            out = pat.sub(sub_v6, out)
        else:
            out = pat.sub(lambda m, lbl=label: next_name(mapping_obj, lbl, m.group(0)), out)

    # Substring-based word anonymization (case-insensitive), longest-first to reduce overlaps
    words = mapping_obj.get("words", [])
    exclusions = mapping_obj.get("exclusions", [])
    if words:
        ex_set = {x.lower() for x in exclusions}
        # Sort all items by length desc to ensure the most specific context (exclusion) is matched first
        all_items = sorted(words + exclusions, key=len, reverse=True)
        pattern = re.compile("(" + "|".join(re.escape(w) for w in all_items) + ")", re.IGNORECASE)

        def sub_word(m):
            orig = m.group(0)  # exact matched substring, preserve case
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
textarea{width:100%;height:70vh;font-family:monospace;font-size:13px;padding:8px;box-sizing:border-box}
.controls{display:flex;gap:8px;margin-bottom:8px}button{padding:6px 10px}.right-col{display:flex;flex-direction:column}.small{font-size:12px;color:#444;margin-top:6px}
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
    <div><label><strong>Output</strong></label><textarea id="output" spellcheck="false"></textarea></div>
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

async function loadState() {
  const state = await (await fetch('/get_state')).json();
  const mapping = state.mapping;
  currentProject = state.active_project;

  document.getElementById('input').value = mapping.last_input || '';
  document.getElementById('output').value = mapping.last_output || '';
  document.getElementById('active-name').textContent = `Project: ${currentProject}`;

  // Load words/exclusions from localStorage based on project name
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
  document.getElementById('output').value = res.result;
};
document.getElementById('deanon').onclick = async ()=>{
  const inp = document.getElementById('input').value;
  const res = await post('/deanonymize',{text:inp});
  document.getElementById('output').value = res.result;
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
