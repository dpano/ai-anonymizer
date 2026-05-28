#!/usr/bin/env python3
# Run: python app.py
from flask import Flask, render_template_string, request, jsonify, send_file
import re, json
from pathlib import Path
from io import BytesIO

app = Flask(__name__)
mapping = {"by_type": {}, "reverse": {}, "words": [], "word_map": {}, "exclusions": []}
MAPPING_FILE = Path("mapping_state.json")
PLACE_FMT = "ANON_{type}_{n}"

def save_to_disk():
    with open(MAPPING_FILE, "w") as f:
        json.dump(mapping, f, indent=2)

if MAPPING_FILE.exists():
    try: mapping.update(json.loads(MAPPING_FILE.read_text()))
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
body{font-family:system-ui,Segoe UI,Roboto,Arial;margin:12px} .container{display:grid;grid-template-columns:1fr 1fr 280px;gap:12px;align-items:start}
textarea{width:100%;height:70vh;font-family:monospace;font-size:13px;padding:8px;box-sizing:border-box}
.controls{display:flex;gap:8px;margin-bottom:8px}button{padding:6px 10px}.right-col{display:flex;flex-direction:column}.small{font-size:12px;color:#444;margin-top:6px}
</style></head><body>
<h2>Text & Code Anonymizer — Local UI</h2>
<div class="controls">
  <button id="anon">Anonymize →</button>
  <button id="deanon">← Deanonymize</button>
  <button id="download">Download mapping</button>
  <input type="file" id="loadmap" style="display:none"/>
  <button id="loadbtn">Load mapping JSON</button>
  <button id="clear">Clear mapping</button>
</div>
<div class="container">
  <div><label><strong>Input</strong></label><textarea id="input" spellcheck="false">// paste text or code here</textarea></div>
  <div><label><strong>Output</strong></label><textarea id="output" spellcheck="false">// anonymized or de-anonymized result</textarea></div>
  <div class="right-col">
    <label><strong>Custom words/names (one per line, case-insensitive)</strong></label>
    <textarea id="words" spellcheck="false"></textarea>
    <label style="margin-top:12px"><strong>Exclusions / Allow-list (no mask)</strong></label>
    <textarea id="exclusions" style="height:20vh" spellcheck="false" placeholder="e.g. mission_id"></textarea>
    <div class="small">Add sensitive names, brands, or projects then press Anonymize. Mapping persists across runs.</div>
  </div>
</div>
<script>
async function post(path, body){ const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}); return r.json(); }
window.onload = async () => {
  const localWords = localStorage.getItem('anon_words');
  const localExs = localStorage.getItem('anon_exs');
  if(localWords) document.getElementById('words').value = localWords;
  if(localExs) document.getElementById('exclusions').value = localExs;

  const state = await (await fetch('/get_state')).json();
  if(state.last_input) document.getElementById('input').value = state.last_input;
  if(state.last_output) document.getElementById('output').value = state.last_output;

  const w=document.getElementById('words'), ex=document.getElementById('exclusions');
  const s=()=>{ localStorage.setItem('anon_words', w.value); localStorage.setItem('anon_exs', ex.value); };
  w.oninput=s; w.onblur=s; ex.oninput=s; ex.onblur=s;
};
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
    return jsonify(mapping)

@app.route('/anonymize', methods=['POST'])
def api_anonymize():
    data = request.get_json() or {}
    text = data.get('text', '')
    words = data.get('words', [])
    exclusions = data.get('exclusions', [])

    existing = mapping.get("words", [])
    for w in words:
        if not any(x.lower() == w.lower() for x in existing):
            existing.append(w)
    mapping["words"] = existing

    existing_ex = mapping.get("exclusions", [])
    for e in exclusions:
        if not any(x.lower() == e.lower() for x in existing_ex):
            existing_ex.append(e)
    mapping["exclusions"] = existing_ex

    out = anonymize_text(text, mapping)
    mapping["last_input"] = text
    mapping["last_output"] = out
    save_to_disk()
    return jsonify({"result": out})

@app.route('/deanonymize', methods=['POST'])
def api_deanonymize():
    data = request.get_json() or {}
    text = data.get('text', '')
    out = deanonymize_text(text, mapping)
    mapping["last_input"] = text
    mapping["last_output"] = out
    save_to_disk()
    return jsonify({"result": out})

@app.route('/download_mapping')
def download_mapping():
    bio = BytesIO()
    bio.write(json.dumps(mapping, indent=2).encode('utf-8'))
    bio.seek(0)
    return send_file(bio, download_name='mapping.json', as_attachment=True, mimetype='application/json')

@app.route('/load_mapping', methods=['POST'])
def load_mapping_route():
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
    mapping.clear()
    mapping.update({"by_type": {}, "reverse": {}, "words": [], "word_map": {}, "exclusions": []})
    if MAPPING_FILE.exists(): MAPPING_FILE.unlink()
    return jsonify({"status": "cleared"})

if __name__ == '__main__':
    app.run(debug=True)
