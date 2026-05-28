#!/usr/bin/env python3
# Run: python app.py
from flask import Flask, render_template_string, request, jsonify, send_file
import re, json
from pathlib import Path
from io import BytesIO

app = Flask(__name__)
mapping = {"by_type": {}, "reverse": {}, "words": [], "word_map": {}}
PLACE_FMT = "<<ANON_{type}_{n}>>"

PATTERNS = [
    ("EMAIL", re.compile(r"\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")),
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
    typ_map = typ_map = by_type.setdefault(typ, {})
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
    token = f"<<ANON_WORD_{n}>>"
    wm[word] = token
    mapping_obj.setdefault("reverse", {})[token] = word
    return token

def anonymize_text(text, mapping_obj):
    def sub_email(m): return next_name(mapping_obj, "EMAIL", m.group(0))
    def sub_uuid(m): return next_name(mapping_obj, "UUID", m.group(0))
    def sub_ipv4(m): return next_name(mapping_obj, "IPV4", m.group(0))
    def sub_ipv6(m):
        orig = m.group(0)
        return orig if ":" not in orig or len(orig) < 5 else next_name(mapping_obj, "IPV6", orig)
    def sub_winpath(m): return next_name(mapping_obj, "WINPATH", m.group(0))
    def sub_unixpath(m): return next_name(mapping_obj, "UNIXPATH", m.group(0))
    def sub_domain(m): return next_name(mapping_obj, "DOMAIN", m.group(0))
    def sub_hex(m): return next_name(mapping_obj, "HEXSECRET", m.group(0))
    def sub_username(m):
        orig = m.group(1); return m.group(0).replace(orig, next_name(mapping_obj, "USERNAME", orig))
    def sub_idnum(m):
        orig = m.group(1); return m.group(0).replace(orig, next_name(mapping_obj, "IDNUM", orig))

    funcs = [
        (PATTERNS[0][1], sub_email),
        (PATTERNS[1][1], sub_uuid),
        (PATTERNS[2][1], sub_ipv4),
        (PATTERNS[3][1], sub_ipv6),
        (PATTERNS[4][1], sub_winpath),
        (PATTERNS[5][1], sub_unixpath),
        (PATTERNS[6][1], sub_domain),
        (PATTERNS[7][1], sub_hex),
        (PATTERNS[8][1], sub_username),
        (PATTERNS[9][1], sub_idnum),
    ]
    out = text
    for pat, fn in funcs:
        out = pat.sub(fn, out)

    # Substring-based word anonymization (case-insensitive), longest-first to reduce overlaps
    words = mapping_obj.get("words", [])
    if words:
        # sort words by length desc and escape for regex
        sorted_words = sorted(words, key=len, reverse=True)
        pattern = re.compile("(" + "|".join(re.escape(w) for w in sorted_words) + ")", re.IGNORECASE)
        def sub_word(m):
            orig = m.group(0)  # exact matched substring, preserve case
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
<h2>Code Anonymizer — Local UI</h2>
<div class="controls">
  <button id="anon">Anonymize →</button>
  <button id="deanon">← Deanonymize</button>
  <button id="download">Download mapping</button>
  <input type="file" id="loadmap" style="display:none"/>
  <button id="loadbtn">Load mapping JSON</button>
  <button id="clear">Clear mapping</button>
</div>
<div class="container">
  <div><label><strong>Input</strong></label><textarea id="input" spellcheck="false">// paste original code or text here</textarea></div>
  <div><label><strong>Output</strong></label><textarea id="output" spellcheck="false">// anonymized or de-anonymized result</textarea></div>
  <div class="right-col">
    <label><strong>Words to mask (one per line, substring match, case-insensitive)</strong></label>
    <textarea id="words" spellcheck="false"></textarea>
    <div class="small">Edit words then press Anonymize. Mapping persists until Clear mapping. Avoid very short common words.</div>
  </div>
</div>
<script>
async function post(path, body){ const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}); return r.json(); }
document.getElementById('anon').onclick = async ()=>{
  const inp = document.getElementById('input').value;
  const words = document.getElementById('words').value.split(/\\r?\\n/).map(s=>s.trim()).filter(Boolean);
  const res = await post('/anonymize',{text:inp, words: words});
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

@app.route('/anonymize', methods=['POST'])
def api_anonymize():
    data = request.get_json() or {}
    text = data.get('text', '')
    words = data.get('words', [])
    existing = mapping.get("words", [])
    for w in words:
        if not any(x.lower() == w.lower() for x in existing):
            existing.append(w)
    mapping["words"] = existing
    out = anonymize_text(text, mapping)
    return jsonify({"result": out})

@app.route('/deanonymize', methods=['POST'])
def api_deanonymize():
    data = request.get_json() or {}
    text = data.get('text', '')
    out = deanonymize_text(text, mapping)
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
    return jsonify({"status": "mapping loaded"})

@app.route('/clear_mapping', methods=['POST'])
def clear_mapping_route():
    mapping.clear()
    mapping.update({"by_type": {}, "reverse": {}, "words": [], "word_map": {}})
    return jsonify({"status": "cleared"})

if __name__ == '__main__':
    app.run(debug=True)
