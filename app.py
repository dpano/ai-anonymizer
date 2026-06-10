#!/usr/bin/env python3
# Run: python app.py
"""
Flask application entry point.
Responsible only for route definitions and wiring together storage + anonymizer.
"""
import json
from io import BytesIO

from flask import Flask, render_template, request, jsonify, send_file

from storage import store, save_to_disk, get_mapping
from anonymizer import anonymize_text, deanonymize_text

app = Flask(__name__)


# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------

@app.route('/')
def index():
    return render_template('index.html')


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

@app.route('/get_state')
def get_state():
    return jsonify({
        "mapping": get_mapping(),
        "projects": store["projects"],
        "active_project": store["active_project"],
    })


# ---------------------------------------------------------------------------
# Project management
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Anonymization
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Mapping import / export
# ---------------------------------------------------------------------------

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
    for key in ("by_type", "reverse", "words", "word_map", "exclusions"):
        mapping.setdefault(key, {} if key not in ("words", "exclusions") else [])
    save_to_disk()
    return jsonify({"status": "mapping loaded"})


@app.route('/clear_mapping', methods=['POST'])
def clear_mapping_route():
    active = store["active_project"]
    store["projects"][active] = {"by_type": {}, "reverse": {}, "words": [], "word_map": {}, "exclusions": []}
    save_to_disk()
    return jsonify({"status": "cleared"})


# ---------------------------------------------------------------------------

if __name__ == '__main__':
    app.run(debug=True)
