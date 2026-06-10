"""
Project store management: in-memory state, disk persistence, and active-project access.
"""
import json
from pathlib import Path

MAPPING_FILE = Path("mapping_state.json")
PLACE_FMT = "ANON_{type}_{n}"

_empty_project = lambda: {"by_type": {}, "reverse": {}, "words": [], "word_map": {}, "exclusions": []}

store = {
    "projects": {"default": _empty_project()},
    "active_project": "default",
}

# Load persisted state from disk on startup
if MAPPING_FILE.exists():
    try:
        data = json.loads(MAPPING_FILE.read_text())
        if "projects" in data:
            store.update(data)
    except Exception:
        pass


def save_to_disk() -> None:
    """Persist the full store to disk."""
    with open(MAPPING_FILE, "w") as f:
        json.dump(store, f, indent=2)


def get_mapping() -> dict:
    """Return the mapping dict for the currently active project, creating it if needed."""
    active = store.get("active_project", "default")
    if active not in store["projects"]:
        store["projects"][active] = _empty_project()
    return store["projects"][active]
