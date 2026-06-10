"""
Core anonymization and de-anonymization logic.
Depends on patterns.py for regex definitions and storage.py for token formatting.
"""
import re
from patterns import PATTERNS, DATE_TIME_PATTERNS
from storage import PLACE_FMT


def _collect_date_spans(text: str) -> set:
    """Return the set of character positions covered by any date/time pattern."""
    protected: set = set()
    for pat in DATE_TIME_PATTERNS:
        for m in pat.finditer(text):
            protected.update(range(m.start(), m.end()))
    return protected


def next_name(mapping_obj: dict, typ: str, original: str) -> str:
    """Return (and persist) the anonymization token for a typed PII value."""
    by_type = mapping_obj.setdefault("by_type", {})
    typ_map = by_type.setdefault(typ, {})
    if original in typ_map:
        return typ_map[original]
    n = len(typ_map) + 1
    token = PLACE_FMT.format(type=typ, n=n)
    typ_map[original] = token
    mapping_obj.setdefault("reverse", {})[token] = original
    return token


def make_word_token(mapping_obj: dict, word: str) -> str:
    """Return (and persist) the anonymization token for a custom word."""
    wm = mapping_obj.setdefault("word_map", {})
    if word in wm:
        return wm[word]
    n = len(wm) + 1
    token = f"ANON_WORD_{n}"
    wm[word] = token
    mapping_obj.setdefault("reverse", {})[token] = word
    return token


def anonymize_text(text: str, mapping_obj: dict) -> str:
    """
    Replace PII and custom words in *text* with opaque tokens.
    Date/time values are protected and never replaced.
    """
    protected = _collect_date_spans(text)

    def safe_sub(pat, label, text_in, capture_group=None):
        result = []
        prev = 0
        for m in pat.finditer(text_in):
            start, end = m.start(), m.end()
            # Skip matches that overlap a protected date/time span
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
                # Skip short hex strings that are not real IPv6 addresses
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

    # Apply custom word substitutions
    words = mapping_obj.get("words", [])
    exclusions = mapping_obj.get("exclusions", [])
    if words:
        ex_set = {x.lower() for x in exclusions}
        # Sort longest first so multi-word phrases match before their parts.
        # No \b anchors: custom terms must also match when embedded inside
        # larger words or identifiers (e.g. OPLAN inside ApprovedPostsInOPLAN).
        all_items = sorted(words + exclusions, key=len, reverse=True)
        word_pattern = re.compile(
            "(" + "|".join(re.escape(w) for w in all_items) + ")",
            re.IGNORECASE,
        )
        # Recompute protected spans on the partially-anonymized text
        protected2 = _collect_date_spans(out)

        def sub_word(m):
            if protected2.intersection(range(m.start(), m.end())):
                return m.group(0)
            orig = m.group(0)
            if orig.lower() in ex_set:
                return orig
            return make_word_token(mapping_obj, orig)

        out = word_pattern.sub(sub_word, out)

    return out


def deanonymize_text(text: str, mapping_obj: dict) -> str:
    """Replace all ANON_* tokens in *text* with their original values."""
    rev = mapping_obj.get("reverse", {})
    for token in sorted(rev.keys(), key=len, reverse=True):
        text = text.replace(token, rev[token])
    return text
