"""
Regex pattern definitions for anonymization.
- PATTERNS: PII patterns to detect and replace.
- DATE_TIME_PATTERNS: date/time patterns to explicitly protect (never anonymized).
"""
import re

PATTERNS = [
    ("EMAIL",       re.compile(r"\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")),
    ("PHONE",       re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")),
    ("CREDIT_CARD", re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")),
    ("SSN",         re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("IBAN",        re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b")),
    ("UUID",        re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")),
    # IPv4: require each octet 0-255, exclude date-like patterns (dd.mm.yyyy etc.)
    ("IPv4",        re.compile(r"\b(?!(?:\d{1,2}|\d{4})[./]\d{1,2}[./]\d{2,4}\b)(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")),
    ("IPv6",        re.compile(r"\b([0-9a-fA-F:]{2,})\b")),
    # WINPATH: Windows file paths
    ("WINPATH",     re.compile(r"[A-Za-z]:\\[^\s\"'<>]+")),
    # UNIXPATH: exclude date-like yyyy/mm/dd, dd/mm/yyyy, mm/dd/yyyy patterns
    ("UNIXPATH",    re.compile(r"(?<![\w<:/.-])(?!\d{1,4}/\d{1,2}/\d{1,4}(?:\b|[^/]))(?:(?:\.{1,2}|~)?/[^ \n\t\"'<>]+|[a-zA-Z0-9_-]+(?:/[^ \n\t\"'<>]+){2,}|[a-zA-Z0-9_-]+(?:/[^ \n\t\"'<>]+)+\.[a-zA-Z0-9]{2,10}(?:#[^ \n\t\"'<>]+)?)")),
    ("DOMAIN",      re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|io|dev|local|xyz|gov|edu)\b")),
    ("HEXSECRET",   re.compile(r"\b[a-fA-F0-9]{32,}\b")),
    ("USERNAME",    re.compile(r"\buser(?:[:=]\s*|\s+)([A-Za-z0-9._-]+)\b", re.IGNORECASE)),
    ("IDNUM",       re.compile(r"\bID(?:[:=]\s*|\s+)([0-9]{3,})\b", re.IGNORECASE)),
]

# Date/time patterns to explicitly protect — these are never anonymized.
DATE_TIME_PATTERNS = [
    # ISO 8601: 2025-03-12, 2025-03-12T14:30:00Z, 2025-03-12T14:30:00+02:00
    re.compile(r"\b\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])(?:[T ]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)?\b"),
    # dd/mm/yyyy or mm/dd/yyyy or dd-mm-yyyy etc.
    re.compile(r"\b(?:0?[1-9]|[12]\d|3[01])[/\-.](?:0?[1-9]|1[0-2])[/\-.](?:\d{2}|\d{4})\b"),
    # yyyy/mm/dd
    re.compile(r"\b\d{4}[/\-.](0?[1-9]|1[0-2])[/\-.](0?[1-9]|[12]\d|3[01])\b"),
    # Time only: HH:MM, HH:MM:SS, HH:MM:SS.mmm
    re.compile(r"\b(?:[01]\d|2[0-3]):\d{2}(?::\d{2}(?:\.\d+)?)?\b"),
    # Month name dates: 12 January 2025, January 12 2025, Jan 12 2025, 12 Jan 2025
    re.compile(
        r"\b(?:\d{1,2}\s+)?(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|"
        r"Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)"
        r"(?:\s+\d{1,2})?(?:,?\s+\d{4})?\b",
        re.IGNORECASE,
    ),
]
