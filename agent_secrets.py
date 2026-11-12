#!/usr/bin/env python3
"""agent-secrets: find and scrub secrets that AI coding agents leave behind.

Claude Code's "don't ask again" turns the exact command you approved into a
permanent allow-rule in .claude/settings.local.json, including any password
typed inline (PGPASSWORD=..., sshpass -p ..., mysql -p...). MCP configs and
session transcripts leak the same way. Generic scanners miss many of these
because they look for token formats, not agent file formats.

Commands:
    scan <path>...   report inline secrets (redacted), exit 1 if any
    scrub <path>     move secrets from agent configs into .env.local
    history <path>   scan every line ever added in git history

Standard library only. No network access.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import math
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field

__version__ = "1.0.0"

BACKUP_DIR = ".agent-secrets-backup"
IGNORE_FILE = ".agent-secrets-ignore"
ENV_LOCAL = ".env.local"
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", BACKUP_DIR}
REQUIRED_GITIGNORE = [".env.local", ".claude/settings.local.json", ".agent-secrets-backup/"]

MAX_TEXT_BYTES = 2 * 1024 * 1024          # generic fallback files
MAX_PRIORITY_BYTES = 50 * 1024 * 1024     # agent configs and transcripts

SETTINGS_NAMES = {"settings.json", "settings.local.json"}
MCP_NAMES = {"mcp.json", ".mcp.json", "claude_desktop_config.json"}
TRANSCRIPT_EXTS = {".jsonl", ".txt", ".log"}
# In source code an unquoted right-hand side is an expression, not a literal.
CODE_EXTS = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go", ".rb",
             ".java", ".kt", ".rs", ".c", ".h", ".cc", ".cpp", ".hpp", ".cs",
             ".php", ".swift", ".scala", ".lua", ".dart"}
CONFIG_TYPES = {"settings", "mcp", "env"}


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------

@dataclass
class Hit:
    """A detected secret inside one string. Offsets are relative to that string."""
    kind: str
    start: int
    end: int
    value: str = field(repr=False)
    var: str = ""


def redact(value: str) -> str:
    """First 3 chars + *** + last 2 chars; never the full value."""
    return value[:3] + "***" + value[-2:] if len(value) >= 8 else "***"


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


PLACEHOLDER_EXACT = {
    "changeme", "change-me", "change_me", "replaceme", "replace-me", "example",
    "xxx", "todo", "tbd", "none", "null", "nil", "true", "false", "undefined",
    "redacted", "password", "passwd", "secret", "token", "placeholder",
    "dummy", "sample", "pass", "default",
}
PLACEHOLDER_MARKERS = ("example", "placeholder", "changeme", "change-me",
                       "replace-me", "replace_me", "redacted", "xxxx", "***", "...")


def is_placeholder(value: str) -> bool:
    """True for env references, templates and obvious dummy values."""
    s = value.strip().strip("\"'")
    if not s:
        return True
    if s.startswith("$") or "${" in s or "{{" in s:          # $VAR ${VAR} ${{ x }}
        return True
    if s.startswith("{env:") or re.fullmatch(r"%[A-Za-z_][A-Za-z0-9_]*%", s):
        return True
    if s.startswith("<") and s.endswith(">"):
        return True
    low = s.lower()
    if low in PLACEHOLDER_EXACT or low.startswith("your"):
        return True
    if any(marker in low for marker in PLACEHOLDER_MARKERS):
        return True
    return len(set(low)) == 1                                    # xxxxxxxx, ********


_B = r"(?<![A-Za-z0-9_\-])"
PREFIX_DETECTORS = [
    ("anthropic-key", re.compile(_B + r"sk-ant-[A-Za-z0-9_\-]{16,}"), "ANTHROPIC_API_KEY"),
    ("openai-key", re.compile(_B + r"sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{16,}"), "OPENAI_API_KEY"),
    ("github-token", re.compile(_B + r"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"), "GITHUB_TOKEN"),
    ("aws-key", re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])"), "AWS_ACCESS_KEY_ID"),
    ("slack-token", re.compile(_B + r"xox[bpas]-[A-Za-z0-9\-]{10,}"), "SLACK_TOKEN"),
    ("google-api-key", re.compile(_B + r"AIza[0-9A-Za-z_\-]{20,}"), "GOOGLE_API_KEY"),
    ("gitlab-token", re.compile(_B + r"glpat-[A-Za-z0-9_\-]{16,}"), "GITLAB_TOKEN"),
]

# Characters allowed in an unquoted shell word we treat as a value.
_NOQ = r"[^\s\"'`;&|()\\]"
_VAL = r"(?:\\?\"([^\"\\]*)\\?\"|'([^'\\]*)'|(" + _NOQ + r"+))"

AUTH_HEADER_RE = re.compile(
    r"(?i)\bauthorization\\?[\"']?\s*[:=]\s*\\?[\"']?\s*(bearer|basic)\s+([A-Za-z0-9._~+/=\-]{12,})")
DB_URL_RE = re.compile(
    r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver)"
    r"://[^\s:/@'\"`]+:([^\s@'\"`/]+)@")
def _assign_re(var: str):
    return re.compile(r"(?<![A-Za-z0-9_])" + var + "=" + _VAL)


ENV_ASSIGN_DETECTORS = [
    ("pgpassword", _assign_re("PGPASSWORD"), "PGPASSWORD"),
    ("mysql-password", _assign_re("MYSQL_PWD"), "DB_PASSWORD"),
    ("sshpass", _assign_re("SSHPASS"), "DB_PASSWORD"),
]
SSHPASS_RE = re.compile(r"\bsshpass(?:\s+-[a-oq-zA-Z]\S*)*\s+-p\s*" + _VAL)
MYSQL_CMD_RE = re.compile(_B + r"(?:mysql|mysqldump|mysqladmin|mariadb)(?![A-Za-z0-9_\-])([^\n|;&]*)")
MYSQL_P_RE = re.compile(r"(?<!\S)-p" + _VAL)
# `mysql -p dbname` prompts for a password, so a spaced value only counts when
# another argument follows it.
MYSQL_P_SPACED_RE = re.compile(
    r"(?<!\S)-p\s+(?:\"([^\"\\]*)\"|'([^'\\]*)'|([^\s\"'`;&|()\\\-]" + _NOQ + r"*))(?=\s+[^\s)\"'`\\])")
FLAG_RE = re.compile(
    r"(?<![A-Za-z0-9_\-])--(password|passwd|api-key|apikey|api_key|token|auth-token|"
    r"access-token|secret|client-secret)(?:=|\s+)" + _VAL)
NAMED_RE = re.compile(
    r"(?<![A-Za-z0-9_$])(?P<name>[A-Za-z_][A-Za-z0-9_.\-]*)\\?[\"']?\s*(?P<op>:=|=(?![=>~])|:)\s*"
    r"(?:(?P<q>\\?[\"'])(?P<qv>.*?)(?P=q)|(?P<uv>[^\s,;}\])\"'`\\]+))")

SECRET_WORDS = {"token", "secret", "password", "passwd", "pwd", "auth", "oauth",
                "apikey", "passphrase", "credential", "credentials", "privatekey",
                "secretkey", "accesskey"}
SECRET_SUFFIXES = ("token", "secret", "password", "passwd", "pwd", "apikey")
# A name ending in one of these describes a secret (where it lives, how long
# it is) rather than holding one: PASSWORD_FILE, token_url, max_tokens.
NON_SECRET_LAST = {
    "file", "path", "url", "uri", "endpoint", "name", "id", "type", "length", "len",
    "count", "limit", "ttl", "expiry", "expires", "expiration", "header", "field",
    "env", "var", "dir", "prompt", "hint", "policy", "label", "mode", "method",
    "provider", "strategy", "scheme", "enabled", "required", "timeout", "kind",
    "format", "location", "cmd", "command", "helper", "prefix", "regex", "pattern",
    "size", "version", "max", "min", "rotation", "age", "hash", "store", "manager",
}


def name_segments(name: str) -> list:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return [s for s in re.split(r"[_.\-\s]+", spaced.lower()) if s]


def name_strength(name: str):
    """'strong' for clearly secret names, 'weak' for *_key style names, else None."""
    segs = name_segments(name or "")
    if not segs or name.upper() in ("PWD", "OLDPWD") or segs[-1] in NON_SECRET_LAST:
        return None
    for seg in segs:
        if seg in SECRET_WORDS or seg.endswith(SECRET_SUFFIXES):
            return "strong"
    if len(segs) >= 2 and segs[-1] == "key":
        return "weak"
    return None


def env_var_name(name: str) -> str:
    var = re.sub(r"[^A-Za-z0-9_]", "_", name).upper().strip("_") or "SECRET"
    return "_" + var if var[0].isdigit() else var


def is_high_entropy(value: str) -> bool:
    if len(value) < 24 or not re.fullmatch(r"[A-Za-z0-9+/=_\-]+", value):
        return False
    mixed = (re.search(r"[a-z]", value) and re.search(r"[A-Z]", value)
             and re.search(r"[0-9]", value))
    hexy = re.fullmatch(r"[0-9a-fA-F]+", value) and re.search(r"[0-9]", value)
    return bool(mixed or hexy) and shannon_entropy(value) >= 3.5


def named_kind(value: str, strength: str, structured: bool):
    """Decide whether a value assigned to a secret-named variable is a secret."""
    if is_placeholder(value):
        return None
    if is_high_entropy(value):
        return "high-entropy-secret"
    if len(value) < 8 or value.lower() in PLACEHOLDER_EXACT:
        return None
    if re.match(r"^[a-z][a-z0-9+.\-]*://", value.lower()):            # plain URL
        return None
    if value.startswith(("/", "~/", "./", "../")) or re.match(r"^[A-Za-z]:\\", value):
        return None
    if re.fullmatch(r"[A-Za-z_]+(?:\.[A-Za-z_]+)+", value):            # dotted.identifier
        return None
    has_digit = any(c.isdigit() for c in value)
    if strength == "weak" and not (has_digit and any(c.isalpha() for c in value)):
        return None
    if not structured:
        # Free text: demand something password-like, reject prose and names.
        if any(c.isspace() for c in value) or value.isdigit():
            return None
        if re.fullmatch(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+", value):       # ENV_VAR_NAME
            return None
        if any(c in value for c in "()[]{}<>"):
            return None
        if not (has_digit or any(c in value for c in "!@#%^&*+=?~")):
            return None
    return "named-secret"


def _group_span(m, *groups):
    for g in groups:
        if m.group(g) is not None:
            return m.start(g), m.end(g)
    return None


def detect_text(text: str, structured: bool = False, code: bool = False) -> list:
    """Run every detector over one line or string. Returns non-overlapping hits."""
    hits: list = []

    def add(kind, span, var, min_len=3):
        if span is None:
            return
        start, end = span
        value = text[start:end]
        # Whitespace inside an inline value almost always means we matched a
        # code fragment ("PGPASSWORD=" + pw + " psql"), not a password.
        if len(value) < min_len or is_placeholder(value) or any(c.isspace() for c in value):
            return
        if any(start < h.end and h.start < end for h in hits):
            return
        hits.append(Hit(kind, start, end, value, var))

    for kind, rx, var in PREFIX_DETECTORS:
        for m in rx.finditer(text):
            token = m.group(0)
            if kind in ("openai-key", "anthropic-key") and not re.search(r"[0-9]", token):
                continue
            add(kind, m.span(), var)
    for m in AUTH_HEADER_RE.finditer(text):
        scheme = m.group(1).lower()
        if scheme == "bearer" and len(m.group(2)) >= 16:
            add("bearer-token", m.span(2), "API_TOKEN")
        elif scheme == "basic":
            add("basic-auth", m.span(2), "BASIC_AUTH")
    for m in DB_URL_RE.finditer(text):
        add("db-url-password", m.span(1), "DB_PASSWORD")
    for kind, rx, var in ENV_ASSIGN_DETECTORS:
        for m in rx.finditer(text):
            add(kind, _group_span(m, 1, 2, 3), var)
    for m in SSHPASS_RE.finditer(text):
        add("sshpass", _group_span(m, 1, 2, 3), "DB_PASSWORD")
    for cmd in MYSQL_CMD_RE.finditer(text):
        for rx in (MYSQL_P_RE, MYSQL_P_SPACED_RE):
            for m in rx.finditer(text, cmd.start(1), cmd.end(1)):
                add("mysql-password", _group_span(m, 1, 2, 3), "DB_PASSWORD")
    for m in FLAG_RE.finditer(text):
        span = _group_span(m, 2, 3, 4)
        if span and not text[span[0]:span[1]].startswith("-"):
            flag = m.group(1).replace("-", "_")
            var = {"passwd": "PASSWORD", "apikey": "API_KEY"}.get(flag, flag.upper())
            add("cli-flag-secret", span, var)
    pos = 0
    while True:
        m = NAMED_RE.search(text, pos)
        if not m:
            break
        strength = name_strength(m.group("name"))
        if not strength:
            # Resume right after the operator so a quoted value such as a
            # transcript message ("content": "... DB_PASSWORD=...") is still searched.
            pos = m.end("op")
            continue
        pos = m.end()
        if m.group("qv") is not None:
            group = "qv"
        elif code:
            continue                       # unquoted RHS in code is an expression
        else:
            group = "uv"
        kind = named_kind(m.group(group), strength, structured)
        if kind:
            add(kind, m.span(group), env_var_name(m.group("name")), min_len=8)
    hits.sort(key=lambda h: h.start)
    return hits


def detect_kv(name: str, value: str) -> list:
    """Detect secrets in a value whose key is known (env block, .env line)."""
    hits = detect_text(value)
    if hits:
        for h in hits:
            if h.start == 0 and h.end == len(value):
                h.var = env_var_name(name)
        return hits
    if "auth" in (name or "").lower():
        m = re.fullmatch(r"(?i)(bearer|token|basic)\s+(\S{16,})", value.strip())
        if m and not is_placeholder(m.group(2)):
            kind = "basic-auth" if m.group(1).lower() == "basic" else "bearer-token"
            off = value.index(m.group(2))
            return [Hit(kind, off, off + len(m.group(2)), m.group(2), env_var_name(name))]
    strength = name_strength(name)
    if strength:
        kind = named_kind(value, strength, structured=True)
        if kind:
            return [Hit(kind, 0, len(value), value, env_var_name(name))]
    return []


# ---------------------------------------------------------------------------
# Scanners
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    file: str
    line: int
    kind: str
    value: str = field(repr=False)
    var: str = ""
    json_path: tuple = None
    start: int = 0
    end: int = 0
    env_key: str = None
    env_value: str = field(default=None, repr=False)

    @property
    def preview(self) -> str:
        return redact(self.value)

    def to_dict(self) -> dict:
        return {"file": self.file, "line": self.line, "kind": self.kind, "preview": self.preview}


GENERIC_KINDS = {"named-secret", "high-entropy-secret"}
CONTEXT_KINDS = {"mcp-env": "mcp-env-secret", "allow": "allow-rule-secret", "env": "env-secret"}


def classify(rel: str) -> str:
    parts = rel.replace("\\", "/").split("/")
    name = parts[-1]
    if name in SETTINGS_NAMES or (".claude" in parts[:-1] and name.startswith("settings")
                                  and name.endswith(".json")):
        return "settings"
    if name in MCP_NAMES:
        return "mcp"
    if name == ".env" or name.startswith(".env."):
        return "env"
    ext = os.path.splitext(name)[1].lower()
    if ext == ".json":
        return "json"
    if ext in TRANSCRIPT_EXTS:
        return "transcript"
    return "text"


def load_ignore(root: str) -> list:
    path = os.path.join(root, IGNORE_FILE)
    if not os.path.isfile(path):
        return []
    with open(path, encoding="utf-8", errors="replace") as fh:
        return [ln.strip() for ln in fh if ln.strip() and not ln.strip().startswith("#")]


def is_ignored(rel: str, patterns: list) -> bool:
    """gitignore-flavoured fnmatch: 'dir/**', 'dir/', '*.log', '/anchored'."""
    cand = rel.replace("\\", "/").strip("/")
    if cand.startswith("./"):
        cand = cand[2:]
    for pat in patterns:
        anchored = pat.startswith("/")
        p = pat.lstrip("/")
        if p.endswith("/"):
            p += "**"
        if fnmatch.fnmatchcase(cand, p) or fnmatch.fnmatchcase(cand + "/", p):
            return True
        if p.endswith("/**") and (cand == p[:-3] or cand.startswith(p[:-3] + "/")):
            return True
        if not anchored and "/" not in p and any(fnmatch.fnmatchcase(part, p) for part in cand.split("/")):
            return True
    return False


def iter_files(target: str, patterns: list):
    """Yield (abs_path, rel_path) for regular files, skipping vendored/ignored dirs."""
    for root, dirs, files in os.walk(target):
        rel_root = os.path.relpath(root, target)
        rel_root = "" if rel_root == "." else rel_root.replace(os.sep, "/") + "/"
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS
                         and not os.path.islink(os.path.join(root, d))
                         and not is_ignored(rel_root + d + "/", patterns))
        for name in sorted(files):
            abs_path = os.path.join(root, name)
            rel = rel_root + name
            if os.path.islink(abs_path) or not os.path.isfile(abs_path) or is_ignored(rel, patterns):
                continue
            yield abs_path, rel


def read_text(abs_path: str, ftype: str):
    """Return decoded text, or None for binary / oversized files."""
    limit = MAX_TEXT_BYTES if ftype in ("text", "json") else MAX_PRIORITY_BYTES
    try:
        if os.path.getsize(abs_path) > limit:
            return None
        with open(abs_path, "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    if b"\0" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


def scan_lines(text: str, rel: str, structured: bool = False, code: bool = False) -> list:
    out = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for h in detect_text(line, structured=structured, code=code):
            out.append(Finding(rel, lineno, h.kind, h.value, h.var))
    return out


def parse_env_line(line: str):
    m = re.match(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.\-]*)\s*=\s*(.*)$", line)
    if not m:
        return None
    key, raw = m.group(1), m.group(2).strip()
    if raw[:1] in ("'", '"'):
        q = raw[0]
        end = raw.find(q, 1)
        while q == '"' and end > 0 and raw[end - 1] == "\\":
            end = raw.find(q, end + 1)
        if end > 0:
            val = raw[1:end]
            return key, (val.replace('\\"', '"').replace("\\\\", "\\") if q == '"' else val)
    return key, re.split(r"\s+#", raw, 1)[0].strip()


def scan_env(text: str, rel: str) -> list:
    out = []
    for lineno, line in enumerate(text.splitlines(), 1):
        kv = parse_env_line(line)
        if kv is None:
            for h in detect_text(line):        # comments, odd lines
                out.append(Finding(rel, lineno, h.kind, h.value, h.var))
            continue
        key, value = kv
        for h in detect_kv(key, value):
            kind = CONTEXT_KINDS["env"] if h.kind in GENERIC_KINDS else h.kind
            out.append(Finding(rel, lineno, kind, h.value, h.var, env_key=key, env_value=value))
    return out


def _json_context(path: tuple) -> str:
    keys = [p for p in path if isinstance(p, str)]
    if "mcpServers" in keys:
        rest = keys[keys.index("mcpServers"):]
        return "mcp-env" if ("env" in rest or "headers" in rest) else "mcp"
    if "permissions" in keys:
        return "allow"
    if "env" in keys:
        return "env"
    return "json"


def iter_json_strings(obj, path=()):
    """Yield (path, key_name_or_None, string) for every string in a JSON tree."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str):
                yield path + (k,), k, v
            else:
                yield from iter_json_strings(v, path + (k,))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            if isinstance(v, str):
                yield path + (i,), None, v
                # MCP-style args: ["--api-key", "<value>"]
                nxt = obj[i + 1] if i + 1 < len(obj) else None
                if v.startswith("-") and isinstance(nxt, str) and name_strength(v.lstrip("-")):
                    yield path + (i + 1,), v.lstrip("-"), nxt
            else:
                yield from iter_json_strings(v, path + (i,))


def _line_of(text: str, value: str, cursors: dict) -> int:
    needle = json.dumps(value)[1:-1]
    pos = text.find(needle, cursors.get(needle, 0))
    if pos < 0:
        pos = text.find(needle)
    if pos < 0:
        needle = json.dumps(value, ensure_ascii=False)[1:-1]
        pos = text.find(needle)
    if pos < 0:
        return 1
    cursors[needle] = pos + 1
    return text.count("\n", 0, pos) + 1


def scan_json_config(text: str, rel: str) -> list:
    """Structured pass over a settings/MCP JSON file, plus a raw line pass."""
    try:
        data = json.loads(text)
    except ValueError:
        return scan_lines(text, rel, structured=True)
    out, seen, cursors = [], set(), {}
    for path, key, value in iter_json_strings(data):
        hits = detect_kv(key, value) if key is not None else detect_text(value)
        ctx = _json_context(path)
        for h in hits:
            if (path, h.start, h.end) in seen:
                continue
            seen.add((path, h.start, h.end))
            kind = CONTEXT_KINDS.get(ctx, h.kind) if h.kind in GENERIC_KINDS else h.kind
            out.append(Finding(rel, _line_of(text, h.value, cursors), kind, h.value, h.var,
                               json_path=path, start=h.start, end=h.end))
    known = {(f.line, f.value) for f in out}
    for f in scan_lines(text, rel, structured=True):
        if (f.line, f.value) not in known and not any(f.value in k[1] or k[1] in f.value
                                                       for k in known if k[0] == f.line):
            out.append(f)
    return out


def scan_file(abs_path: str, rel: str):
    """Return (ftype, findings) for one file."""
    ftype = classify(rel)
    text = read_text(abs_path, ftype)
    if text is None:
        return ftype, []
    if ftype == "json" and '"mcpServers"' in text:
        ftype = "mcp"
    if ftype in ("settings", "mcp"):
        return ftype, scan_json_config(text, rel)
    if ftype == "env":
        return ftype, scan_env(text, rel)
    code = os.path.splitext(rel)[1].lower() in CODE_EXTS
    return ftype, scan_lines(text, rel, structured=False, code=code)


def scan_paths(paths: list) -> list:
    """Scan directories (recursively) and/or individual files."""
    findings = []
    cwd_patterns = None
    for path in paths:
        if os.path.isdir(path):
            for abs_path, rel in iter_files(path, load_ignore(path)):
                findings.extend(scan_file(abs_path, rel)[1])
        else:
            if cwd_patterns is None:
                cwd_patterns = load_ignore(os.getcwd())
            rel = os.path.relpath(path).replace(os.sep, "/")
            parts = set(rel.split("/"))
            if parts & SKIP_DIRS or is_ignored(rel, cwd_patterns):
                continue
            findings.extend(scan_file(path, path)[1])
    findings.sort(key=lambda f: (f.file, f.line))
    return findings


# ---------------------------------------------------------------------------
# Scrubber
# ---------------------------------------------------------------------------

def read_env_file(path: str) -> dict:
    env = {}
    if os.path.isfile(path):
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                kv = parse_env_line(line.rstrip("\n"))
                if kv and not line.lstrip().startswith("#"):
                    env.setdefault(kv[0], kv[1])
    return env


def quote_env(value: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9_\-.:/@+=%,~^]*", value):
        return value
    if "'" not in value:
        return "'" + value + "'"
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _json_get(obj, path):
    for p in path:
        obj = obj[p]
    return obj


def _json_set(obj, path, value):
    _json_get(obj, path[:-1])[path[-1]] = value


def backup(target: str, abs_path: str, rel: str) -> bool:
    dest = os.path.join(target, BACKUP_DIR, rel)
    if os.path.exists(dest):
        return False                      # keep the pristine first backup
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    shutil.copy2(abs_path, dest)
    return True


def ensure_gitignore(target: str, entries: list) -> list:
    path = os.path.join(target, ".gitignore")
    content = ""
    if os.path.isfile(path):
        with open(path, encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    have = {ln.strip().lstrip("/").rstrip("/") for ln in content.splitlines()}
    missing = []
    for entry in entries:
        if entry.lstrip("/").rstrip("/") not in have and entry not in missing:
            missing.append(entry)
    if missing:
        with open(path, "a", encoding="utf-8") as fh:
            if content and not content.endswith("\n"):
                fh.write("\n")
            if "# agent-secrets" not in content:
                fh.write("# agent-secrets\n")
            fh.write("".join(e + "\n" for e in missing))
    return missing


def scrub_path(target: str, out=print) -> dict:
    target = os.path.abspath(target)
    patterns = load_ignore(target)
    env_local = os.path.join(target, ENV_LOCAL)
    existing = read_env_file(env_local)
    pending: dict = {}           # var -> value to append to .env.local
    allocated: dict = {}         # value -> var

    def allocate(base: str, value: str) -> str:
        if value in allocated:
            return allocated[value]
        cand, n = base, 2
        while True:
            cur = existing.get(cand, pending.get(cand))
            if cur is None or cur == value:
                if cur is None:
                    pending[cand] = value
                allocated[value] = cand
                return cand
            cand, n = f"{base}_{n}", n + 1

    edits, manual, env_files, conflicts = [], [], [], []
    report_only = 0
    for abs_path, rel in iter_files(target, patterns):
        ftype, findings = scan_file(abs_path, rel)
        if not findings:
            continue
        if ftype in ("settings", "mcp"):
            spans: dict = {}
            for f in findings:
                if f.json_path is None:
                    manual.append(f)
                    continue
                var = allocate(f.var or env_var_name(f.kind), f.value)
                spans.setdefault(f.json_path, []).append((f.start, f.end, var, f.value))
            if spans:
                edits.append((abs_path, rel, spans))
        elif ftype == "env":
            if rel == ENV_LOCAL:
                continue                     # this is the protected store itself
            env_files.append((rel, findings))
            for f in findings:
                if not f.env_key:
                    manual.append(f)
                    continue
                cur = existing.get(f.env_key, pending.get(f.env_key))
                if cur is None:
                    pending[f.env_key] = f.env_value
                elif cur != f.env_value:
                    conflicts.append((rel, f.env_key))
        else:
            report_only += len(findings)

    # 1. Store values first so a crash never loses a secret.
    if pending:
        fresh = not os.path.exists(env_local)
        old = ""
        if not fresh:
            with open(env_local, encoding="utf-8", errors="replace") as fh:
                old = fh.read()
        fd = os.open(env_local, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            if old and not old.endswith("\n"):
                fh.write("\n")
            if fresh:
                fh.write("# Secrets moved here by agent-secrets. Never commit this file.\n")
            for key, value in pending.items():
                fh.write(f"{key}={quote_env(value)}\n")
    if os.path.exists(env_local):
        os.chmod(env_local, 0o600)

    # 2. Rewrite JSON configs (after backing them up).
    rewritten = []
    for abs_path, rel, spans in edits:
        with open(abs_path, encoding="utf-8") as fh:
            data = json.load(fh)
        previews = []
        for path, items in spans.items():
            s = _json_get(data, path)
            last = len(s) + 1
            for start, end, var, value in sorted(items, reverse=True):
                if end > last or s[start:end] != value:
                    continue                # overlapping or stale span
                s = s[:start] + "${" + var + "}" + s[end:]
                last = start
                previews.append((var, redact(value)))
            _json_set(data, path, s)
        backup(target, abs_path, rel)
        with open(abs_path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
        rewritten.append((rel, previews))

    # 3. Make sure the secret stores can never be committed.
    gi_entries = REQUIRED_GITIGNORE + [rel for rel, _ in env_files]
    added = ensure_gitignore(target, gi_entries)

    for rel, previews in rewritten:
        out(f"rewrote {rel}: {len(previews)} secret(s)")
        for var, prev in sorted(previews):
            out(f"  {prev} -> ${{{var}}}")
    for rel, findings in env_files:
        out(f"kept {rel} unchanged ({len(findings)} secret value(s)); copied to {ENV_LOCAL}, "
            f"ensured it is gitignored")
    for rel, key in conflicts:
        out(f"warning: {key} from {rel} differs from the value already in {ENV_LOCAL}; left as is")
    if pending:
        out(f"stored {len(pending)} value(s) in {ENV_LOCAL} (mode 600): {', '.join(sorted(pending))}")
    if added:
        out(f"added to .gitignore: {', '.join(added)}")
    if manual:
        out(f"{len(manual)} finding(s) could not be rewritten automatically; edit by hand:")
        for f in manual:
            out(f"  {f.file}:{f.line} {f.kind} {f.preview}")
    if report_only:
        out(f"report-only: {report_only} finding(s) in transcripts/other files were not modified "
            f"(run `scan` to list them); rotate those credentials")
    if not (rewritten or env_files or pending or added or manual or report_only):
        out("nothing to scrub: no inline secrets in agent config files")
    return {"rewritten": rewritten, "env_files": [r for r, _ in env_files], "stored": sorted(pending),
            "gitignore_added": added, "manual": len(manual), "report_only": report_only}


# ---------------------------------------------------------------------------
# Git history
# ---------------------------------------------------------------------------

class HistoryError(Exception):
    pass


def history_path(path: str) -> list:
    """Scan every added line in all git history. Read-only."""
    git = shutil.which("git")
    if not git:
        raise HistoryError("git executable not found on PATH")
    if not os.path.isdir(path):
        raise HistoryError(f"not a directory: {path}")
    top = subprocess.run([git, "-C", path, "rev-parse", "--show-toplevel"],
                         capture_output=True, text=True)
    if top.returncode != 0:
        raise HistoryError(f"not a git repository: {path}")
    patterns = load_ignore(top.stdout.strip())
    cmd = [git, "-C", path, "log", "-p", "--all", "--no-color", "-U0", "--no-ext-diff",
           "--no-textconv", "--date=short", "--format=%x00commit %H %h %ad"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    found: dict = {}
    short = date = file = None
    ftype, code, skip = "text", False, True
    in_header, lineno = False, 0
    for raw in proc.stdout:
        line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
        if line.startswith("\x00commit "):
            _, _full, short, date = (line[1:].split(" ", 3) + [""])[:4]
            file, in_header = None, False
        elif line.startswith("diff --git "):
            file, in_header = None, True
        elif in_header and line.startswith("+++ "):
            p = line[4:].strip('"')
            file = None if p == "/dev/null" else (p[2:] if p.startswith("b/") else p)
            if file:
                ftype = classify(file)
                code = os.path.splitext(file)[1].lower() in CODE_EXTS
                skip = bool(set(file.split("/")) & SKIP_DIRS) or is_ignored(file, patterns)
        elif line.startswith("@@"):
            m = re.match(r"@@ -\S+ \+(\d+)", line)
            lineno, in_header = (int(m.group(1)) if m else 0), False
        elif line.startswith("+") and not in_header and file:
            content = line[1:]
            if not skip:
                kv = parse_env_line(content) if ftype == "env" else None
                if kv:
                    hits = [Hit(CONTEXT_KINDS["env"] if h.kind in GENERIC_KINDS else h.kind,
                                h.start, h.end, h.value) for h in detect_kv(*kv)]
                else:
                    hits = detect_text(content, structured=ftype in CONFIG_TYPES, code=code)
                for h in hits:
                    ident = (file, h.kind, redact(h.value))
                    prev = found.get(ident)
                    # git log is newest-first: the last one seen introduced it.
                    found[ident] = {"commit": short, "date": date, "file": file, "line": lineno,
                                  "kind": h.kind, "preview": redact(h.value),
                                  "commits": (prev["commits"] + 1) if prev else 1}
            lineno += 1
    proc.wait()
    if proc.returncode != 0:
        err = proc.stderr.read().decode("utf-8", errors="replace").strip()
        if "does not have any commits" not in err:
            raise HistoryError(f"git log failed: {err.splitlines()[-1] if err else proc.returncode}")
    return sorted(found.values(), key=lambda r: (r["date"] or "", r["file"], r["line"]))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _cmd_scan(args) -> int:
    for p in args.paths:
        if not os.path.exists(p):
            print(f"agent-secrets: path not found: {p}", file=sys.stderr)
            return 2
    findings = scan_paths(args.paths)
    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    elif findings:
        for f in findings:
            print(f"{f.file}:{f.line}: {f.kind}: {f.preview}")
        files = len({f.file for f in findings})
        print(f"\n{len(findings)} finding(s) in {files} file(s). Values are redacted. "
              f"Move them to env vars (`scrub`) and rotate anything ever committed.")
    else:
        print("No inline secrets found.")
    return 1 if findings else 0


def _cmd_scrub(args) -> int:
    if not os.path.isdir(args.path):
        print(f"agent-secrets: not a directory: {args.path}", file=sys.stderr)
        return 2
    scrub_path(args.path)
    print("note: .env files are treated as the local secret store and are never blanked; "
          "transcripts are report-only.")
    return 0


def _cmd_history(args) -> int:
    try:
        rows = history_path(args.path)
    except HistoryError as exc:
        print(f"agent-secrets: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps([{k: r[k] for k in ("commit", "date", "file", "line", "kind", "preview")}
                          for r in rows], indent=2))
    elif rows:
        for r in rows:
            print(f"{r['commit']} {r['date']} {r['file']}:{r['line']}: {r['kind']}: {r['preview']}")
        print(f"\n{len(rows)} distinct secret(s) in git history. Rotate them: deleting the file "
              f"or rewriting history does not un-leak a pushed credential.")
    else:
        print("No secrets found in git history.")
    return 1 if rows else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="agent-secrets",
        description="Find and scrub secrets in AI agent configs (.claude settings, MCP configs, "
                    ".env files, transcripts). Exit codes: 0 clean, 1 findings, 2 usage error.")
    p.add_argument("--version", action="version", version=f"agent-secrets {__version__}")
    sub = p.add_subparsers(dest="command", metavar="{scan,scrub,history}")
    s = sub.add_parser("scan", help="report inline secrets (redacted)")
    s.add_argument("paths", nargs="+", metavar="path", help="directory or file(s) to scan")
    s.add_argument("--json", action="store_true", help="emit a JSON array of findings")
    s.set_defaults(func=_cmd_scan)
    s = sub.add_parser("scrub", help="move config secrets into .env.local and use ${VAR} refs")
    s.add_argument("path", help="project directory")
    s.set_defaults(func=_cmd_scrub)
    s = sub.add_parser("history", help="scan lines added anywhere in git history (read-only)")
    s.add_argument("path", help="git repository (or a subdirectory of one)")
    s.add_argument("--json", action="store_true", help="emit a JSON array of findings")
    s.set_defaults(func=_cmd_history)
    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help(sys.stderr)
        return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
