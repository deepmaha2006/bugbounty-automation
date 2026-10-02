"""Remediation knowledge base loader + schema validation.

The KB is a data file (config/remediation_kb.yaml) — see its header for the
field-by-field schema. This module only loads and validates it and builds
lookup indexes; resolving a finding to an entry lives in remediation_service.
"""
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List

import yaml

KB_PATH = Path(__file__).resolve().parents[2] / "config" / "remediation_kb.yaml"

KINDS = {"vulnerability", "signal"}
PRIORITIES = {"P1", "P2", "P3", "P4"}
SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")
EXPLOITABILITY = ("High", "Medium", "Low")

REQUIRED_FIELDS = (
    "key", "kind", "aliases", "category", "cwe", "owasp", "severity_guidance",
    "exploitability", "business_impact", "why_it_matters", "detection_signal",
    "false_positive_check", "triage_priority", "remediation",
    "compensating_controls", "verification", "references", "tags",
)
REMEDIATION_FIELDS = (
    "immediate_mitigation", "short_term_fix", "long_term_hardening",
    "code_fix_examples", "config_examples",
)

_KEY_RE = re.compile(r"^[a-z0-9_]+\.[a-z0-9_]+$")
_CWE_RE = re.compile(r"^CWE-\d+$")
_OWASP_RE = re.compile(r"^A\d{2}:2021-")


class KBValidationError(ValueError):
    """Raised when the knowledge base file does not match the schema."""


DRAFT_MARKER = "DRAFT — review before use"


def _contains_marker(value: Any) -> bool:
    if isinstance(value, str):
        return DRAFT_MARKER in value
    if isinstance(value, dict):
        return any(_contains_marker(v) for v in value.values())
    if isinstance(value, (list, tuple)):
        return any(_contains_marker(v) for v in value)
    return False


def validate_entry(entry: Dict[str, Any]) -> List[str]:
    """Return a list of problems with one entry (empty list = valid)."""
    errs = []
    key = entry.get("key", "<missing key>")
    # Auto-drafted entries are pre-filled from the nearest existing entry, so
    # they can look complete; they must never be appended until an analyst
    # has reviewed every field and removed the draft marker and tag.
    if "draft" in [str(t).lower() for t in (entry.get("tags") or [])]:
        errs.append(f"{key}: still tagged 'draft' — review and remove the tag")
    if _contains_marker(entry):
        errs.append(f"{key}: still contains '{DRAFT_MARKER}' text — review and rewrite it")
    for f in REQUIRED_FIELDS:
        if f not in entry or entry[f] in (None, ""):
            errs.append(f"{key}: missing '{f}'")
    if errs:
        return errs

    if not _KEY_RE.match(str(entry["key"])):
        errs.append(f"{key}: key must look like '<category>.<slug>' (lowercase)")
    if entry["kind"] not in KINDS:
        errs.append(f"{key}: kind must be one of {sorted(KINDS)}")
    if not isinstance(entry["aliases"], list) or not entry["aliases"] \
            or not all(isinstance(a, str) and a.strip() for a in entry["aliases"]):
        errs.append(f"{key}: aliases must be a non-empty list of strings")
    if not _CWE_RE.match(str(entry["cwe"])):
        errs.append(f"{key}: cwe must look like 'CWE-123'")
    if not _OWASP_RE.match(str(entry["owasp"])):
        errs.append(f"{key}: owasp must look like 'A05:2021-...'")
    if not str(entry["severity_guidance"]).startswith(SEVERITIES):
        errs.append(f"{key}: severity_guidance must start with one of {SEVERITIES}")
    if not str(entry["exploitability"]).startswith(EXPLOITABILITY):
        errs.append(f"{key}: exploitability must start with one of {EXPLOITABILITY}")
    if entry["triage_priority"] not in PRIORITIES:
        errs.append(f"{key}: triage_priority must be one of {sorted(PRIORITIES)}")

    rem = entry["remediation"]
    if not isinstance(rem, dict):
        errs.append(f"{key}: remediation must be a mapping")
    else:
        for f in REMEDIATION_FIELDS:
            if f not in rem:
                errs.append(f"{key}: remediation missing '{f}'")
        for f in ("immediate_mitigation", "short_term_fix", "long_term_hardening"):
            if f in rem and not str(rem[f] or "").strip():
                errs.append(f"{key}: remediation.{f} is empty")
        for f in ("code_fix_examples", "config_examples"):
            if f in rem and not isinstance(rem[f], dict):
                errs.append(f"{key}: remediation.{f} must be a mapping (may be empty)")

    for f in ("compensating_controls", "references", "tags"):
        if not isinstance(entry[f], list) or not entry[f]:
            errs.append(f"{key}: {f} must be a non-empty list")
    if isinstance(entry["references"], list):
        for ref in entry["references"]:
            if not str(ref).startswith("https://"):
                errs.append(f"{key}: reference is not an https URL: {ref}")
    return errs


def parse_kb(data: Any) -> Dict[str, Any]:
    """Validate raw YAML data and build indexes. Raises KBValidationError."""
    if not isinstance(data, dict) or not isinstance(data.get("entries"), list):
        raise KBValidationError("KB must be a mapping with an 'entries' list")

    problems, by_key, by_alias = [], {}, {}
    for entry in data["entries"]:
        if not isinstance(entry, dict):
            problems.append(f"entry is not a mapping: {entry!r}")
            continue
        errs = validate_entry(entry)
        if errs:
            problems.extend(errs)
            continue
        key = entry["key"]
        if key in by_key:
            problems.append(f"{key}: duplicate key")
            continue
        by_key[key] = entry
        for alias in entry["aliases"]:
            norm = alias.strip().lower()
            if norm in by_alias and by_alias[norm] != key:
                problems.append(f"{key}: alias '{alias}' already used by {by_alias[norm]}")
            by_alias[norm] = key

    if problems:
        raise KBValidationError("Invalid remediation KB:\n  " + "\n  ".join(problems))

    by_category: Dict[str, List[str]] = {}
    by_cwe: Dict[str, List[str]] = {}
    for key, entry in by_key.items():
        by_category.setdefault(entry["category"], []).append(key)
        by_cwe.setdefault(entry["cwe"], []).append(key)

    return {
        "schema_version": data.get("schema_version", 1),
        "entries": by_key,
        "by_alias": by_alias,
        "by_category": by_category,
        "by_cwe": by_cwe,
    }


def load_kb(path: Path = KB_PATH) -> Dict[str, Any]:
    """Load + validate the KB file (uncached)."""
    with open(path, encoding="utf-8") as fh:
        return parse_kb(yaml.safe_load(fh))


@lru_cache(maxsize=1)
def get_kb() -> Dict[str, Any]:
    """Process-wide cached KB. Call get_kb.cache_clear() after editing the file."""
    return load_kb()


def _ordered(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Schema field order, so appended entries read like hand-written ones."""
    out = {f: entry[f] for f in REQUIRED_FIELDS if f in entry}
    out["remediation"] = {f: entry["remediation"][f] for f in REMEDIATION_FIELDS
                          if f in entry["remediation"]}
    out.update({k: v for k, v in entry.items() if k not in out})
    return out


def append_entry(entry: Dict[str, Any], path: Path = KB_PATH) -> Dict[str, Any]:
    """Validate one finished entry and append it to the KB file.

    Checked before writing: the entry's own schema, and duplicate keys/aliases
    against the whole existing KB. After writing, the full file is re-loaded;
    if that fails for any reason the original file is restored. Comments and
    formatting of existing entries are preserved (text append, not rewrite).
    Raises KBValidationError on any problem.
    """
    path = Path(path)
    errs = validate_entry(entry)
    if errs:
        raise KBValidationError("Entry rejected:\n  " + "\n  ".join(errs))

    original = path.read_text(encoding="utf-8")
    current = yaml.safe_load(original) or {}
    parse_kb({"entries": list(current.get("entries") or []) + [entry]})  # dup check

    dumped = yaml.safe_dump([_ordered(entry)], sort_keys=False, allow_unicode=True,
                            default_flow_style=False, width=88)
    block = "\n" + "".join("  " + line if line.strip() else line
                           for line in dumped.splitlines(keepends=True))
    if not original.endswith("\n"):
        block = "\n" + block
    try:
        with open(path, "a", encoding="utf-8", newline="\n") as fh:
            fh.write(block)
        load_kb(path)
    except Exception:
        path.write_text(original, encoding="utf-8", newline="\n")
        raise
    finally:
        get_kb.cache_clear()
    return entry
