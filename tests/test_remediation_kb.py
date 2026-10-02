"""Schema tests for the remediation knowledge base (config/remediation_kb.yaml)."""
import copy

import pytest

from webapp.services import remediation_kb as kbm


@pytest.fixture(scope="module")
def kb():
    return kbm.load_kb()


def test_kb_file_loads_and_validates(kb):
    assert kb["schema_version"] == 1
    assert kb["entries"], "KB has no entries"


def test_exemplar_entries_present(kb):
    for key in ("sqli.injection", "sec_misconfig.missing_security_header",
                "recon.technology_fingerprint"):
        assert key in kb["entries"], key


def test_every_entry_has_full_schema(kb):
    for key, e in kb["entries"].items():
        assert kbm.validate_entry(e) == [], key
        for f in kbm.REMEDIATION_FIELDS:
            assert f in e["remediation"], (key, f)


def test_aliases_index_is_case_insensitive(kb):
    assert kb["by_alias"]["sql injection"] == "sqli.injection"
    assert kb["by_alias"]["missing security header"] == "sec_misconfig.missing_security_header"


def test_signal_entries_do_not_prescribe_code_fixes(kb):
    for key, e in kb["entries"].items():
        if e["kind"] == "signal":
            assert e["remediation"]["code_fix_examples"] == {}, key
            assert e["triage_priority"] in ("P3", "P4"), key


def _base_entry(kb):
    return copy.deepcopy(kb["entries"]["sqli.injection"])


@pytest.mark.parametrize("mutate,needle", [
    (lambda e: e.pop("cwe"), "missing 'cwe'"),
    (lambda e: e.update(cwe="89"), "cwe must look like"),
    (lambda e: e.update(kind="script"), "kind must be one of"),
    (lambda e: e.update(triage_priority="P9"), "triage_priority"),
    (lambda e: e.update(references=["http://insecure.example"]), "not an https URL"),
    (lambda e: e["remediation"].pop("short_term_fix"), "remediation missing"),
    (lambda e: e.update(key="Bad Key"), "key must look like"),
])
def test_validator_rejects_bad_entries(kb, mutate, needle):
    e = _base_entry(kb)
    mutate(e)
    errs = kbm.validate_entry(e)
    assert any(needle in x for x in errs), errs


def test_duplicate_alias_across_entries_is_rejected(kb):
    a = _base_entry(kb)
    b = _base_entry(kb)
    b["key"] = "sqli.other"
    with pytest.raises(kbm.KBValidationError, match="already used"):
        kbm.parse_kb({"entries": [a, b]})


def test_duplicate_key_is_rejected(kb):
    with pytest.raises(kbm.KBValidationError, match="duplicate key"):
        kbm.parse_kb({"entries": [_base_entry(kb), _base_entry(kb)]})
