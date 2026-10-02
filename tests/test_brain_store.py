"""Stage 5 plumbing: persistent unresolved store + KB append/list helpers."""
import copy
import json
import shutil

import pytest

from webapp.services import remediation_kb as kbm
from webapp.services import remediation_service as rs


# --- Persistent unresolved store ----------------------------------------------
def test_signature_saved_once_with_count_and_timestamps():
    rs.record_unresolved({"type": "Flux Leak", "category": "physics"})
    rs.record_unresolved({"type": "flux leak", "category": "PHYSICS"})
    [item] = rs.list_unresolved()
    assert item["signature"] == "physics|flux leak" and item["count"] == 2
    assert item["first_seen"] <= item["last_seen"]


def test_store_is_persisted_to_disk():
    rs.record_unresolved({"type": "Flux Leak", "category": "physics"})
    on_disk = json.loads(rs.UNRESOLVED_PATH.read_text(encoding="utf-8"))
    assert "physics|flux leak" in on_disk
    assert not rs.UNRESOLVED_PATH.with_suffix(".json.tmp").exists()   # atomic write cleaned up


def test_draft_template_shape():
    rs.record_unresolved({"type": "Flux Leak", "category": "physics", "cwe": "cwe-999"})
    [item] = rs.list_unresolved()
    d = item["draft"]
    assert d["key"] == "physics.flux_leak"
    assert d["aliases"] == ["Flux Leak"] and d["category"] == "physics" and d["cwe"] == "CWE-999"
    assert set(kbm.REQUIRED_FIELDS) <= set(d)
    assert set(kbm.REMEDIATION_FIELDS) == set(d["remediation"])
    assert d["remediation"]["short_term_fix"] == "" and d["tags"] == ["draft"]
    assert kbm.validate_entry(d), "an unfinished draft must not pass validation"


def test_draft_key_for_uncategorized_finding():
    rs.record_unresolved({"type": "Something Odd!!"})
    assert rs.list_unresolved()[0]["draft"]["key"] == "unclassified.something_odd"


def test_list_is_sorted_by_frequency():
    for _ in range(3):
        rs.record_unresolved({"type": "Common"})
    rs.record_unresolved({"type": "Rare"})
    assert [i["type"] for i in rs.list_unresolved()] == ["Common", "Rare"]


def test_resolve_persists_unknown_findings():
    rs.resolve({"type": "Totally New Thing", "category": "misc"})
    assert rs.list_unresolved()[0]["signature"] == "misc|totally new thing"


def test_corrupt_store_is_tolerated():
    rs.UNRESOLVED_PATH.parent.mkdir(parents=True, exist_ok=True)
    rs.UNRESOLVED_PATH.write_text("{not json", encoding="utf-8")
    assert rs.list_unresolved() == []
    rs.record_unresolved({"type": "After Corruption"})
    assert rs.list_unresolved()[0]["type"] == "After Corruption"


def test_store_write_failure_never_breaks_resolve(monkeypatch):
    def boom(_data):
        raise OSError("disk full")
    monkeypatch.setattr(rs, "_save_store", boom)
    r = rs.resolve({"type": "Unmatched Thing"})
    assert r["unresolved"] is True and r["priority"] in rs.PRIORITY_ORDER


def test_dismiss_and_clear():
    rs.record_unresolved({"type": "A"})
    rs.record_unresolved({"type": "B"})
    assert rs.dismiss_unresolved("-|a") is True
    assert rs.dismiss_unresolved("-|a") is False
    assert [i["type"] for i in rs.list_unresolved()] == ["B"]
    rs.clear_unresolved()
    assert rs.list_unresolved() == []


# --- KB append helper (always on a temp copy, never the real KB) -------------
@pytest.fixture()
def kb_copy(tmp_path):
    dest = tmp_path / "remediation_kb.yaml"
    shutil.copyfile(kbm.KB_PATH, dest)
    yield dest
    kbm.get_kb.cache_clear()


def _new_entry(key="misc.flux_leak", alias="Flux Leak"):
    e = copy.deepcopy(kbm.load_kb()["entries"]["sqli.injection"])
    e.update(key=key, aliases=[alias], category=key.split(".")[0], cwe="CWE-20",
             tags=["test"])
    e["why_it_matters"] = 'Values with "quotes": colons, #hashes and a > sign survive.'
    return e


def test_append_entry_adds_a_loadable_entry_and_keeps_existing_text(kb_copy):
    before = kb_copy.read_text(encoding="utf-8")
    kbm.append_entry(_new_entry(), path=kb_copy)
    after = kb_copy.read_text(encoding="utf-8")
    assert after.startswith(before)                      # comments + entries untouched
    kb = kbm.load_kb(kb_copy)
    assert kb["by_alias"]["flux leak"] == "misc.flux_leak"
    assert kb["entries"]["misc.flux_leak"]["why_it_matters"] == _new_entry()["why_it_matters"]
    assert len(kb["entries"]) == len(kbm.load_kb()["entries"]) + 1


@pytest.mark.parametrize("mutate,match", [
    (lambda e: e.pop("verification"), "missing 'verification'"),
    (lambda e: e.update(key="sqli.injection"), "duplicate key"),
    (lambda e: e.update(aliases=["Stored XSS"]), "already used"),
])
def test_append_entry_rejects_and_leaves_file_unchanged(kb_copy, mutate, match):
    before = kb_copy.read_text(encoding="utf-8")
    e = _new_entry()
    mutate(e)
    with pytest.raises(kbm.KBValidationError, match=match):
        kbm.append_entry(e, path=kb_copy)
    assert kb_copy.read_text(encoding="utf-8") == before


def test_unfinished_draft_cannot_be_appended(kb_copy):
    before = kb_copy.read_text(encoding="utf-8")
    with pytest.raises(kbm.KBValidationError):
        kbm.append_entry(rs.draft_entry("Flux Leak", "misc"), path=kb_copy)
    assert kb_copy.read_text(encoding="utf-8") == before


def test_append_rolls_back_if_post_write_load_fails(kb_copy, monkeypatch):
    before = kb_copy.read_text(encoding="utf-8")
    real_load = kbm.load_kb

    def failing_load(path=kbm.KB_PATH):
        if path == kb_copy:
            raise kbm.KBValidationError("simulated post-write failure")
        return real_load(path)
    monkeypatch.setattr(kbm, "load_kb", failing_load)
    with pytest.raises(kbm.KBValidationError, match="simulated"):
        kbm.append_entry(_new_entry(), path=kb_copy)
    assert kb_copy.read_text(encoding="utf-8") == before


def test_add_kb_entry_dismisses_covered_signatures(kb_copy):
    rs.record_unresolved({"type": "Flux Leak", "category": "misc"})
    rs.record_unresolved({"type": "Unrelated", "category": "misc"})
    out = rs.add_kb_entry(_new_entry(), path=kb_copy)
    assert out == {"key": "misc.flux_leak", "dismissed": ["misc|flux leak"]}
    assert [i["type"] for i in rs.list_unresolved()] == ["Unrelated"]
    r = rs.resolve({"type": "Flux Leak"}, kb=kbm.load_kb(kb_copy))
    assert (r["key"], r["resolved_by"], r["unresolved"]) == ("misc.flux_leak", "alias", False)


def test_real_kb_file_is_never_touched_by_these_tests():
    # Sanity: every append test above used a temp copy.
    assert "misc.flux_leak" not in kbm.load_kb()["entries"]
