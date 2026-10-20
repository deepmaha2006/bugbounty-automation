"""
Hermetic tests for utils/oob_tracker.py.
"""

import sys
import os
import time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest.mock import patch


# ---------------------------------------------------------------------------
# Helper to reload the module with a custom env var value
# ---------------------------------------------------------------------------

def _import_oob(oob_server_value=""):
    """Re-import oob_tracker with a specific HYDRAX_OOB_SERVER value."""
    import importlib
    with patch.dict(os.environ, {"HYDRAX_OOB_SERVER": oob_server_value}):
        import utils.oob_tracker as mod
        importlib.reload(mod)
        return mod


# ---------------------------------------------------------------------------
# Basic API
# ---------------------------------------------------------------------------

class TestOobConfigured:
    def test_returns_false_when_env_absent(self):
        mod = _import_oob("")
        assert mod.oob_configured() is False

    def test_returns_true_when_env_set(self):
        mod = _import_oob("interact.sh")
        assert mod.oob_configured() is True


class TestGenerateToken:
    def test_length(self):
        from utils.oob_tracker import generate_token
        tok = generate_token()
        assert len(tok) == 16

    def test_hex_chars_only(self):
        from utils.oob_tracker import generate_token
        tok = generate_token()
        int(tok, 16)  # raises ValueError if not hex

    def test_unique(self):
        from utils.oob_tracker import generate_token
        tokens = {generate_token() for _ in range(100)}
        assert len(tokens) == 100


class TestOobUrl:
    def test_returns_none_when_no_server(self):
        mod = _import_oob("")
        assert mod.oob_url("abc123") is None

    def test_returns_url_with_token_subdomain(self):
        mod = _import_oob("interact.sh")
        url = mod.oob_url("deadbeef01234567")
        assert url == "http://deadbeef01234567.interact.sh"

    def test_trailing_slash_stripped(self):
        mod = _import_oob("interact.sh/")
        url = mod.oob_url("abc")
        assert url is not None
        assert not url.endswith("//")


# ---------------------------------------------------------------------------
# Token registration and callback
# ---------------------------------------------------------------------------

class TestCallbackMechanism:
    def test_register_then_check_false(self):
        from utils.oob_tracker import register_token, check_callback, _callbacks
        token = "testtoken00001"
        register_token(token)
        assert check_callback(token) is False

    def test_mark_then_check_true(self):
        from utils.oob_tracker import (
            register_token, mark_callback_received, check_callback
        )
        token = "testtoken00002"
        register_token(token)
        mark_callback_received(token)
        assert check_callback(token) is True

    def test_check_unknown_token_returns_false(self):
        from utils.oob_tracker import check_callback
        assert check_callback("nonexistent_token_xyz") is False


# ---------------------------------------------------------------------------
# wait_for_callback
# ---------------------------------------------------------------------------

class TestWaitForCallback:
    def test_returns_false_when_no_callback_arrives(self):
        from utils.oob_tracker import register_token, wait_for_callback
        token = "timeout_test_001"
        register_token(token)
        result = wait_for_callback(token, timeout=1)
        assert result is False

    def test_returns_true_when_callback_arrives_quickly(self):
        import threading
        from utils.oob_tracker import (
            register_token, mark_callback_received, wait_for_callback
        )
        token = "fast_callback_001"
        register_token(token)

        def _trigger():
            time.sleep(0.2)
            mark_callback_received(token)

        t = threading.Thread(target=_trigger, daemon=True)
        t.start()
        result = wait_for_callback(token, timeout=3)
        t.join(timeout=1)
        assert result is True


# ---------------------------------------------------------------------------
# oob_skipped_note
# ---------------------------------------------------------------------------

class TestOobSkippedNote:
    def test_contains_oob_server_instruction(self):
        from utils.oob_tracker import oob_skipped_note
        note = oob_skipped_note()
        assert "HYDRAX_OOB_SERVER" in note
        assert "Interactsh" in note or "interactsh" in note
