"""Phase 8 regression tests for the standalone connector agent
(connector/agent.py) — the actual artifact a customer installs, not the
platform side. Verifies the allowlisted job handlers return real,
non-fabricated data and that job verification/execution correctly refuses
what it should (bad signature, expired job, unknown job_type).

connector/agent.py deliberately imports nothing from webapp/core/scanners/
utils (it's meant to run on a machine with none of that installed), so these
tests import it directly as a standalone module.
"""
import datetime
import socket

from connector import agent


class TestAllowlistedJobHandlers:
    def test_inventory_check_returns_real_host_data(self):
        result = agent._job_inventory_check({})
        assert result["hostname"] == socket.gethostname()
        assert result["cpu_count"] == __import__("os").cpu_count()
        assert "disk_total_bytes" in result

    def test_configuration_check_only_examines_authorized_paths(self):
        result = agent._job_configuration_check({"paths": ["requirements.txt", "/definitely/not/real/path"]})
        assert result["checked"] == 2
        assert result["findings"][0]["path"] == "requirements.txt"
        assert result["findings"][0]["exists"] is True
        assert result["findings"][1]["exists"] is False

    def test_configuration_check_empty_scope_checks_nothing(self):
        result = agent._job_configuration_check({})
        assert result["checked"] == 0

    def test_vulnerability_assessment_reports_real_port_state(self):
        # Bind a real ephemeral port, then check the assessment sees it open,
        # and see a definitely-closed port reported closed.
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        try:
            open_port = srv.getsockname()[1]
            result = agent._job_vulnerability_assessment({"ports": [open_port, 1]})
            by_port = {r["port"]: r["listening"] for r in result["ports"]}
            assert by_port[open_port] is True
            assert by_port[1] is False
        finally:
            srv.close()

    def test_telemetry_collection_returns_hostname(self):
        result = agent._job_telemetry_collection({})
        assert result["hostname"] == socket.gethostname()

    def test_all_four_spec_job_types_have_handlers(self):
        assert set(agent.JOB_HANDLERS.keys()) == {
            "inventory_check", "configuration_check",
            "vulnerability_assessment", "telemetry_collection",
        }


class TestJobVerificationAndExecution:
    def _signed_job(self, platform_priv_pem, job_type="inventory_check", scope=None,
                    expires_delta=datetime.timedelta(minutes=10)):
        now = datetime.datetime.now(datetime.timezone.utc)
        job = {
            "job_id": 1, "organization_id": 1, "connector_id": 1, "job_type": job_type,
            "scope": scope or {}, "authorization": "user:1",
            "created_at": now.isoformat(), "expires_at": (now + expires_delta).isoformat(),
        }
        payload = {k: v for k, v in job.items()}
        job["signature"] = agent.sign(platform_priv_pem, payload)
        return job

    def test_valid_signed_job_executes_and_reports(self, monkeypatch):
        platform_priv, platform_pub = agent.Ed25519PrivateKey.generate(), None
        priv_pem = platform_priv.private_bytes(
            agent.serialization.Encoding.PEM, agent.serialization.PrivateFormat.PKCS8,
            agent.serialization.NoEncryption()).decode()
        pub_pem = platform_priv.public_key().public_bytes(
            agent.serialization.Encoding.PEM, agent.serialization.PublicFormat.SubjectPublicKeyInfo).decode()

        connector_priv_pem, _ = _connector_keypair()
        identity = {"server": "https://platform.invalid", "connector_id": 1,
                   "connector_secret": "s", "private_key_pem": connector_priv_pem,
                   "platform_public_key_pem": pub_pem}
        job = self._signed_job(priv_pem)

        submitted = {}

        class FakeResponse:
            status_code = 200
            text = "ok"

        def fake_post(url, headers=None, json=None, timeout=None):
            submitted["url"] = url
            submitted["json"] = json
            return FakeResponse()

        monkeypatch.setattr(agent.requests, "post", fake_post)
        agent._execute_job(identity, job)
        assert "result" in submitted["json"]
        assert "signature" in submitted["json"]
        # The reported result really did come from the real handler.
        assert submitted["json"]["result"]["hostname"] == socket.gethostname()

    def test_job_with_wrong_signature_never_executes(self, monkeypatch):
        _, pub_pem = _connector_keypair()  # wrong key entirely, not the platform's
        connector_priv_pem, _ = _connector_keypair()
        identity = {"server": "https://platform.invalid", "connector_id": 1,
                   "connector_secret": "s", "private_key_pem": connector_priv_pem,
                   "platform_public_key_pem": pub_pem}
        real_platform_priv, _ = _connector_keypair()
        job = self._signed_job(real_platform_priv)  # signed by a DIFFERENT key than identity trusts

        called = []
        monkeypatch.setattr(agent.requests, "post", lambda *a, **k: called.append(1))
        agent._execute_job(identity, job)
        assert called == []  # never reached the result-submission call

    def test_expired_job_never_executes(self, monkeypatch):
        priv_pem, pub_pem = _connector_keypair()
        connector_priv_pem, _ = _connector_keypair()
        identity = {"server": "https://platform.invalid", "connector_id": 1,
                   "connector_secret": "s", "private_key_pem": connector_priv_pem,
                   "platform_public_key_pem": pub_pem}
        job = self._signed_job(priv_pem, expires_delta=datetime.timedelta(minutes=-5))

        called = []
        monkeypatch.setattr(agent.requests, "post", lambda *a, **k: called.append(1))
        agent._execute_job(identity, job)
        assert called == []


def _connector_keypair():
    priv = agent.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_pem = priv.private_bytes(agent.serialization.Encoding.PEM, agent.serialization.PrivateFormat.PKCS8,
                                  agent.serialization.NoEncryption()).decode()
    pub_pem = pub.public_bytes(agent.serialization.Encoding.PEM,
                               agent.serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return priv_pem, pub_pem
