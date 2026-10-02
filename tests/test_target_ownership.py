"""P2-5 regression tests — added_by_user_id is populated on target creation.

Targets created through the verification endpoints or system scan flow must
persist the authenticated user's database ID in the targets.added_by_user_id
column. Legacy targets that pre-date this column must be handled safely (NULL).

This is PURE persistence testing — ownership enforcement (P2-6) is a separate
item and NOT tested here.
"""
import webapp.db as db_module
from webapp.services.system_scan_service import start_system_scan


class TestDnsTxtTargetOwnership:
    def test_dns_txt_challenge_target_created_with_added_by_user_id(self, fake,
                                                                    client,
                                                                    admin_headers):
        url = "http://127.0.0.1:8001/dns-target"
        r = client.post("/api/verification/dns-txt/generate",
                        headers=admin_headers,
                        data={"target_url": url})
        assert r.status_code == 200, r.text
        target_id = r.json()["target_id"]
        target = fake.get_target(target_id)
        assert target is not None
        assert target["added_by_user_id"] is not None
        # The fixture makes the first registered user the admin (id=1)
        assert target["added_by_user_id"] == 1

    def test_dns_txt_challenge_target_existing_target_preserves_original_owner(self,
                                                                                fake,
                                                                                client,
                                                              admin_headers):
        # Create a target as a different user first (simulate legacy state)
        tid = fake.add_target("http://127.0.0.1:8002/existing",
                              verification_method="dns_txt",
                              added_by_user_id=999)
        # Now the admin generates a challenge for the SAME URL
        r = client.post("/api/verification/dns-txt/generate",
                        headers=admin_headers,
                        data={"target_url": "http://127.0.0.1:8002/existing"})
        assert r.status_code == 200, r.text
        # The existing target's owner should NOT change
        target = fake.get_target(tid)
        assert target["added_by_user_id"] == 999


class TestEngagementLetterTargetOwnership:
    def test_engagement_letter_target_created_with_added_by_user_id(self, fake,
                                                                    client,
                                                                    admin_headers,
                                                                    monkeypatch):
        # Need to bypass file upload in test
        import io
        from unittest.mock import patch

        def mock_upload(file_obj, filename):
            return io.BytesIO(b"%PDF-test")

        with patch("builtins.open", create=True):
            url = "http://127.0.0.1:8003/letter-target"
            file_data = io.BytesIO(b"%PDF-test content")
            r = client.post("/api/verification/engagement-letter/upload",
                            headers=admin_headers,
                            data={"target_url": url},
                            files={"file": ("test.pdf", file_data, "application/pdf")})
            assert r.status_code == 200, r.text
            target_id = r.json().get("target_id")  # Not in response, fetch from fake
            # Find the target created
            targets = fake.targets
            target = next((t for t in targets.values() if t["url"] == url), None)
            assert target is not None
            assert target["added_by_user_id"] is not None
            assert target["added_by_user_id"] == 1


class TestSystemScanTargetOwnership:
    def test_system_scan_creates_target_with_added_by_user_id(self, fake,
                                                              admin_headers,
                                                              monkeypatch):
        # Stub out the heavy scanning internals
        def stub_run(*args, **kwargs):
            pass
        monkeypatch.setattr("webapp.services.system_scan_service._run", stub_run)

        url = "http://127.0.0.1:8004/system-target"
        sid = start_system_scan(user_id=1, target=url, scan_mode="fast",
                                tools=["nmap", "nuclei"], threads=2)
        # Find the target created by system scan
        targets = fake.targets
        target = next((t for t in targets.values() if t["url"] == url), None)
        assert target is not None
        assert target["added_by_user_id"] is not None
        assert target["added_by_user_id"] == 1


class TestLegacyTargetsHandleNullSafely:
    def test_target_created_without_added_by_user_id_is_readable(self, fake):
        # Simulate a legacy target (no added_by_user_id)
        tid = fake.add_target("http://127.0.0.1:8005/legacy",
                              verification_method="dns_txt",
                              added_by_user_id=None)
        target = fake.get_target(tid)
        assert target["added_by_user_id"] is None
        # Should not raise when listed
        targets = fake.list_targets()
        assert any(t["id"] == tid for t in targets)

    def test_get_or_create_target_preserves_existing_owner(self, fake):
        # Create target with a specific owner
        tid = fake.add_target("http://127.0.0.1:8006/shared",
                              verification_method="dns_txt",
                              added_by_user_id=42)
        # Call get_or_create_target with a DIFFERENT user_id
        returned_id = fake.get_or_create_target(
            "http://127.0.0.1:8006/shared",
            verification_method="engagement_letter",
            added_by_user_id=999
        )
        assert returned_id == tid
        target = fake.get_target(tid)
        assert target["added_by_user_id"] == 42  # Original owner preserved


class TestTargetOwnershipIsolation:
    def test_admin_created_target_has_admin_as_owner(self, fake, client,
                                                     admin_headers):
        # Admin creates a target
        url = "http://127.0.0.1:8007/admin-target"
        r = client.post("/api/verification/dns-txt/generate",
                        headers=admin_headers,
                        data={"target_url": url})
        assert r.status_code == 200, r.text
        target_id = r.json()["target_id"]
        target = fake.get_target(target_id)
        assert target["added_by_user_id"] == 1  # Admin is user 1

    def test_system_scan_different_users_have_different_owners(self, fake, monkeypatch):
        def stub_run(*args, **kwargs):
            pass
        monkeypatch.setattr("webapp.services.system_scan_service._run", stub_run)

        # Admin (user_id=1) creates a system scan target
        url1 = "http://127.0.0.1:8008/admin-system"
        start_system_scan(user_id=1, target=url1, scan_mode="fast",
                          tools=["nmap"], threads=2)
        targets = fake.targets
        target1 = next((t for t in targets.values() if t["url"] == url1), None)
        assert target1 is not None
        assert target1["added_by_user_id"] == 1

        # Regular user (user_id=2) creates a different system scan target
        url2 = "http://127.0.0.1:8008/user-system"
        start_system_scan(user_id=2, target=url2, scan_mode="fast",
                          tools=["nmap"], threads=2)
        target2 = next((t for t in targets.values() if t["url"] == url2), None)
        assert target2 is not None
        # Different user owns the different target
        assert target2["added_by_user_id"] == 2
        assert target2["added_by_user_id"] != target1["added_by_user_id"]


class TestSystemScanWithDifferentUsers:
    def test_system_scan_user_id_persisted_in_target(self, fake, monkeypatch):
        def stub_run(*args, **kwargs):
            pass
        monkeypatch.setattr("webapp.services.system_scan_service._run", stub_run)

        url = "http://127.0.0.1:8008/user2-system"
        # Run system scan as user_id=2
        sid = start_system_scan(user_id=2, target=url, scan_mode="fast",
                                tools=["nmap"], threads=2)
        targets = fake.targets
        target = next((t for t in targets.values() if t["url"] == url), None)
        assert target is not None
        assert target["added_by_user_id"] == 2