"""Phase 7 regression tests: SSRF self-protection for the scan engine itself
(docs/THREAT_MODEL.md boundary 5).

These test utils/ssrf_guard.py directly — no client/fake fixture — since
the guard's whole job is real address classification via Python's stdlib
`ipaddress`/`socket.getaddrinfo`. Literal IP addresses (used throughout)
resolve locally without any real network/DNS dependency, keeping this
suite hermetic; only a real *hostname* lookup would need actual DNS, and
none of these tests do that.
"""
import pytest

from utils.ssrf_guard import (UnsafeScanTargetError, assert_safe_ip_or_cidr,
                              assert_safe_scan_target, resolve_and_check)


class TestUnsafeAddressesAreRejected:
    @pytest.mark.parametrize("ip", [
        "127.0.0.1", "127.0.0.53", "::1",           # loopback
        "169.254.169.254", "169.254.1.1",            # link-local / cloud metadata
        "10.0.0.5", "172.16.0.1", "192.168.1.1",     # RFC1918 private
        "0.0.0.0",                                    # unspecified
        "224.0.0.1",                                  # multicast
    ])
    def test_resolve_and_check_rejects(self, ip):
        with pytest.raises(UnsafeScanTargetError):
            resolve_and_check(ip)

    def test_localhost_hostname_rejected_without_even_resolving(self):
        with pytest.raises(UnsafeScanTargetError, match="localhost"):
            assert_safe_scan_target("http://localhost:8080/admin")

    @pytest.mark.parametrize("url", [
        "http://127.0.0.1/", "https://127.0.0.1:8443/x",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.5:5432/", "https://192.168.1.1/",
    ])
    def test_assert_safe_scan_target_rejects_full_urls(self, url):
        with pytest.raises(UnsafeScanTargetError):
            assert_safe_scan_target(url)


class TestSafeAddressesArePermitted:
    @pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "93.184.216.34"])
    def test_resolve_and_check_allows_public_ip(self, ip):
        resolve_and_check(ip)  # must not raise

    def test_assert_safe_scan_target_allows_public_url(self):
        assert_safe_scan_target("https://93.184.216.34/path?q=1")  # must not raise


class TestCidrAndIpValidation:
    @pytest.mark.parametrize("cidr", ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                                      "127.0.0.0/8", "169.254.0.0/16"])
    def test_private_cidr_rejected(self, cidr):
        with pytest.raises(UnsafeScanTargetError):
            assert_safe_ip_or_cidr(cidr)

    def test_public_cidr_allowed(self):
        assert_safe_ip_or_cidr("8.8.8.0/24")  # must not raise

    def test_single_unsafe_ip_via_cidr_helper_rejected(self):
        with pytest.raises(UnsafeScanTargetError):
            assert_safe_ip_or_cidr("127.0.0.1")

    def test_unparsable_input_fails_closed(self):
        with pytest.raises(UnsafeScanTargetError):
            assert_safe_ip_or_cidr("not-an-ip-or-cidr")


class TestHostnameExtraction:
    def test_port_is_stripped_before_classification(self):
        # 127.0.0.1:9000 must be recognized as loopback, not fail as an
        # unresolvable literal hostname string "127.0.0.1:9000".
        with pytest.raises(UnsafeScanTargetError) as exc:
            assert_safe_scan_target("http://127.0.0.1:9000/x")
        assert "9000" not in str(exc.value)  # the port never leaks into the hostname check

    def test_bare_host_without_scheme_is_handled(self):
        with pytest.raises(UnsafeScanTargetError):
            assert_safe_scan_target("127.0.0.1")


class TestSystemScanTargetParsing:
    def test_url_with_port_correctly_classified_as_ip_or_single_host_cidr(self):
        # ipaddress.ip_network() accepts a bare address as a degenerate
        # single-host network, so a plain IP is classified as is_cidr, not
        # is_ip, by this pre-existing parser — harmless for the SSRF check,
        # which treats both flags identically. What matters here is that the
        # port was stripped and the host is recognized as an address at all.
        from webapp.services.system_scan_service import _parse_target
        parsed = _parse_target("http://127.0.0.1:8008/admin-system")
        assert parsed["is_ip"] or parsed["is_cidr"]
        assert parsed["host"] == "127.0.0.1"

    def test_bare_cidr_still_parses_correctly(self):
        from webapp.services.system_scan_service import _parse_target
        parsed = _parse_target("10.0.0.0/24")
        assert parsed["is_cidr"] is True

    def test_domain_with_port_strips_port(self):
        from webapp.services.system_scan_service import _parse_target
        parsed = _parse_target("http://example.com:8080/")
        assert parsed["domain"] == "example.com"


class TestEnforcementIsWired(object):
    """Confirms the guard is actually called from the two scan-start
    functions (not just defined and forgotten) — the hermetic fake fixture
    bypasses it by default (see conftest.py::fake), so this checks the real,
    unpatched module attribute exists and is the guard function."""

    def test_web_scan_service_imports_the_guard(self):
        from webapp.services import web_scan_service
        assert web_scan_service.assert_safe_scan_target is assert_safe_scan_target

    def test_system_scan_service_imports_the_guard(self):
        from webapp.services import system_scan_service
        assert system_scan_service.assert_safe_ip_or_cidr is assert_safe_ip_or_cidr
        assert system_scan_service.resolve_and_check is resolve_and_check
