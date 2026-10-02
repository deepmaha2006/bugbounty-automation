"""
Scan Profile Configuration for Bug Bounty Professional.

Defines named scan profiles (presets) that combine scope, authentication,
scanner selection, and other settings for different scan scenarios.
Profiles are persisted as YAML files in config/profiles/.
"""

import glob
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml

from config.scope import ScopeConfig


# Default profiles directory
DEFAULT_PROFILES_DIR = Path(__file__).parent / "profiles"


@dataclass
class ScanProfile:
    """
    A named scan profile containing all configuration for a scan type.

    Profiles encapsulate:
    - Scope configuration (what to scan)
    - Authentication reference
    - Scanner selection (which scanners to run)
    - Crawl/rate limits
    - Custom headers/cookies
    - Metadata (description, tags, version)
    """

    # Identity
    name: str
    description: str = ""
    version: str = "1.0"
    tags: List[str] = field(default_factory=list)

    # Scope configuration (embedded or reference)
    scope: Optional[ScopeConfig] = None
    scope_file: str = ""  # Optional path to external scope file

    # Authentication
    auth_ref: str = ""  # Key into auth config store

    # Scanner selection
    enabled_scanners: List[str] = field(default_factory=list)  # Empty = all default
    disabled_scanners: List[str] = field(default_factory=list)

    # Crawl settings (override scope if set)
    max_pages: int = 0  # 0 = use scope default
    max_depth: int = 0
    max_smart_probes: int = 0

    # Rate limiting (override scope if set)
    requests_per_second: float = 0.0
    burst_limit: int = 0

    # Advanced options
    follow_redirects: bool = True
    respect_robots_txt: bool = False
    crawl_sitemap: bool = True
    crawl_js_routes: bool = False
    verify_findings: bool = True  # Run false-positive verification pass
    capture_screenshots: bool = False  # Requires Playwright

    # Custom request modifiers
    custom_headers: Dict[str, str] = field(default_factory=dict)
    custom_cookies: Dict[str, str] = field(default_factory=dict)

    # Reporting
    report_template: str = "default"  # Future: custom templates
    export_formats: List[str] = field(default_factory=lambda: ["html"])
    fail_on_severity: str = ""  # "critical", "high", "medium" — for CI/CD

    def __post_init__(self):
        if self.scope is None:
            self.scope = ScopeConfig()

    def get_effective_scope(self) -> ScopeConfig:
        """Get the effective scope config (profile overrides + base scope)."""
        scope = self.scope or ScopeConfig()

        # Apply profile-level overrides
        if self.max_pages > 0:
            scope.max_pages = self.max_pages
        if self.max_depth > 0:
            scope.max_depth = self.max_depth
        if self.max_smart_probes > 0:
            scope.max_smart_probes = self.max_smart_probes
        if self.requests_per_second > 0:
            scope.requests_per_second = self.requests_per_second
        if self.burst_limit > 0:
            scope.burst_limit = self.burst_limit

        if self.auth_ref:
            scope.auth_ref = self.auth_ref

        if self.custom_headers:
            scope.custom_headers.update(self.custom_headers)
        if self.custom_cookies:
            scope.custom_cookies.update(self.custom_cookies)

        # Scanner selection: profile takes precedence over scope
        # Only override if profile has explicit values
        if self.enabled_scanners:
            scope.enabled_scanners = self.enabled_scanners
        if self.disabled_scanners:
            scope.disabled_scanners = self.disabled_scanners

        return scope

    def get_scanner_keys(self, all_keys: List[str]) -> List[str]:
        """Get the list of scanner keys to run for this profile."""
        # Profile's enabled_scanners takes direct precedence
        if self.enabled_scanners:
            return [k for k in self.enabled_scanners if k in all_keys]
        # Otherwise use scope's logic
        scope = self.get_effective_scope()
        return scope.get_scanner_keys(all_keys)

    def to_dict(self) -> Dict[str, Any]:
        data = {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "tags": self.tags,
            "auth_ref": self.auth_ref,
            "enabled_scanners": self.enabled_scanners,
            "disabled_scanners": self.disabled_scanners,
            "max_pages": self.max_pages,
            "max_depth": self.max_depth,
            "max_smart_probes": self.max_smart_probes,
            "requests_per_second": self.requests_per_second,
            "burst_limit": self.burst_limit,
            "follow_redirects": self.follow_redirects,
            "respect_robots_txt": self.respect_robots_txt,
            "crawl_sitemap": self.crawl_sitemap,
            "crawl_js_routes": self.crawl_js_routes,
            "verify_findings": self.verify_findings,
            "capture_screenshots": self.capture_screenshots,
            "custom_headers": self.custom_headers,
            "custom_cookies": self.custom_cookies,
            "report_template": self.report_template,
            "export_formats": self.export_formats,
            "fail_on_severity": self.fail_on_severity,
        }
        if self.scope:
            data["scope"] = self.scope.to_dict()
        if self.scope_file:
            data["scope_file"] = self.scope_file
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanProfile":
        scope_data = data.pop("scope", None)
        scope = ScopeConfig.from_dict(scope_data) if scope_data else None
        return cls(scope=scope, **{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    def to_yaml(self) -> str:
        return yaml.dump(self.to_dict(), sort_keys=False, default_flow_style=False)

    @classmethod
    def from_yaml(cls, yaml_str: str) -> "ScanProfile":
        return cls.from_dict(yaml.safe_load(yaml_str))

    def save(self, directory: Union[str, Path] = None) -> Path:
        """Save profile to YAML file in profiles directory."""
        if directory is None:
            directory = DEFAULT_PROFILES_DIR
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)

        # Sanitize filename
        safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in self.name)
        path = directory / f"{safe_name}.yaml"
        path.write_text(self.to_yaml(), encoding="utf-8")
        return path

    @classmethod
    def load(cls, name: str, directory: Union[str, Path] = None) -> "ScanProfile":
        """Load profile by name from profiles directory."""
        if directory is None:
            directory = DEFAULT_PROFILES_DIR
        directory = Path(directory)

        # Try exact match first
        for ext in [".yaml", ".yml"]:
            path = directory / f"{name}{ext}"
            if path.exists():
                return cls.from_yaml(path.read_text(encoding="utf-8"))

        # Try sanitized name
        safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in name)
        for ext in [".yaml", ".yml"]:
            path = directory / f"{safe_name}{ext}"
            if path.exists():
                return cls.from_yaml(path.read_text(encoding="utf-8"))

        raise FileNotFoundError(f"Profile '{name}' not found in {directory}")

    @classmethod
    def load_from_file(cls, path: Union[str, Path]) -> "ScanProfile":
        """Load profile from a specific file path."""
        return cls.from_yaml(Path(path).read_text(encoding="utf-8"))

    def delete(self, directory: Union[str, Path] = None) -> bool:
        """Delete the profile file."""
        if directory is None:
            directory = DEFAULT_PROFILES_DIR
        directory = Path(directory)
        safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in self.name)
        for ext in [".yaml", ".yml"]:
            path = directory / f"{safe_name}{ext}"
            if path.exists():
                path.unlink()
                return True
        return False


# =============================================================================
# Built-in Profile Factory Functions
# =============================================================================

def create_web_full_profile() -> ScanProfile:
    """Comprehensive web application scan."""
    return ScanProfile(
        name="web-full",
        description="Full web application scan with deep crawling and all scanners",
        tags=["web", "comprehensive", "default"],
        scope=ScopeConfig(
            allowed_patterns=["/**"],
            denied_patterns=["/logout", "/signout", "/delete*", "/reset*", "/unsubscribe*"],
            max_pages=200,
            max_depth=5,
            max_smart_probes=500,
            requests_per_second=10.0,
            burst_limit=20,
            crawl_sitemap=True,
            crawl_js_routes=True,
        ),
        enabled_scanners=[],  # All default
        disabled_scanners=[],
        verify_findings=True,
        export_formats=["html", "json"],
    )


def create_api_deep_profile() -> ScanProfile:
    """Deep API security scan."""
    return ScanProfile(
        name="api-deep",
        description="Deep API security scan with extended limits and API-focused scanners",
        tags=["api", "deep", "rest", "graphql"],
        scope=ScopeConfig(
            allowed_patterns=["/api/**", "/v*/**", "/graphql", "/graphiql"],
            denied_patterns=[],
            max_pages=500,
            max_depth=10,
            max_smart_probes=1000,
            requests_per_second=20.0,
            burst_limit=50,
            crawl_sitemap=True,
            crawl_js_routes=False,
        ),
        enabled_scanners=[
            "api", "sqli", "bac", "auth_session", "business_logic",
            "ssrf", "xml", "proto_pollution", "cache",
        ],
        verify_findings=True,
        export_formats=["html", "json", "sarif"],
        fail_on_severity="high",
    )


def create_auth_quick_profile(auth_ref: str = "") -> ScanProfile:
    """Quick authenticated scan for logged-in areas."""
    return ScanProfile(
        name="auth-quick",
        description="Quick authenticated scan for internal applications",
        tags=["auth", "quick", "internal"],
        auth_ref=auth_ref,
        scope=ScopeConfig(
            allowed_patterns=["/**"],
            denied_patterns=["/logout", "/signout"],
            max_pages=100,
            max_depth=3,
            max_smart_probes=200,
            requests_per_second=15.0,
            burst_limit=30,
            auth_ref=auth_ref,
            crawl_sitemap=True,
            crawl_js_routes=True,
        ),
        enabled_scanners=[
            "xss", "sqli", "bac", "auth_session", "business_logic",
            "csrf", "file_upload", "open_redirect", "ssrf",
        ],
        verify_findings=True,
        export_formats=["html", "json"],
    )


def create_compliance_profile() -> ScanProfile:
    """Compliance-focused scan (OWASP Top 10, PCI-DSS relevant)."""
    return ScanProfile(
        name="compliance",
        description="Compliance scan covering OWASP Top 10 and common regulatory requirements",
        tags=["compliance", "owasp", "pci", "hipaa"],
        scope=ScopeConfig(
            allowed_patterns=["/**"],
            denied_patterns=["/logout", "/signout", "/delete*"],
            max_pages=300,
            max_depth=5,
            max_smart_probes=500,
            requests_per_second=10.0,
            burst_limit=20,
        ),
        enabled_scanners=[
            "xss", "sqli", "bac", "auth_session", "ssrf", "xml",
            "proto_pollution", "csrf", "file_upload", "rce",
            "sec_misconfig", "info_disclosure", "cloud",
        ],
        verify_findings=True,
        export_formats=["html", "json", "sarif"],
        fail_on_severity="medium",
    )


def create_mobile_api_profile() -> ScanProfile:
    """Mobile backend API scan."""
    return ScanProfile(
        name="mobile-api",
        description="Mobile application backend API security scan",
        tags=["mobile", "api", "backend"],
        scope=ScopeConfig(
            allowed_patterns=["/api/**", "/mobile/**", "/app/**", "/v*/**"],
            denied_patterns=[],
            max_pages=300,
            max_depth=8,
            max_smart_probes=500,
            requests_per_second=15.0,
            burst_limit=30,
        ),
        enabled_scanners=[
            "api", "sqli", "bac", "auth_session", "business_logic",
            "ssrf", "proto_pollution", "csrf", "open_redirect",
            "xml", "cache", "mobile",
        ],
        verify_findings=True,
        export_formats=["html", "json", "sarif"],
    )


def create_cms_profile() -> ScanProfile:
    """CMS-focused scan (WordPress, Drupal, Joomla, etc.)."""
    return ScanProfile(
        name="cms",
        description="Content Management System security scan",
        tags=["cms", "wordpress", "drupal", "joomla"],
        scope=ScopeConfig(
            allowed_patterns=["/**"],
            denied_patterns=["/logout", "/signout", "/wp-login.php?action=logout"],
            max_pages=150,
            max_depth=4,
            max_smart_probes=300,
            requests_per_second=8.0,
            burst_limit=15,
        ),
        enabled_scanners=[
            "xss", "sqli", "bac", "file_upload", "rce", "xml",
            "sec_misconfig", "info_disclosure", "auth_session",
            "csrf", "open_redirect", "ssrf", "proto_pollution",
        ],
        verify_findings=True,
        export_formats=["html", "json"],
    )


def create_cloud_profile() -> ScanProfile:
    """Cloud infrastructure and configuration scan."""
    return ScanProfile(
        name="cloud",
        description="Cloud infrastructure security scan (AWS, Azure, GCP metadata, storage)",
        tags=["cloud", "aws", "azure", "gcp", "infrastructure"],
        scope=ScopeConfig(
            allowed_patterns=["/**"],
            denied_patterns=[],
            max_pages=100,
            max_depth=3,
            max_smart_probes=200,
            requests_per_second=5.0,
            burst_limit=10,
        ),
        enabled_scanners=[
            "cloud", "recon", "ssrf", "info_disclosure", "sec_misconfig",
            "sub_takeover", "bac", "auth_session",
        ],
        verify_findings=True,
        export_formats=["html", "json", "sarif"],
    )


# =============================================================================
# Profile Registry / Manager
# =============================================================================

class ProfileManager:
    """Manages scan profiles: discovery, loading, saving, listing."""

    def __init__(self, profiles_dir: Union[str, Path] = None):
        self.profiles_dir = Path(profiles_dir) if profiles_dir else DEFAULT_PROFILES_DIR
        self.profiles_dir.mkdir(parents=True, exist_ok=True)
        self._cache: Dict[str, ScanProfile] = {}

    def list_profiles(self) -> List[str]:
        """List all available profile names."""
        profiles = []
        for ext in ["*.yaml", "*.yml"]:
            for path in self.profiles_dir.glob(ext):
                profiles.append(path.stem)
        return sorted(set(profiles))

    def get_profile(self, name: str, use_cache: bool = True) -> ScanProfile:
        """Get a profile by name, with optional caching."""
        if use_cache and name in self._cache:
            return self._cache[name]
        profile = ScanProfile.load(name, self.profiles_dir)
        if use_cache:
            self._cache[name] = profile
        return profile

    def save_profile(self, profile: ScanProfile) -> Path:
        """Save a profile to the profiles directory."""
        path = profile.save(self.profiles_dir)
        self._cache[profile.name] = profile
        return path

    def delete_profile(self, name: str) -> bool:
        """Delete a profile by name."""
        profile = self.get_profile(name, use_cache=False)
        result = profile.delete(self.profiles_dir)
        if name in self._cache:
            del self._cache[name]
        return result

    def create_builtins(self) -> Dict[str, Path]:
        """Create all built-in profiles in the profiles directory."""
        builtins = {
            "web-full": create_web_full_profile(),
            "api-deep": create_api_deep_profile(),
            "auth-quick": create_auth_quick_profile(),
            "compliance": create_compliance_profile(),
            "mobile-api": create_mobile_api_profile(),
            "cms": create_cms_profile(),
            "cloud": create_cloud_profile(),
        }
        paths = {}
        for name, profile in builtins.items():
            paths[name] = self.save_profile(profile)
        return paths

    def export_profile(self, name: str, output_path: Union[str, Path]) -> Path:
        """Export a profile to a specific file path."""
        profile = self.get_profile(name)
        output_path = Path(output_path)
        output_path.write_text(profile.to_yaml(), encoding="utf-8")
        return output_path

    def import_profile(self, path: Union[str, Path]) -> ScanProfile:
        """Import a profile from a file."""
        profile = ScanProfile.load_from_file(path)
        self.save_profile(profile)
        return profile


# Global profile manager instance
_profile_manager: Optional[ProfileManager] = None


def get_profile_manager(profiles_dir: Union[str, Path] = None) -> ProfileManager:
    """Get the global profile manager instance."""
    global _profile_manager
    if _profile_manager is None or (profiles_dir and _profile_manager.profiles_dir != Path(profiles_dir)):
        _profile_manager = ProfileManager(profiles_dir)
    return _profile_manager


def list_profiles(profiles_dir: Union[str, Path] = None) -> List[str]:
    """List all available profiles."""
    return get_profile_manager(profiles_dir).list_profiles()


def load_profile(name: str, profiles_dir: Union[str, Path] = None) -> ScanProfile:
    """Load a profile by name."""
    return get_profile_manager(profiles_dir).get_profile(name)


def save_profile(profile: ScanProfile, profiles_dir: Union[str, Path] = None) -> Path:
    """Save a profile."""
    return get_profile_manager(profiles_dir).save_profile(profile)


def init_builtin_profiles(profiles_dir: Union[str, Path] = None) -> Dict[str, Path]:
    """Initialize all built-in profiles."""
    return get_profile_manager(profiles_dir).create_builtins()