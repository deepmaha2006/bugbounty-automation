"""
Scope Configuration for Bug Bounty Professional.

Defines in-scope/out-of-scope URL patterns, crawl limits, rate limits,
and authentication references for a scan target.
"""

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

import yaml


@dataclass
class ScopeConfig:
    """
    Scope configuration for a scan target.

    Patterns support:
    - Glob: /api/**, /admin/*
    - Regex: ^/api/v\\d+/.*
    - Exact: /api/v1/users
    - Domain: example.com, *.example.com
    """

    # In-scope patterns (URL must match at least one if list non-empty)
    allowed_patterns: List[str] = field(default_factory=list)

    # Out-of-scope patterns (URL matching any is excluded)
    denied_patterns: List[str] = field(default_factory=list)

    # Allowed domains (subdomains included if wildcard)
    allowed_domains: List[str] = field(default_factory=list)

    # Denied domains
    denied_domains: List[str] = field(default_factory=list)

    # Crawl limits
    max_pages: int = 200
    max_depth: int = 5
    max_smart_probes: int = 500

    # Rate limiting
    requests_per_second: float = 10.0
    burst_limit: int = 20

    # Authentication reference (key into auth config store)
    auth_ref: str = ""

    # Advanced
    follow_redirects: bool = True
    respect_robots_txt: bool = False  # For authorized testing, often disabled
    crawl_sitemap: bool = True
    crawl_js_routes: bool = True

    # Scanner selection
    enabled_scanners: List[str] = field(default_factory=list)  # Empty = all default
    disabled_scanners: List[str] = field(default_factory=list)

    # Custom headers/cookies for this scope
    custom_headers: Dict[str, str] = field(default_factory=dict)
    custom_cookies: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self):
        # Compile regex patterns
        self._allowed_regex = [self._compile_pattern(p) for p in self.allowed_patterns]
        self._denied_regex = [self._compile_pattern(p) for p in self.denied_patterns]

    @staticmethod
    def _compile_pattern(pattern: str) -> re.Pattern:
        """Convert glob/regex pattern to compiled regex."""
        # If pattern looks like regex (contains regex metacharacters not in glob), use as-is
        regex_meta = set(r".^$*+?{}[]\|()")
        glob_meta = set("*?[]")
        if any(c in pattern for c in regex_meta - glob_meta):
            try:
                return re.compile(pattern)
            except re.error:
                pass
        # Otherwise treat as glob
        return re.compile(fnmatch.translate(pattern))

    def is_in_scope(self, url: str) -> bool:
        """Check if a URL is within scope."""
        parsed = urlparse(url)
        path = parsed.path or "/"
        host = parsed.netloc.lower()

        # Check domain allow/deny first
        if self.allowed_domains:
            domain_ok = False
            for domain in self.allowed_domains:
                domain = domain.lower()
                if domain.startswith("*."):
                    if host.endswith(domain[1:]) or host == domain[2:]:
                        domain_ok = True
                        break
                elif host == domain or host.endswith("." + domain):
                    domain_ok = True
                    break
            if not domain_ok:
                return False

        if self.denied_domains:
            for domain in self.denied_domains:
                domain = domain.lower()
                if domain.startswith("*."):
                    if host.endswith(domain[1:]) or host == domain[2:]:
                        return False
                elif host == domain or host.endswith("." + domain):
                    return False

        # Check path patterns
        test_url = path
        if parsed.query:
            test_url += "?" + parsed.query

        # If allowed_patterns specified, URL must match at least one
        if self._allowed_regex:
            matched = any(r.search(test_url) for r in self._allowed_regex)
            if not matched:
                return False

        # If denied_patterns specified, URL must not match any
        if self._denied_regex:
            if any(r.search(test_url) for r in self._denied_regex):
                return False

        return True

    def filter_urls(self, urls: List[str]) -> List[str]:
        """Filter a list of URLs to only those in scope."""
        return [u for u in urls if self.is_in_scope(u)]

    def get_scanner_keys(self, all_keys: List[str]) -> List[str]:
        """Get the list of scanner keys to run for this scope."""
        if self.enabled_scanners:
            return [k for k in self.enabled_scanners if k in all_keys]
        return [k for k in all_keys if k not in self.disabled_scanners]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed_patterns": self.allowed_patterns,
            "denied_patterns": self.denied_patterns,
            "allowed_domains": self.allowed_domains,
            "denied_domains": self.denied_domains,
            "max_pages": self.max_pages,
            "max_depth": self.max_depth,
            "max_smart_probes": self.max_smart_probes,
            "requests_per_second": self.requests_per_second,
            "burst_limit": self.burst_limit,
            "auth_ref": self.auth_ref,
            "follow_redirects": self.follow_redirects,
            "respect_robots_txt": self.respect_robots_txt,
            "crawl_sitemap": self.crawl_sitemap,
            "crawl_js_routes": self.crawl_js_routes,
            "enabled_scanners": self.enabled_scanners,
            "disabled_scanners": self.disabled_scanners,
            "custom_headers": self.custom_headers,
            "custom_cookies": self.custom_cookies,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScopeConfig":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    def to_yaml(self) -> str:
        return yaml.dump(self.to_dict(), sort_keys=False, default_flow_style=False)

    @classmethod
    def from_yaml(cls, yaml_str: str) -> "ScopeConfig":
        return cls.from_dict(yaml.safe_load(yaml_str))

    @classmethod
    def from_file(cls, path: Union[str, Path]) -> "ScopeConfig":
        with open(path, "r", encoding="utf-8") as f:
            return cls.from_yaml(f.read())

    def save(self, path: Union[str, Path]) -> None:
        Path(path).write_text(self.to_yaml(), encoding="utf-8")


# Default scope (permissive for backward compatibility)
DEFAULT_SCOPE = ScopeConfig()


def create_api_scope(base_path: str = "/api") -> ScopeConfig:
    """Create a scope restricted to API endpoints."""
    return ScopeConfig(
        allowed_patterns=[f"{base_path}/**"],
        denied_patterns=[],
        max_pages=500,
        max_depth=10,
        enabled_scanners=["api", "sqli", "bac", "auth_session", "business_logic", "ssrf"],
    )


def create_web_scope() -> ScopeConfig:
    """Create a scope for traditional web application scanning."""
    return ScopeConfig(
        allowed_patterns=["/**"],
        denied_patterns=["/logout", "/signout", "/delete*", "/reset*"],
        max_pages=200,
        max_depth=5,
    )


def create_authenticated_scope(auth_ref: str, base_path: str = "/") -> ScopeConfig:
    """Create a scope for authenticated scanning."""
    return ScopeConfig(
        allowed_patterns=[f"{base_path}/**"],
        denied_patterns=["/logout", "/signout"],
        auth_ref=auth_ref,
        max_pages=300,
        max_depth=6,
    )


from urllib.parse import urlparse