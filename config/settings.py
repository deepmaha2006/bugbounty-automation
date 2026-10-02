"""
Central application configuration for Bug Bounty Professional.
Single source of truth for app metadata, paths, theme and the scanner catalog.
"""

from pathlib import Path

# ---------------------------------------------------------------------------
# Application metadata
# ---------------------------------------------------------------------------
APP_NAME = "HydraX"
VERSION = "5.1.0"
AUTHOR = "HackerAI"
APP_TAGLINE = "Enterprise Bug Bounty Automation Platform"

PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = PROJECT_ROOT / "reports"
ASSETS_DIR = PROJECT_ROOT / "assets"

# ---------------------------------------------------------------------------
# Scan engine defaults
# ---------------------------------------------------------------------------
DEFAULT_TIMEOUT = 10            # seconds per HTTP request — was 15; every
                                 # scanner used to hardcode its own override
                                 # anyway (now removed, see HTTPClient call
                                 # sites), so this value is what actually
                                 # governs requests now
DEFAULT_REQUEST_DELAY = 0.05    # seconds between requests (politeness
                                 # jitter only — aggregate rate is capped by
                                 # utils/sync_rate_limiter.py, not this)
DEFAULT_THREADS = 8             # parallel scanner workers — actually wired
                                 # to Settings now via ScanEngine.apply_settings
VERIFY_SSL = False
FOLLOW_REDIRECTS = True
MAX_FINDINGS_PER_SCANNER = 50   # cap evidence bloat per scanner

# ---------------------------------------------------------------------------
# Discovery / Crawl settings (Phase 3)
# ---------------------------------------------------------------------------
CRAWL_MAX_PAGES = 200
CRAWL_MAX_DEPTH = 5
CRAWL_MAX_SMART_PROBES = 500
CRAWL_SMART_PROBE_PAGES = 50
CRAWL_REQUEST_TIMEOUT = 15
CRAWL_REQUEST_DELAY = 0.05

# ---------------------------------------------------------------------------
# Adaptive Rate Limiter Configuration
# ---------------------------------------------------------------------------
DEFAULT_RATE_LIMIT = 10        # req/s per host
MAX_RATE_LIMIT = 50            # max req/s per host
MIN_RATE_LIMIT = 0.1           # minimum rate floor (never stop completely)
BURST_CAPACITY = 20            # token bucket burst capacity
ADAPTIVE_ENABLED = True        # enable adaptive rate adjustment
ROBOTS_TXT_COMPLIANCE = True   # respect robots.txt crawl-delay
ROBOTS_TXT_TTL = 3600          # robots.txt cache TTL in seconds (1 hour)
RATE_INCREASE_THRESHOLD = 100  # successful requests before rate increase
RATE_INCREASE_FACTOR = 1.1     # multiplicative factor for rate increase

# Playwright settings (Phase 3 - JS rendering for SPA)
ENABLE_PLAYWRIGHT = True
PLAYWRIGHT_TIMEOUT = 30000      # ms
PLAYWRIGHT_WAIT_UNTIL = "networkidle"
PLAYWRIGHT_HEADLESS = True

# Enhanced discovery features
CRAWL_SITEMAP = True
CRAWL_GRAPHQL = True
CRAWL_JS_ROUTES = True
ROBOTS_TXT_FORCED_BROWSE = True

# ---------------------------------------------------------------------------
# Severity weights used for the aggregate security score (0-100)
# ---------------------------------------------------------------------------
SEVERITY_WEIGHTS = {
    "Critical": -40,
    "High": -20,
    "Medium": -10,
    "Low": -3,
    "Info": 0,
}

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]

# ---------------------------------------------------------------------------
# Scanner catalog.
# Every entry maps to a real, importable scanner class. Scanners that were
# previously listed but had no implementation (session, jwt, oauth, race
# condition, workflow) have been removed so the catalog only advertises
# capabilities that actually work.
# ---------------------------------------------------------------------------
from scanners.core import (           # noqa: E402
    XSSScanner, SQLInjectionScanner, BrokenAccessScanner,
    SubdomainTakeoverScanner, SecurityMisconfigScanner,
    InfoDisclosureScanner, DDoSTester, PassiveRecon,
    AuthSessionScanner, BusinessLogicScanner, SSRFScanner,
    CSRFTester, FileUploadScanner, RCEScanner,
    APIScanner, CloudScanner, MobileScanner,
    CacheScanner, RequestSmuggler, OpenRedirectScanner,
    ClickjackTester, PrototypePollutionScanner, XMLScanner,
    WebSocketScanner, LLMScanner,
)

SCANNER_CATEGORIES = [
    {
        "name": "Web Application Security",
        "icon": "🌐",
        "scanners": [
            {"key": "xss", "name": "Cross-Site Scripting (XSS)",
             "desc": "Reflected, stored and DOM-based XSS detection", "cls": XSSScanner, "default": True},
            {"key": "sqli", "name": "SQL Injection",
             "desc": "Error, boolean, time and union-based SQLi", "cls": SQLInjectionScanner, "default": True},
            {"key": "csrf", "name": "CSRF",
             "desc": "Anti-CSRF token validation and forced actions", "cls": CSRFTester, "default": True},
            {"key": "ssrf", "name": "SSRF",
             "desc": "Cloud metadata, internal services and port probing", "cls": SSRFScanner, "default": True},
            {"key": "rce", "name": "RCE & Command Injection",
             "desc": "Command injection, SSTI and deserialization", "cls": RCEScanner, "default": True},
            {"key": "file_upload", "name": "File Upload",
             "desc": "Web shells, SVG XSS and MIME-type bypass", "cls": FileUploadScanner, "default": True},
            {"key": "open_redirect", "name": "Open Redirect",
             "desc": "Open redirects and host-header injection", "cls": OpenRedirectScanner, "default": True},
            {"key": "clickjack", "name": "Clickjacking",
             "desc": "X-Frame-Options and CSP frame-ancestors checks", "cls": ClickjackTester, "default": True},
        ],
    },
    {
        "name": "Authentication & Business Logic",
        "icon": "🔑",
        "scanners": [
            {"key": "auth_session", "name": "Auth & Session Management",
             "desc": "Password policies, JWT, OAuth and MFA checks", "cls": AuthSessionScanner, "default": True},
            {"key": "business_logic", "name": "Business Logic",
             "desc": "Coupon abuse, price manipulation and payment bypass", "cls": BusinessLogicScanner, "default": True},
        ],
    },
    {
        "name": "Access Control & Misconfiguration",
        "icon": "🔓",
        "scanners": [
            {"key": "bac", "name": "Broken Access Control",
             "desc": "IDOR, privilege escalation and forced browsing", "cls": BrokenAccessScanner, "default": True},
            {"key": "sub_takeover", "name": "Subdomain Takeover",
             "desc": "DNS enumeration and dangling-service takeover", "cls": SubdomainTakeoverScanner, "default": True},
            {"key": "sec_misconfig", "name": "Security Misconfiguration",
             "desc": "Headers, directory listing, methods and server info", "cls": SecurityMisconfigScanner, "default": True},
        ],
    },
    {
        "name": "Network, Cloud & Recon",
        "icon": "📡",
        "scanners": [
            {"key": "info_disclosure", "name": "Information Disclosure",
             "desc": "Secrets, .git exposure, API keys and stack traces", "cls": InfoDisclosureScanner, "default": True},
            {"key": "cloud", "name": "Cloud Security",
             "desc": "Public S3 buckets, IAM and exposed containers", "cls": CloudScanner, "default": True},
            {"key": "ddos", "name": "DDoS Resilience",
             "desc": "Rate limiting, concurrency and payload limits", "cls": DDoSTester, "default": False},
            {"key": "recon", "name": "Passive Reconnaissance",
             "desc": "DNS, WHOIS, SSL and technology fingerprinting", "cls": PassiveRecon, "default": True},
        ],
    },
    {
        "name": "Advanced & Modern Threats",
        "icon": "🔬",
        "scanners": [
            {"key": "api", "name": "API Security",
             "desc": "GraphQL introspection, BOLA, BFLA, mass assignment", "cls": APIScanner, "default": True},
            {"key": "proto_pollution", "name": "Prototype Pollution",
             "desc": "Client and server-side prototype pollution", "cls": PrototypePollutionScanner, "default": True},
            {"key": "xml", "name": "XML / XXE",
             "desc": "XXE, XML injection and billion-laughs attack", "cls": XMLScanner, "default": True},
            {"key": "websocket", "name": "WebSocket Security",
             "desc": "Missing auth, data leakage and message tampering", "cls": WebSocketScanner, "default": True},
            {"key": "llm", "name": "AI / LLM Security",
             "desc": "Prompt injection, data leakage and plugin abuse", "cls": LLMScanner, "default": True},
            {"key": "mobile", "name": "Exposed Secrets & Endpoints",
             "desc": "Hardcoded API keys/tokens in page source and exposed internal API endpoints", "cls": MobileScanner, "default": True},
            {"key": "cache", "name": "Web Cache Poisoning",
             "desc": "Cache deception and cache-key poisoning", "cls": CacheScanner, "default": True},
            {"key": "smuggling", "name": "Request Smuggling",
             "desc": "CL.TE and TE.CL desync detection", "cls": RequestSmuggler, "default": False},
        ],
    },
]

# Flat lookup: scanner key -> catalog entry (with category attached)
SCANNER_MAP = {}
SCANNER_META = {}
for _category in SCANNER_CATEGORIES:
    for _scan in _category["scanners"]:
        SCANNER_MAP[_scan["key"]] = _scan["cls"]
        _scan["category"] = _category["name"]
        _scan["category_icon"] = _category["icon"]
        SCANNER_META[_scan["key"]] = _scan

ALL_SCANNER_KEYS = list(SCANNER_MAP.keys())
DEFAULT_SCANNER_KEYS = [k for k, v in SCANNER_META.items() if v.get("default")]


def resolve_target_url(raw: str) -> str:
    """Normalize a user-supplied target into a valid http(s) URL."""
    target = (raw or "").strip()
    if not target:
        raise ValueError("Target URL cannot be empty.")
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    return target
