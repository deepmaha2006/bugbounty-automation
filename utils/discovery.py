"""
URL, parameter and form discovery.

Before the vulnerability scanners run, this module crawls the target
(links, forms, scripts, robots.txt, sitemap.xml) and produces the real
attack surface: every same-origin endpoint, every GET parameter name and
every POST form field. Scanners then test those targets, which is what
makes the suite find vulnerabilities on *any* website — not only pages
that already carry query parameters in their bare URL.

The crawl is deliberately bounded (page count, depth and probe budget)
so discovery finishes in seconds even on large applications.

Phase 3 enhancements:
- Playwright-based JS rendering for SPA route discovery
- Sitemap-driven discovery with priority sorting
- robots.txt disallow → forced-browse candidate seeding
- GraphQL introspection endpoint detection
- Increased default limits for comprehensive scanning
"""

import re
import time
import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional, TYPE_CHECKING, Set
from urllib.parse import (
    urljoin, urlparse, parse_qs, urlencode, urlunparse,
)

from bs4 import BeautifulSoup

from utils.http_client import HTTPClient
from core.scan_context import abort_if_stopped, stop_requested

if TYPE_CHECKING:
    from config.scope import ScopeConfig

# ---------------------------------------------------------------------------
# Tunables (increased for professional/comprehensive scanning)
# ---------------------------------------------------------------------------
MAX_PAGES = 200
MAX_DEPTH = 5
MAX_SMART_PROBES = 500
SMART_PROBE_PAGES = 50
REQUEST_TIMEOUT = 15
REQUEST_DELAY = 0.05

# Page fetches and smart-parameter probes are pure network I/O bound by the
# per-request rate-limit delay in HTTPClient — running them one at a time
# made discovery (and therefore the whole scan) take minutes even on small
# sites before a single vulnerability scanner started. Both are fanned out
# across a small thread pool instead; response parsing / state mutation
# stays single-threaded (only the network I/O is concurrent), so no locking
# is needed around self.targets/_seen_urls/queue.
CRAWL_FETCH_WORKERS = 10

# Playwright settings
PLAYWRIGHT_ENABLED = True
PLAYWRIGHT_TIMEOUT = 30000  # ms
PLAYWRIGHT_WAIT_UNTIL = "networkidle"
PLAYWRIGHT_HEADLESS = True

# Parameters most likely to drive server-side logic. Used to probe pages
# that expose no query parameters in their HTML.
SMART_PARAMS = [
    "id", "q", "s", "search", "query", "term", "keyword", "page",
    "page_no", "category", "cat", "user", "username", "user_id", "uid",
    "account", "order", "order_id", "file", "filename", "path", "url",
    "redirect", "next", "return", "callback", "lang", "type", "action",
    "cmd", "code", "name", "email", "role", "status", "sort", "filter",
]

# File extensions we should never treat as HTML crawl targets.
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".css",
    ".js", ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".gz",
    ".tar", ".mp4", ".mp3", ".avi", ".mov", ".doc", ".docx", ".xls",
    ".xlsx", ".ppt", ".pptx", ".exe", ".msi", ".apk", ".ipa", ".dmg",
    ".webm", ".map", ".json", ".xml", ".txt", ".csv", ".woff",
}

STATIC_JS_PATTERNS = re.compile(
    r"\.js(?:\?|$)|\.min\.js|/assets/|/static/|/js/", re.IGNORECASE
)


@dataclass
class DiscoveredTarget:
    """One testable endpoint discovered during the crawl."""

    url: str
    method: str = "get"                                   # get | post
    params: List[str] = field(default_factory=list)       # GET param names
    form_fields: Dict[str, str] = field(default_factory=dict)  # POST fields
    source: str = ""                                      # link|form|path|query|sitemap|probe
    title: str = ""

    def to_dict(self) -> Dict:
        return {
            "url": self.url,
            "method": self.method,
            "params": self.params,
            "form_fields": self.form_fields,
            "source": self.source,
            "title": self.title,
        }


def normalize_target(raw: str) -> str:
    """Normalize a user-supplied target to a clean http(s) URL."""
    target = (raw or "").strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    parsed = urlparse(target)
    path = parsed.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    return urlunparse((parsed.scheme, parsed.netloc, path, parsed.params, "", ""))


def _same_origin(a: str, b: str) -> bool:
    pa, pb = urlparse(a), urlparse(b)
    return (pa.scheme, pa.netloc) == (pb.scheme, pb.netloc)


def _strip_fragment(url: str) -> str:
    return url.split("#", 1)[0]


class URLDiscovery:
    """Bounded crawler that extracts testable endpoints from a target."""

    def __init__(self, target: str, max_pages: int = MAX_PAGES,
                 max_depth: int = MAX_DEPTH, request_timeout: int = REQUEST_TIMEOUT,
                 request_delay: float = REQUEST_DELAY, verify_ssl: bool = False,
                 smart_probe: bool = True, include_common_paths: bool = True,
                 crawl_sitemap: bool = True, crawl_graphql: bool = True,
                 crawl_js_routes: bool = True):
        self.client = HTTPClient(timeout=request_timeout, delay=request_delay,
                                 verify_ssl=verify_ssl)
        self.root = normalize_target(target)
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.smart_probe = smart_probe
        self.include_common_paths = include_common_paths

        # Optional scope configuration for in-scope filtering
        self.scope: Optional["ScopeConfig"] = None

        self.targets: List[DiscoveredTarget] = []
        self._seen_urls = set()
        self._seen_forms = set()
        self._probe_counter = 0
        self.pages_fetched = 0
        self.probes_fired = 0
        self.error: Optional[str] = None
        self._discovery_started = time.time()
        # _fetch() runs concurrently across worker threads (see _crawl);
        # guards the pages_fetched counter it increments.
        self._pages_fetched_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------
    def discover(self) -> List[DiscoveredTarget]:
        """Run the crawl and return the discovered targets."""
        try:
            self._crawl()
            if self.include_common_paths:
                self._add_common_paths()
            self._dedup()
        except Exception as exc:  # noqa: BLE001
            self.error = f"{type(exc).__name__}: {exc}"
        return self.targets

    def summary(self) -> Dict:
        return {
            "root": self.root,
            "pages_fetched": self.pages_fetched,
            "probes_fired": self.probes_fired,
            "targets": len(self.targets),
            "get_targets": sum(1 for t in self.targets if t.method == "get"),
            "post_targets": sum(1 for t in self.targets if t.method == "post"),
            "params_found": sum(len(t.params) for t in self.targets),
            "form_fields_found": sum(len(t.form_fields) for t in self.targets),
            "error": self.error,
            "elapsed_seconds": round(time.time() - self._discovery_started, 2),
        }

    # ------------------------------------------------------------------
    # Crawl
    # ------------------------------------------------------------------
    def _crawl(self) -> None:
        # Always probe the root page for smart parameters.
        self._add_target(self.root, params=[], source="root")

        queue: List = [(self.root, 0)]
        visited = set()
        workers = max(1, min(CRAWL_FETCH_WORKERS, self.max_pages))

        with ThreadPoolExecutor(max_workers=workers) as executor:
            while queue and self.pages_fetched < self.max_pages:
                if stop_requested():
                    return

                # Pull a batch of not-yet-visited URLs and fetch them all at
                # once — only the network I/O (_fetch) runs concurrently;
                # everything below (parsing, self.targets/_seen_urls/queue
                # mutation) happens back on this thread as each future
                # completes, so none of it needs locking.
                batch: List = []
                while queue and len(batch) < workers and self.pages_fetched + len(batch) < self.max_pages:
                    url, depth = queue.pop(0)
                    if url in visited:
                        continue
                    visited.add(url)
                    batch.append((url, depth))

                if not batch:
                    break

                future_to_item = {executor.submit(self._fetch, url): (url, depth) for url, depth in batch}

                for future in as_completed(future_to_item):
                    if stop_requested():
                        return
                    url, depth = future_to_item[future]
                    try:
                        resp = future.result()
                    except Exception:  # noqa: BLE001
                        resp = None
                    if resp is None:
                        continue

                    next_pages = self._process_page(url, depth, resp)
                    for nxt in next_pages:
                        if nxt not in visited and self.pages_fetched < self.max_pages:
                            queue.append((nxt, depth + 1))

        # -- robots.txt / sitemap ---------------------------------------
        self._add_robots_and_sitemap()

    def _process_page(self, url: str, depth: int, resp) -> List[str]:
        """Parse one fetched page: extract forms/links/iframes, fire smart
        parameter probing, and return same-origin links worth crawling
        next. Runs on the crawler's driving thread (see _crawl) — never
        called concurrently, so no locking is needed around self.targets/
        _seen_urls/_seen_forms."""
        ctype = resp.headers.get("Content-Type", "")
        if "html" not in ctype and "xhtml" not in ctype:
            return []

        try:
            soup = BeautifulSoup(resp.text, "html.parser")
        except Exception:  # noqa: BLE001
            return []

        page_title = ""
        if soup.title and soup.title.string:
            page_title = " ".join(soup.title.string.split())[:80]

        # -- forms -------------------------------------------------
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = (form.get("method", "get") or "get").lower()
            form_url = _strip_fragment(urljoin(url, action or url))
            if not _same_origin(form_url, self.root):
                continue
            fields: Dict[str, str] = {}
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name:
                    continue
                if inp.name == "select":
                    fields[name] = ""
                else:
                    fields[name] = inp.get("value", "")
            form_key = (form_url, method, tuple(sorted(fields)))
            if form_key in self._seen_forms:
                continue
            self._seen_forms.add(form_key)
            if method == "post":
                self._add_target(form_url, params=[],
                                 form_fields=fields, source="form",
                                 title=page_title)
            elif fields:
                self._add_target(form_url, params=sorted(fields),
                                 source="form", title=page_title)
            elif form_url != self.root:
                self._add_target(form_url, params=[], source="form",
                                 title=page_title)

        # -- links --------------------------------------------------
        next_pages = []
        for link in soup.find_all(["a", "area"]):
            href = link.get("href")
            if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue
            full = _strip_fragment(urljoin(url, href))
            if not _same_origin(full, self.root):
                continue
            if self._is_skip(full):
                continue
            if not self._is_in_scope(full):
                continue
            parsed = urlparse(full)
            qs = parse_qs(parsed.query)
            if qs:
                self._add_target(full, params=sorted(qs), source="query",
                                 title=page_title)
            else:
                self._add_target(full, params=[], source="link",
                                 title=page_title)
                if depth < self.max_depth:
                    next_pages.append(full)

        # -- iframes / meta refresh --------------------------------
        for frame in soup.find_all(["iframe", "frame"]):
            src = frame.get("src")
            if src:
                full = _strip_fragment(urljoin(url, src))
                if _same_origin(full, self.root) and not self._is_skip(full):
                    if self._is_in_scope(full):
                        next_pages.append(full)

        # -- smart parameter probing --------------------------------
        if self.smart_probe:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            if not qs and self.probes_fired < MAX_SMART_PROBES:
                self._probe_smart_params(url, page_title)

        return next_pages

    # ------------------------------------------------------------------
    # Fetch helpers
    # ------------------------------------------------------------------
    def _fetch(self, url: str):
        try:
            resp = self.client.get(url)
            with self._pages_fetched_lock:
                self.pages_fetched += 1
            return resp
        except Exception:  # noqa: BLE001
            return None

    def _probe_smart_params(self, url: str, page_title: str) -> None:
        """Detect which common parameters a page accepts (cheap probes).

        Fires the up-to-30 SMART_PARAMS probes concurrently instead of one
        at a time — serially, with HTTPClient's per-request rate-limit
        delay, this alone could cost several seconds *per parameterless
        page* crawled, multiplied by up to SMART_PROBE_PAGES pages.
        """
        if self.pages_fetched > SMART_PROBE_PAGES and self.probes_fired > 0:
            return
        baseline = self._fetch(url)
        if baseline is None:
            return
        base_len = len(baseline.text)
        base_status = baseline.status_code
        parsed = urlparse(url)

        remaining_budget = MAX_SMART_PROBES - self.probes_fired
        if remaining_budget <= 0:
            return
        params_to_try = SMART_PARAMS[:remaining_budget]

        # Precompute markers on this thread (no shared-counter races), then
        # fan the actual requests out to worker threads.
        jobs = []
        for param in params_to_try:
            marker = f"zzq{self._probe_counter}{param}"
            self._probe_counter += 1
            jobs.append((param, marker))
        self.probes_fired += len(jobs)

        def probe_one(param: str, marker: str) -> Optional[str]:
            q = urlencode({param: marker})
            probe_url = urlunparse(parsed._replace(query=q))
            try:
                resp = self.client.get(probe_url)
                diff = abs(len(resp.text) - base_len)
                reflected = marker in resp.text
                # A page "uses" the parameter when the value is reflected,
                # the status code changes, or the response size shifts a lot.
                if reflected or diff > 150 or resp.status_code != base_status:
                    return param
            except Exception:  # noqa: BLE001
                pass
            return None

        found = []
        workers = max(1, min(CRAWL_FETCH_WORKERS, len(jobs)))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(probe_one, param, marker) for param, marker in jobs]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)

        if found:
            self._add_target(url, params=found[:5], source="probe", title=page_title)

    def _add_robots_and_sitemap(self) -> None:
        if stop_requested():
            return
        # robots.txt disallow paths are prime forced-browsing candidates.
        try:
            robots_url = urljoin(self.root, "/robots.txt")
            resp = self.client.get(robots_url)
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    line = line.strip()
                    low = line.lower()
                    if low.startswith("disallow") and ":" in line:
                        path = line.split(":", 1)[1].strip()
                        if path and path != "/":
                            full = urljoin(self.root, path)
                            if _same_origin(full, self.root) and not self._is_skip(full):
                                self._add_target(full, params=[], source="robots")
        except Exception:  # noqa: BLE001
            pass

        # sitemap.xml locations
        try:
            sitemap_url = urljoin(self.root, "/sitemap.xml")
            resp = self.client.get(sitemap_url)
            if resp.status_code == 200 and "xml" in resp.headers.get("Content-Type", "").lower():
                soup = BeautifulSoup(resp.text, "xml")
                for loc in soup.find_all("loc"):
                    loc_text = (loc.get_text() or "").strip()
                    if not loc_text:
                        continue
                    full = _strip_fragment(loc_text)
                    if _same_origin(full, self.root) and not self._is_skip(full):
                        self._add_target(full, params=[], source="sitemap")
        except Exception:  # noqa: BLE001
            pass

    def _add_common_paths(self) -> None:
        """Add high-value paths from the payload database (checked later by
        info-disclosure / BAC / misconfig scanners; here we only pre-seed the
        URL list so parameter scanners skip obvious non-parameter endpoints)."""
        # Handled by dedicated scanners; nothing extra to add for param tests.
        return

    # ------------------------------------------------------------------
    # Bookkeeping
    # ------------------------------------------------------------------
    def _is_in_scope(self, url: str) -> bool:
        """Check if a URL is within the configured scope."""
        if self.scope:
            return self.scope.is_in_scope(url)
        return True

    def _is_skip(self, url: str) -> bool:
        path = urlparse(url).path.lower()
        for ext in SKIP_EXTENSIONS:
            if path.endswith(ext):
                return True
        return False

    def _add_target(self, url: str, params: List[str],
                    form_fields: Optional[Dict[str, str]] = None,
                    source: str = "link", title: str = "") -> None:
        url = _strip_fragment(url)
        if not _same_origin(url, self.root):
            return
        if not self._is_in_scope(url):
            return
        key = (url, source)
        if key in self._seen_urls:
            return
        self._seen_urls.add(key)
        method = "post" if form_fields else "get"
        self.targets.append(DiscoveredTarget(
            url=url, method=method, params=list(params),
            form_fields=form_fields or {}, source=source, title=title,
        ))

    def _dedup(self) -> None:
        """Merge duplicate URLs, preferring the version with most params."""
        by_url: Dict[str, DiscoveredTarget] = {}
        for t in self.targets:
            existing = by_url.get(t.url)
            if existing is None:
                by_url[t.url] = t
                continue
            # merge params/form fields
            merged_params = sorted(set(existing.params) | set(t.params))
            merged_fields = {**t.form_fields, **existing.form_fields}
            if len(merged_params) > len(existing.params) or merged_fields:
                existing.params = merged_params
                existing.form_fields = merged_fields
                if t.method == "post" or existing.method == "post":
                    existing.method = "post" if (merged_fields or t.form_fields) else existing.method
                existing.source = existing.source if existing.params else t.source
        self.targets = list(by_url.values())


def discover_target(target: str, **kwargs) -> List[DiscoveredTarget]:
    """One-shot discovery helper used by the scan engine and CLI."""
    return URLDiscovery(target, **kwargs).discover()


# =============================================================================
# Phase 3: Enhanced Discovery - Playwright, GraphQL, Sitemap Priority
# =============================================================================

class PlaywrightCrawler:
    """
    Playwright-based crawler for JavaScript-rendered content (SPA routes,
    dynamic forms, client-side navigation).

    Requires: playwright>=1.40.0 (install via: pip install playwright && playwright install chromium)
    """

    def __init__(self, target: str, max_pages: int = MAX_PAGES,
                 max_depth: int = MAX_DEPTH, timeout: int = PLAYWRIGHT_TIMEOUT,
                 wait_until: str = PLAYWRIGHT_WAIT_UNTIL, headless: bool = PLAYWRIGHT_HEADLESS):
        self.target = normalize_target(target)
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.timeout = timeout
        self.wait_until = wait_until
        self.headless = headless
        self._playwright = None
        self._browser = None
        self._page = None
        self.discovered_routes: Set[str] = set()
        self.discovered_graphql_endpoints: Set[str] = set()
        self.errors: List[str] = []

    def _init_playwright(self):
        """Lazy initialization of Playwright."""
        try:
            from playwright.sync_api import sync_playwright
            self._playwright = sync_playwright().start()
            self._browser = self._playwright.chromium.launch(headless=self.headless)
            self._page = self._browser.new_page()
            # Enable request/response interception for GraphQL detection
            self._page.on("request", self._on_request)
            self._page.on("response", self._on_response)
        except ImportError:
            self.errors.append("Playwright not installed. Run: pip install playwright && playwright install chromium")
            return False
        except Exception as e:
            self.errors.append(f"Playwright initialization failed: {e}")
            return False
        return True

    def _on_request(self, request):
        """Intercept requests to detect GraphQL endpoints."""
        url = request.url
        if "/graphql" in url.lower() or request.resource_type == "xhr":
            # Check for GraphQL content-type or query in body
            try:
                post_data = request.post_data
                if post_data and ("query" in post_data or "mutation" in post_data):
                    self.discovered_graphql_endpoints.add(url)
            except Exception:
                pass

    def _on_response(self, response):
        """Intercept responses for additional analysis."""
        # Could extract API endpoints from responses
        pass

    def crawl(self) -> List[DiscoveredTarget]:
        """Run the Playwright crawl and return discovered targets."""
        if not self._init_playwright():
            return []

        try:
            # Start from root
            self._navigate_and_extract(self.target, depth=0)

            # Also try to extract SPA routes from common patterns
            self._extract_spa_routes()

            # Convert discovered routes to DiscoveredTarget objects
            targets = []
            for route in self.discovered_routes:
                targets.append(DiscoveredTarget(
                    url=route,
                    method="get",
                    params=[],
                    source="playwright_spa",
                    title="SPA Route"
                ))

            for gql_endpoint in self.discovered_graphql_endpoints:
                targets.append(DiscoveredTarget(
                    url=gql_endpoint,
                    method="post",
                    params=["query", "variables", "operationName"],
                    source="playwright_graphql",
                    title="GraphQL Endpoint"
                ))

            return targets

        finally:
            self._cleanup()

    def _navigate_and_extract(self, url: str, depth: int):
        """Navigate to URL and extract links/routes."""
        if depth > self.max_depth or len(self.discovered_routes) >= self.max_pages:
            return

        if url in self.discovered_routes:
            return

        try:
            self._page.goto(url, wait_until=self.wait_until, timeout=self.timeout)
            self.discovered_routes.add(url)

            # Extract all links from the rendered page
            links = self._page.eval_on_selector_all("a[href]", "elements => elements.map(e => e.href)")
            for link in links:
                full = _strip_fragment(urljoin(url, link))
                if _same_origin(full, self.target) and not self._is_skip(full):
                    if full not in self.discovered_routes:
                        self._navigate_and_extract(full, depth + 1)

            # Also extract form actions
            forms = self._page.eval_on_selector_all("form", """
                forms => forms.map(f => ({
                    action: f.action || window.location.href,
                    method: (f.method || 'get').toLowerCase(),
                    fields: Array.from(f.querySelectorAll('input[name], textarea[name], select[name]'))
                        .map(i => i.name)
                }))
            """)
            for form in forms:
                form_url = _strip_fragment(urljoin(url, form["action"]))
                if _same_origin(form_url, self.target):
                    self.discovered_routes.add(form_url)

        except Exception as e:
            self.errors.append(f"Error crawling {url}: {e}")

    def _extract_spa_routes(self):
        """Extract SPA routes from common JavaScript frameworks."""
        try:
            # React Router v6: window.__REACT_ROUTER__
            # Vue Router: window.__VUE_ROUTER__ or router.options.routes
            # Next.js: __NEXT_DATA__.props.pageProps.__N_SSG
            # Generic: look for route definitions in scripts

            routes = self._page.evaluate("""
                () => {
                    const routes = new Set();

                    // React Router
                    if (window.__REACT_ROUTER__) {
                        try {
                            const matchRoutes = window.__REACT_ROUTER__.matchRoutes;
                            if (matchRoutes) {
                                matchRoutes.forEach(r => r.path && routes.add(r.path));
                            }
                        } catch {}
                    }

                    // Vue Router
                    if (window.__VUE_ROUTER__) {
                        try {
                            const router = window.__VUE_ROUTER__;
                            if (router.options && router.options.routes) {
                                router.options.routes.forEach(r => r.path && routes.add(r.path));
                            }
                        } catch {}
                    }

                    // Next.js
                    if (window.__NEXT_DATA__) {
                        try {
                            const data = window.__NEXT_DATA__;
                            if (data.props && data.props.pageProps) {
                                Object.keys(data.props.pageProps).forEach(k => {
                                    if (k.startsWith('/')) routes.add(k);
                                });
                            }
                        } catch {}
                    }

                    // Angular: try to find router config
                    if (window.ng && window.ng.getRouter) {
                        try {
                            const router = window.ng.getRouter();
                            router.config.forEach(r => r.path && routes.add(r.path));
                        } catch {}
                    }

                    // Generic: look for data-route or similar attributes
                    document.querySelectorAll('[data-route], [router-link], [href^="/"]').forEach(el => {
                        const href = el.getAttribute('href') || el.getAttribute('data-route') || '';
                        if (href.startsWith('/')) routes.add(href);
                    });

                    return Array.from(routes);
                }
            """)

            for route in routes:
                full = urljoin(self.target, route)
                if _same_origin(full, self.target) and not self._is_skip(full):
                    self.discovered_routes.add(full)

        except Exception as e:
            self.errors.append(f"Error extracting SPA routes: {e}")

    def _is_skip(self, url: str) -> bool:
        path = urlparse(url).path.lower()
        for ext in SKIP_EXTENSIONS:
            if path.endswith(ext):
                return True
        return False

    def _cleanup(self):
        """Clean up Playwright resources."""
        try:
            if self._page:
                self._page.close()
            if self._browser:
                self._browser.close()
            if self._playwright:
                self._playwright.stop()
        except Exception:
            pass


class SitemapDiscovery:
    """
    Enhanced sitemap discovery with priority sorting and deep sitemap index support.
    """

    def __init__(self, target: str, client: HTTPClient):
        self.target = normalize_target(target)
        self.client = client
        self.sitemap_urls: List[Dict] = []  # {url, priority, lastmod, changefreq}

    def discover(self) -> List[DiscoveredTarget]:
        """Discover URLs from sitemap.xml and sitemap index."""
        targets = []

        # Check for sitemap index first
        sitemap_index_url = urljoin(self.target, "/sitemap.xml")
        try:
            resp = self.client.get(sitemap_index_url)
            if resp.status_code == 200 and "xml" in resp.headers.get("Content-Type", "").lower():
                soup = BeautifulSoup(resp.text, "xml")

                # Check if it's a sitemap index
                sitemap_tags = soup.find_all("sitemap")
                if sitemap_tags:
                    # It's a sitemap index - fetch each sitemap
                    for sitemap in sitemap_tags:
                        loc = sitemap.find("loc")
                        if loc:
                            sitemap_url = loc.get_text().strip()
                            self._fetch_sitemap(sitemap_url, targets)
                else:
                    # It's a regular sitemap
                    self._fetch_sitemap(sitemap_index_url, targets)
        except Exception as e:
            pass  # Silently fail, sitemap is optional

        # Also check robots.txt for sitemap references
        self._check_robots_for_sitemaps(targets)

        # Sort by priority (highest first) and lastmod (newest first)
        targets.sort(key=lambda t: (
            -(t.get("priority", 0.5) if isinstance(t, dict) else 0.5),
            -(t.get("lastmod_timestamp", 0) if isinstance(t, dict) else 0)
        ))

        # Convert to DiscoveredTarget
        result = []
        for item in targets:
            if isinstance(item, dict):
                result.append(DiscoveredTarget(
                    url=item["url"],
                    method="get",
                    params=[],
                    source="sitemap_priority",
                    title=f"Priority: {item.get('priority', 0.5):.1f}"
                ))
            else:
                result.append(DiscoveredTarget(
                    url=item,
                    method="get",
                    params=[],
                    source="sitemap",
                    title=""
                ))

        return result

    def _fetch_sitemap(self, sitemap_url: str, targets: List):
        """Fetch and parse a single sitemap."""
        try:
            resp = self.client.get(sitemap_url)
            if resp.status_code != 200:
                return
            soup = BeautifulSoup(resp.text, "xml")
            for url_tag in soup.find_all("url"):
                loc = url_tag.find("loc")
                if not loc:
                    continue
                url = loc.get_text().strip()
                if not _same_origin(url, self.target):
                    continue

                # Extract metadata
                priority = 0.5
                lastmod = None
                lastmod_ts = 0
                changefreq = ""

                p = url_tag.find("priority")
                if p:
                    try:
                        priority = float(p.get_text().strip())
                    except:
                        pass

                lm = url_tag.find("lastmod")
                if lm:
                    lastmod = lm.get_text().strip()
                    try:
                        from datetime import datetime
                        lastmod_ts = datetime.fromisoformat(lastmod.replace('Z', '+00:00')).timestamp()
                    except:
                        pass

                cf = url_tag.find("changefreq")
                if cf:
                    changefreq = cf.get_text().strip()

                targets.append({
                    "url": _strip_fragment(url),
                    "priority": priority,
                    "lastmod": lastmod,
                    "lastmod_timestamp": lastmod_ts,
                    "changefreq": changefreq
                })
        except Exception:
            pass

    def _check_robots_for_sitemaps(self, targets: List):
        """Check robots.txt for sitemap declarations."""
        try:
            robots_url = urljoin(self.target, "/robots.txt")
            resp = self.client.get(robots_url)
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("sitemap:"):
                        sitemap_url = line.split(":", 1)[1].strip()
                        self._fetch_sitemap(sitemap_url, targets)
        except Exception:
            pass


class GraphQLIntrospection:
    """
    Detect and introspect GraphQL endpoints to generate query/mutation targets.
    """

    def __init__(self, target: str, client: HTTPClient):
        self.target = normalize_target(target)
        self.client = client
        self.endpoints: List[str] = []
        self.schema: Optional[Dict] = None

    def discover(self) -> List[DiscoveredTarget]:
        """Find GraphQL endpoints and introspect schema."""
        targets = []

        # Common GraphQL endpoint paths
        common_paths = [
            "/graphql", "/graphiql", "/api/graphql", "/v1/graphql",
            "/graphql/", "/api/graphql/", "/query", "/api/query",
        ]

        for path in common_paths:
            url = urljoin(self.target, path)
            if self._is_graphql_endpoint(url):
                self.endpoints.append(url)

        # Also check discovered endpoints from Playwright/crawl
        # (would be passed in from caller)

        for endpoint in self.endpoints:
            # Add the endpoint itself as a target
            targets.append(DiscoveredTarget(
                url=endpoint,
                method="post",
                params=["query", "variables", "operationName"],
                source="graphql_endpoint",
                title="GraphQL Endpoint"
            ))

            # Try introspection
            schema = self._introspect(endpoint)
            if schema:
                self.schema = schema
                # Generate targets for each query/mutation
                for op_type in ["query", "mutation"]:
                    for field_name, field_info in schema.get(op_type, {}).items():
                        targets.append(DiscoveredTarget(
                            url=endpoint,
                            method="post",
                            params=["query", "variables"],
                            source="graphql_introspection",
                            title=f"GraphQL {op_type}: {field_name}"
                        ))

        return targets

    def _is_graphql_endpoint(self, url: str) -> bool:
        """Check if URL is a GraphQL endpoint."""
        try:
            # Try introspection query
            query = {"query": "{ __schema { queryType { name } } }"}
            resp = self.client.post(url, json=query, headers={"Content-Type": "application/json"})
            if resp.status_code == 200:
                data = resp.json()
                return "data" in data and "__schema" in data.get("data", {})
        except Exception:
            pass
        return False

    def _introspect(self, url: str) -> Optional[Dict]:
        """Perform full GraphQL introspection."""
        try:
            introspection_query = """
            {
                __schema {
                    queryType { name }
                    mutationType { name }
                    types {
                        name
                        kind
                        fields {
                            name
                            args { name type { kind name ofType { kind name } } }
                            type { kind name ofType { kind name } }
                        }
                    }
                }
            }
            """
            resp = self.client.post(url, json={"query": introspection_query},
                                   headers={"Content-Type": "application/json"})
            if resp.status_code == 200:
                data = resp.json()
                if "data" in data and "__schema" in data["data"]:
                    return self._parse_schema(data["data"]["__schema"])
        except Exception:
            pass
        return None

    def _parse_schema(self, schema: Dict) -> Dict:
        """Parse introspection result into query/mutation map."""
        result = {"query": {}, "mutation": {}}
        query_type_name = schema.get("queryType", {}).get("name")
        mutation_type_name = schema.get("mutationType", {}).get("name")

        for type_def in schema.get("types", []):
            if type_def["name"] == query_type_name:
                for field in type_def.get("fields", []):
                    result["query"][field["name"]] = field
            elif type_def["name"] == mutation_type_name:
                for field in type_def.get("fields", []):
                    result["mutation"][field["name"]] = field
        return result


def discover_with_playwright(target: str, **kwargs) -> List[DiscoveredTarget]:
    """One-shot discovery using Playwright for JS-rendered content."""
    crawler = PlaywrightCrawler(target, **kwargs)
    return crawler.crawl()


def discover_sitemap_priority(target: str, client: HTTPClient) -> List[DiscoveredTarget]:
    """One-shot sitemap discovery with priority sorting."""
    sitemap = SitemapDiscovery(target, client)
    return sitemap.discover()


def discover_graphql(target: str, client: HTTPClient) -> List[DiscoveredTarget]:
    """One-shot GraphQL introspection discovery."""
    gql = GraphQLIntrospection(target, client)
    return gql.discover()


def enhanced_discover(target: str, **kwargs) -> List[DiscoveredTarget]:
    """
    Enhanced discovery combining all methods:
    - Static crawl (URLDiscovery)
    - Playwright SPA crawl (optional)
    - Sitemap priority discovery
    - GraphQL introspection
    """
    all_targets = []

    # 1. Static crawl (always runs)
    static_discovery = URLDiscovery(target, **kwargs)
    all_targets.extend(static_discovery.discover())

    # 2. Sitemap with priority (if enabled)
    if kwargs.get("crawl_sitemap", True):
        client = HTTPClient(timeout=kwargs.get("request_timeout", REQUEST_TIMEOUT),
                           delay=kwargs.get("request_delay", REQUEST_DELAY),
                           verify_ssl=kwargs.get("verify_ssl", False))
        sitemap_targets = discover_sitemap_priority(target, client)
        all_targets.extend(sitemap_targets)

    # 3. GraphQL introspection (if enabled)
    if kwargs.get("crawl_graphql", True):
        client = HTTPClient(timeout=kwargs.get("request_timeout", REQUEST_TIMEOUT),
                           delay=kwargs.get("request_delay", REQUEST_DELAY),
                           verify_ssl=kwargs.get("verify_ssl", False))
        gql_targets = discover_graphql(target, client)
        all_targets.extend(gql_targets)

    # 4. Playwright SPA crawl (if enabled and available)
    if kwargs.get("crawl_js_routes", True) and PLAYWRIGHT_ENABLED:
        try:
            pw_targets = discover_with_playwright(target, **kwargs)
            all_targets.extend(pw_targets)
        except Exception:
            pass  # Playwright not available or failed

    # Deduplicate
    seen = set()
    deduped = []
    for t in all_targets:
        if t.url not in seen:
            seen.add(t.url)
            deduped.append(t)

    return deduped
