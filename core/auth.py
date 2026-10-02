"""
Authentication Manager for Bug Bounty Professional.

Provides session persistence, cookie jar management, token refresh,
form-login flow, OAuth2 client credentials, and JWT handling.
All auth state is bound to the current scan context via thread-local storage.
"""

import json
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests
from requests.cookies import RequestsCookieJar

from utils.http_client import HTTPClient
from core.scan_context import get_scan_context, set_scan_context


# Thread-local storage for auth state per worker thread
_auth_local = threading.local()


@dataclass
class AuthConfig:
    """Configuration for a single authentication method."""

    # Method type: "form", "oauth2", "jwt", "session", "header"
    method: str = "form"

    # Form-based login
    login_url: str = ""
    username_field: str = "username"
    password_field: str = "password"
    username: str = ""
    password: str = ""
    csrf_field: str = ""           # optional: field name for CSRF token
    csrf_selector: str = ""        # optional: CSS selector to extract CSRF from login page
    extra_form_fields: Dict[str, str] = field(default_factory=dict)

    # OAuth2 Client Credentials
    token_url: str = ""
    client_id: str = ""
    client_secret: str = ""
    scopes: List[str] = field(default_factory=list)
    audience: str = ""

    # JWT
    jwt_token: str = ""
    jwt_header: str = "Authorization"
    jwt_prefix: str = "Bearer"

    # Session reuse (cookies + headers)
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)

    # General
    verify_ssl: bool = False
    timeout: int = 30
    retry_on_401: bool = True      # auto re-auth on 401

    def to_dict(self) -> Dict[str, Any]:
        return {
            "method": self.method,
            "login_url": self.login_url,
            "username_field": self.username_field,
            "password_field": self.password_field,
            "username": self.username,
            "password": self.password,  # caller should redact before logging
            "csrf_field": self.csrf_field,
            "csrf_selector": self.csrf_selector,
            "extra_form_fields": self.extra_form_fields,
            "token_url": self.token_url,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scopes": self.scopes,
            "audience": self.audience,
            "jwt_token": self.jwt_token,
            "jwt_header": self.jwt_header,
            "jwt_prefix": self.jwt_prefix,
            "cookies": self.cookies,
            "headers": self.headers,
            "verify_ssl": self.verify_ssl,
            "timeout": self.timeout,
            "retry_on_401": self.retry_on_401,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuthConfig":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class AuthState:
    """Runtime authentication state for a scan."""

    config: AuthConfig
    session: requests.Session = field(default_factory=requests.Session)
    access_token: str = ""
    token_expires_at: float = 0
    csrf_token: str = ""
    authenticated: bool = False
    last_login_at: float = 0

    def get_cookie_jar(self) -> RequestsCookieJar:
        return self.session.cookies

    def get_auth_headers(self) -> Dict[str, str]:
        """Return headers to attach to every request."""
        headers = dict(self.config.headers)
        if self.config.method == "jwt" and self.config.jwt_token:
            headers[self.config.jwt_header] = f"{self.config.jwt_prefix} {self.config.jwt_token}"
        elif self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"
        elif self.csrf_token and self.config.csrf_field:
            # Some APIs expect CSRF in header
            headers["X-CSRF-Token"] = self.csrf_token
        return headers

    def is_token_expired(self) -> bool:
        import time
        return self.access_token and time.time() >= self.token_expires_at - 60  # 60s buffer


def _get_auth_state() -> Optional[AuthState]:
    return getattr(_auth_local, "auth_state", None)


def _set_auth_state(state: Optional[AuthState]) -> None:
    if state is None:
        try:
            delattr(_auth_local, "auth_state")
        except AttributeError:
            pass
    else:
        _auth_local.auth_state = state


class AuthManager:
    """
    Manages authentication for a scan run.

    Usage:
        auth = AuthManager(config)
        auth.login()  # or auth.authenticate()
        # Then use auth.client.get/post which auto-attaches auth
        # Or get headers via auth.get_headers() for custom requests
    """

    def __init__(self, config: AuthConfig):
        self.config = config
        self._state: Optional[AuthState] = None
        self._client: Optional[HTTPClient] = None

    @property
    def client(self) -> HTTPClient:
        """HTTP client with auth automatically applied."""
        if self._client is None:
            self._client = HTTPClient(
                timeout=self.config.timeout,
                verify_ssl=self.config.verify_ssl,
            )
            # Monkey-patch to inject auth
            original_get = self._client.get
            original_post = self._client.post

            def authed_get(url, **kwargs):
                headers = kwargs.pop("headers", {})
                headers.update(self.get_headers())
                return original_get(url, headers=headers, **kwargs)

            def authed_post(url, **kwargs):
                headers = kwargs.pop("headers", {})
                headers.update(self.get_headers())
                return original_post(url, headers=headers, **kwargs)

            self._client.get = authed_get
            self._client.post = authed_post
        return self._client

    def get_state(self) -> Optional[AuthState]:
        return self._state

    def get_headers(self) -> Dict[str, str]:
        if self._state:
            return self._state.get_auth_headers()
        return dict(self.config.headers)

    def get_cookies(self) -> RequestsCookieJar:
        if self._state:
            return self._state.get_cookie_jar()
        jar = RequestsCookieJar()
        for k, v in self.config.cookies.items():
            jar.set(k, v)
        return jar

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def authenticate(self) -> bool:
        """Run the appropriate authentication flow based on config.method."""
        if self.config.method == "form":
            return self.login_form()
        elif self.config.method == "oauth2":
            return self.login_oauth2()
        elif self.config.method == "jwt":
            return self.use_jwt()
        elif self.config.method == "session":
            return self.use_session()
        elif self.config.method == "header":
            return self.use_header_auth()
        else:
            raise ValueError(f"Unknown auth method: {self.config.method}")

    def login_form(self) -> bool:
        """Perform form-based login with optional CSRF token extraction."""
        import time
        if not self.config.login_url:
            raise ValueError("login_url required for form auth")

        self._state = AuthState(config=self.config)

        # Step 1: GET login page to extract CSRF if needed
        csrf_token = ""
        if self.config.csrf_selector:
            try:
                resp = self._client.get(self.config.login_url)
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(resp.text, "html.parser")
                el = soup.select_one(self.config.csrf_selector)
                if el:
                    csrf_token = el.get("value") or el.get("content") or el.text.strip()
            except Exception:
                pass

        # Also check for CSRF in cookies
        if not csrf_token:
            for cookie in self._state.session.cookies:
                if "csrf" in cookie.name.lower() or "xsrf" in cookie.name.lower():
                    csrf_token = cookie.value
                    break

        # Step 2: POST credentials
        form_data = {
            self.config.username_field: self.config.username,
            self.config.password_field: self.config.password,
        }
        form_data.update(self.config.extra_form_fields)
        if self.config.csrf_field and csrf_token:
            form_data[self.config.csrf_field] = csrf_token

        try:
            resp = self._state.session.post(
                self.config.login_url,
                data=form_data,
                headers=self._state.get_auth_headers(),
                timeout=self.config.timeout,
                verify=self.config.verify_ssl,
                allow_redirects=True,
            )
        except Exception as e:
            self._state.authenticated = False
            raise RuntimeError(f"Form login request failed: {e}")

        # Step 3: Verify login success
        success = self._verify_login_response(resp)
        if success:
            self._state.authenticated = True
            self._state.last_login_at = time.time()
            self._state.csrf_token = csrf_token
            # Persist cookies from response
            self._state.session.cookies.update(resp.cookies)
            _set_auth_state(self._state)
            return True

        self._state.authenticated = False
        return False

    def login_oauth2(self) -> bool:
        """OAuth2 Client Credentials flow."""
        import time
        if not self.config.token_url or not self.config.client_id or not self.config.client_secret:
            raise ValueError("token_url, client_id, client_secret required for oauth2")

        self._state = AuthState(config=self.config)

        data = {
            "grant_type": "client_credentials",
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
        }
        if self.config.scopes:
            data["scope"] = " ".join(self.config.scopes)
        if self.config.audience:
            data["audience"] = self.config.audience

        try:
            resp = self._state.session.post(
                self.config.token_url,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=self.config.timeout,
                verify=self.config.verify_ssl,
            )
        except Exception as e:
            raise RuntimeError(f"OAuth2 token request failed: {e}")

        if resp.status_code != 200:
            raise RuntimeError(f"OAuth2 token request failed: {resp.status_code} {resp.text}")

        token_data = resp.json()
        self._state.access_token = token_data.get("access_token", "")
        expires_in = token_data.get("expires_in", 3600)
        self._state.token_expires_at = time.time() + expires_in
        self._state.authenticated = bool(self._state.access_token)
        self._state.last_login_at = time.time()
        _set_auth_state(self._state)
        return self._state.authenticated

    def use_jwt(self) -> bool:
        """Use a static JWT token."""
        if not self.config.jwt_token:
            raise ValueError("jwt_token required for jwt auth")

        self._state = AuthState(config=self.config)
        self._state.access_token = self.config.jwt_token
        self._state.authenticated = True
        _set_auth_state(self._state)
        return True

    def use_session(self) -> bool:
        """Reuse existing session cookies and headers."""
        self._state = AuthState(config=self.config)
        # Pre-populate cookies
        for k, v in self.config.cookies.items():
            self._state.session.cookies.set(k, v)
        self._state.authenticated = True
        _set_auth_state(self._state)
        return True

    def use_header_auth(self) -> bool:
        """Use custom headers (e.g., API key in header)."""
        self._state = AuthState(config=self.config)
        self._state.authenticated = True
        _set_auth_state(self._state)
        return True

    def refresh_if_needed(self) -> bool:
        """Refresh token if expired (OAuth2 only)."""
        if not self._state or not self._state.authenticated:
            return False
        if self.config.method == "oauth2" and self._state.is_token_expired():
            return self.login_oauth2()
        if self.config.method == "form" and self.config.retry_on_401:
            # For form auth, we'd need to re-login; caller handles 401 retry
            pass
        return True

    def handle_response(self, response: requests.Response) -> bool:
        """
        Check response for auth failure (401/403) and optionally re-authenticate.
        Returns True if caller should retry the request.
        """
        if response.status_code in (401, 403) and self.config.retry_on_401:
            if self.config.method == "oauth2":
                if self.login_oauth2():
                    return True
            elif self.config.method == "form":
                if self.login_form():
                    return True
        return False

    def _verify_login_response(self, response: requests.Response) -> bool:
        """Heuristic: login succeeded if we get a session cookie or redirect away from login page."""
        # Check for session cookies set
        if response.cookies:
            for cookie in response.cookies:
                if any(kw in cookie.name.lower() for kw in ("session", "auth", "token", "sid", "csrf", "xsrf")):
                    return True

        # Check for redirect away from login page
        if response.url != self.config.login_url and not response.url.endswith("/login"):
            return True

        # Check for success indicators in body
        text = response.text.lower()
        if any(kw in text for kw in ("logout", "sign out", "dashboard", "welcome", "profile")):
            return True

        # If status is 200 but we're still on login page, likely failed
        if response.status_code == 200 and "login" in response.url:
            return False

        return response.status_code in (200, 302, 303)

    # ------------------------------------------------------------------
    # Context binding for scan engine integration
    # ------------------------------------------------------------------
    def bind_to_context(self) -> None:
        """Bind this auth state to the current scan context (thread-local)."""
        if self._state:
            ctx = get_scan_context()
            if ctx:
                ctx.auth_state = self._state
            _set_auth_state(self._state)

    @staticmethod
    def get_current_state() -> Optional[AuthState]:
        """Get auth state from current thread's scan context or thread-local."""
        ctx = get_scan_context()
        if ctx and hasattr(ctx, "auth_state") and ctx.auth_state:
            return ctx.auth_state
        return _get_auth_state()

    @staticmethod
    def get_current_headers() -> Dict[str, str]:
        state = AuthManager.get_current_state()
        if state:
            return state.get_auth_headers()
        return {}

    @staticmethod
    def get_current_cookies() -> RequestsCookieJar:
        state = AuthManager.get_current_state()
        if state:
            return state.get_cookie_jar()
        return RequestsCookieJar()


# ----------------------------------------------------------------------
# Convenience functions for scanner integration
# ----------------------------------------------------------------------
def create_authenticated_client(auth_config: AuthConfig) -> HTTPClient:
    """Create an HTTPClient with authentication pre-configured."""
    auth = AuthManager(auth_config)
    auth.authenticate()
    return auth.client


def apply_auth_to_request(
    url: str,
    headers: Dict[str, str],
    cookies: Dict[str, str],
    auth_config: Optional[AuthConfig] = None,
) -> Tuple[Dict[str, str], Dict[str, str]]:
    """Apply auth headers/cookies to a request (used by scanners)."""
    merged_headers = dict(headers)
    merged_cookies = dict(cookies)

    if auth_config:
        auth = AuthManager(auth_config)
        if not auth._state or not auth._state.authenticated:
            auth.authenticate()
        merged_headers.update(auth.get_headers())
        for k, v in auth.get_cookies().items():
            merged_cookies[k] = v
    else:
        # Fall back to thread-local/context auth
        merged_headers.update(AuthManager.get_current_headers())
        for k, v in AuthManager.get_current_cookies().items():
            merged_cookies[k] = v

    return merged_headers, merged_cookies