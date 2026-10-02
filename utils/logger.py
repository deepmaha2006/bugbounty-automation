"""
Structured JSONL Logging System for Bug Bounty Professional.

Provides high-performance async JSONL logging with correlation ID propagation,
multiple handlers, and structured logging helpers.
"""

import asyncio
import json
import logging
import sys
import time
import uuid
from contextvars import ContextVar
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, Optional, List, Callable, Union
from contextlib import contextmanager

from config import settings

# Context variables for correlation ID propagation
correlation_id_var: ContextVar[Optional[str]] = ContextVar('correlation_id', default=None)
session_id_var: ContextVar[Optional[str]] = ContextVar('session_id', default=None)
scanner_key_var: ContextVar[Optional[str]] = ContextVar('scanner_key', default=None)
phase_var: ContextVar[Optional[str]] = ContextVar('phase', default=None)
target_url_var: ContextVar[Optional[str]] = ContextVar('target_url', default=None)


class LogLevel(Enum):
    """Log levels."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class LogPhase(Enum):
    """Scan phases."""
    DISCOVERY = "discovery"
    SCANNING = "scanning"
    VERIFICATION = "verification"
    REPORTING = "reporting"
    INITIALIZATION = "initialization"
    CLEANUP = "cleanup"


@dataclass
class LogRecord:
    """Structured log record for JSONL output."""
    timestamp: str
    level: str
    logger_name: str
    message: str
    correlation_id: Optional[str] = None
    session_id: Optional[str] = None
    scanner_key: Optional[str] = None
    phase: Optional[str] = None
    target_url: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(asdict(self), separators=(',', ':'), ensure_ascii=False)


class JSONLFormatter(logging.Formatter):
    """Formatter that outputs JSONL records."""

    def format(self, record: logging.LogRecord) -> str:
        # Extract structured fields from record
        extra = getattr(record, 'extra_fields', {})
        log_record = LogRecord(
            timestamp=datetime.now(timezone.utc).isoformat(),
            level=record.levelname,
            logger_name=record.name,
            message=record.getMessage(),
            correlation_id=correlation_id_var.get(),
            session_id=session_id_var.get(),
            scanner_key=scanner_key_var.get(),
            phase=phase_var.get(),
            target_url=target_url_var.get(),
            extra=extra,
        )
        return log_record.to_json()


class ConsoleFormatter(logging.Formatter):
    """Human-readable console formatter with colors."""

    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
        'RESET': '\033[0m',
    }

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, '')
        reset = self.COLORS['RESET']

        # Build context string
        ctx_parts = []
        if corr := correlation_id_var.get():
            ctx_parts.append(f"corr={corr[:8]}")
        if sess := session_id_var.get():
            ctx_parts.append(f"sess={sess[:8]}")
        if scan := scanner_key_var.get():
            ctx_parts.append(f"scanner={scan}")
        if ph := phase_var.get():
            ctx_parts.append(f"phase={ph}")

        ctx_str = f" [{', '.join(ctx_parts)}]" if ctx_parts else ""

        return f"{color}{datetime.now().strftime('%H:%M:%S')}{reset} {record.levelname:<8} {record.name}{ctx_str} - {record.getMessage()}"


class AsyncFileHandler(logging.Handler):
    """Async file handler with buffering for high-throughput logging."""

    def __init__(self, filepath: Union[str, Path], max_bytes: int = 100_000_000, backup_count: int = 10, buffer_size: int = 1000):
        super().__init__()
        self.filepath = Path(filepath)
        self.filepath.parent.mkdir(parents=True, exist_ok=True)
        self.max_bytes = max_bytes
        self.backup_count = backup_count
        self.buffer_size = buffer_size
        self._buffer: List[str] = []
        self._buffer_lock = asyncio.Lock()
        self._file_handle = None
        self._write_task: Optional[asyncio.Task] = None
        self._shutdown = False
        self._rotate_lock = asyncio.Lock()

    def emit(self, record: logging.LogRecord):
        """Buffer the record for async writing."""
        try:
            msg = self.format(record)
            self._buffer.append(msg)
            if len(self._buffer) >= self.buffer_size:
                self._flush_buffer_sync()
        except Exception:
            self.handleError(record)

    def _flush_buffer_sync(self):
        """Synchronous buffer flush (for emergency)."""
        if not self._buffer:
            return
        try:
            with open(self.filepath, 'a', encoding='utf-8') as f:
                for line in self._buffer:
                    f.write(line + '\n')
            self._buffer.clear()
            self._maybe_rotate()
        except Exception as e:
            print(f"Log write error: {e}", file=sys.stderr)

    async def _flush_buffer_async(self):
        """Async buffer flush."""
        async with self._buffer_lock:
            if not self._buffer:
                return
            try:
                async with self._rotate_lock:
                    # Use thread pool for file I/O
                    loop = asyncio.get_event_loop()
                    await loop.run_in_executor(None, self._flush_buffer_sync)
            except Exception as e:
                print(f"Async log write error: {e}", file=sys.stderr)

    def _maybe_rotate(self):
        """Rotate log file if needed."""
        try:
            if self.filepath.exists() and self.filepath.stat().st_size >= self.max_bytes:
                # Rotate files
                for i in range(self.backup_count - 1, 0, -1):
                    src = self.filepath.with_suffix(f'.{i}')
                    dst = self.filepath.with_suffix(f'.{i + 1}')
                    if src.exists():
                        src.rename(dst)
                self.filepath.rename(self.filepath.with_suffix('.1'))
        except Exception as e:
            print(f"Log rotation error: {e}", file=sys.stderr)

    async def start(self):
        """Start the async flush task."""
        self._shutdown = False
        self._write_task = asyncio.create_task(self._periodic_flush())

    async def stop(self):
        """Stop and flush remaining buffer."""
        self._shutdown = True
        if self._write_task:
            await self._write_task
        await self._flush_buffer_async()

    async def _periodic_flush(self):
        """Periodically flush buffer."""
        while not self._shutdown:
            await asyncio.sleep(1.0)
            await self._flush_buffer_async()


class StructuredLogger:
    """
    High-level structured logger with convenience methods.
    """

    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
        self.name = name

    def _log(self, level: LogLevel, message: str, **extra):
        """Internal log method with extra fields."""
        extra_fields = {k: v for k, v in extra.items() if v is not None}
        self.logger.log(level.value, message, extra={'extra_fields': extra_fields})

    def debug(self, message: str, **extra):
        self._log(LogLevel.DEBUG, message, **extra)

    def info(self, message: str, **extra):
        self._log(LogLevel.INFO, message, **extra)

    def warning(self, message: str, **extra):
        self._log(LogLevel.WARNING, message, **extra)

    def error(self, message: str, **extra):
        self._log(LogLevel.ERROR, message, **extra)

    def critical(self, message: str, **extra):
        self._log(LogLevel.CRITICAL, message, **extra)

    # Structured logging helpers
    def log_finding(self, finding: Any, session_id: str = None, correlation_id: str = None):
        """Log a vulnerability finding."""
        finding_data = {}
        if hasattr(finding, 'to_dict'):
            finding_data = finding.to_dict()
        elif hasattr(finding, '__dict__'):
            finding_data = {k: v for k, v in finding.__dict__.items() if not k.startswith('_')}

        self.info(
            f"Finding: {finding_data.get('type', 'Unknown')} at {finding_data.get('url', 'N/A')}",
            finding_type=finding_data.get('type'),
            finding_severity=finding_data.get('severity'),
            finding_url=finding_data.get('url'),
            finding_confidence=finding_data.get('confidence'),
            session_id=session_id or session_id_var.get(),
            correlation_id=correlation_id or correlation_id_var.get(),
        )

    def log_scan_event(self, event_type: str, session_id: str = None, details: Dict = None):
        """Log a scan lifecycle event."""
        self.info(
            f"Scan event: {event_type}",
            event_type=event_type,
            session_id=session_id or session_id_var.get(),
            details=details or {},
        )

    def log_error(self, error: Exception, context: Dict = None):
        """Log an error with context."""
        self.error(
            f"Error: {type(error).__name__}: {error}",
            error_type=type(error).__name__,
            error_message=str(error),
            context=context or {},
        )

    def log_performance(self, operation: str, duration_ms: float, metadata: Dict = None):
        """Log performance timing."""
        self.info(
            f"Performance: {operation} took {duration_ms:.2f}ms",
            operation=operation,
            duration_ms=duration_ms,
            metadata=metadata or {},
        )

    def log_request(self, method: str, url: str, status: int = None, duration_ms: float = None):
        """Log HTTP request."""
        self.debug(
            f"HTTP {method} {url}" + (f" -> {status}" if status else ""),
            http_method=method,
            http_url=url,
            http_status=status,
            http_duration_ms=duration_ms,
        )

    def log_rate_limit(self, host: str, rate: float, tokens: float, action: str):
        """Log rate limiter action."""
        self.debug(
            f"Rate limit {action} for {host}: rate={rate:.2f}, tokens={tokens:.2f}",
            rate_limit_host=host,
            rate_limit_rate=rate,
            rate_limit_tokens=tokens,
            rate_limit_action=action,
        )


# Global logger registry
_loggers: Dict[str, StructuredLogger] = {}


def get_logger(name: str) -> StructuredLogger:
    """Get or create a structured logger."""
    if name not in _loggers:
        _loggers[name] = StructuredLogger(name)
    return _loggers[name]


@contextmanager
def correlation_id(corr_id: str = None):
    """Context manager for correlation ID."""
    cid = corr_id or str(uuid.uuid4())[:12]
    token = correlation_id_var.set(cid)
    try:
        yield cid
    finally:
        correlation_id_var.reset(token)


@contextmanager
def session_context(session_id: str = None):
    """Context manager for scan session ID."""
    sid = session_id or f"scan-{int(time.time())}-{str(uuid.uuid4())[:8]}"
    token = session_id_var.set(sid)
    try:
        yield sid
    finally:
        session_id_var.reset(token)


@contextmanager
def scanner_context(scanner_key: str):
    """Context manager for scanner key."""
    token = scanner_key_var.set(scanner_key)
    try:
        yield
    finally:
        scanner_key_var.reset(token)


@contextmanager
def phase_context(phase: str):
    """Context manager for scan phase."""
    token = phase_var.set(phase)
    try:
        yield
    finally:
        phase_var.reset(token)


@contextmanager
def target_context(target_url: str):
    """Context manager for target URL."""
    token = target_url_var.set(target_url)
    try:
        yield
    finally:
        target_url_var.reset(token)


@contextmanager
def scan_context(session_id: str = None, correlation_id: str = None, target_url: str = None):
    """Combined context manager for a full scan."""
    with session_context(session_id) as sid:
        with correlation_id(correlation_id) as cid:
            if target_url:
                with target_context(target_url):
                    yield sid, cid
            else:
                yield sid, cid


def configure_logging(
    level: str = None,
    log_file: str = None,
    console: bool = True,
    json_file: bool = True,
    max_bytes: int = 100_000_000,
    backup_count: int = 10,
) -> List[logging.Handler]:
    """
    Configure application logging.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path to log file (JSONL format)
        console: Enable console output
        json_file: Enable JSONL file output
        max_bytes: Max file size before rotation
        backup_count: Number of backup files to keep

    Returns:
        List of configured handlers
    """
    # Get level from settings or parameter
    log_level = getattr(settings, 'LOG_LEVEL', level or 'INFO')
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)

    # Clear existing handlers
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.setLevel(numeric_level)

    handlers = []

    # Console handler
    if console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(ConsoleFormatter())
        console_handler.setLevel(numeric_level)
        root_logger.addHandler(console_handler)
        handlers.append(console_handler)

    # JSONL file handler
    if json_file and log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = AsyncFileHandler(
            filepath=log_path,
            max_bytes=max_bytes,
            backup_count=backup_count,
        )
        file_handler.setFormatter(JSONLFormatter())
        file_handler.setLevel(numeric_level)
        root_logger.addHandler(file_handler)
        handlers.append(file_handler)

        # Start async flush
        loop = asyncio.get_event_loop()
        if loop.is_running():
            loop.create_task(file_handler.start())
        else:
            loop.run_until_complete(file_handler.start())

    # Configure specific logger levels
    _configure_component_loggers(numeric_level)

    return handlers


def _configure_component_loggers(root_level: int):
    """Configure log levels for specific components."""
    component_levels = {
        'scanners': logging.INFO,
        'discovery': logging.INFO,
        'rate_limiter': logging.WARNING,
        'verifier': logging.INFO,
        'http_client': logging.WARNING,  # DEBUG only when needed
        'asyncio': logging.WARNING,
        'aiohttp': logging.WARNING,
        'urllib3': logging.WARNING,
    }

    for name, level in component_levels.items():
        logger = logging.getLogger(name)
        logger.setLevel(max(level, root_level))


async def shutdown_logging(handlers: List[logging.Handler]):
    """Gracefully shutdown logging handlers."""
    for handler in handlers:
        if isinstance(handler, AsyncFileHandler):
            await handler.stop()
        handler.close()


# Convenience function for quick setup
def setup_logging(
    log_file: str = None,
    level: str = None,
    console: bool = True,
) -> List[logging.Handler]:
    """Quick logging setup with defaults."""
    if log_file is None:
        log_dir = Path(getattr(settings, 'REPORTS_DIR', 'reports')) / 'logs'
        log_file = str(log_dir / f"scan-{datetime.now().strftime('%Y%m%d-%H%M%S')}.jsonl")

    return configure_logging(
        level=level or getattr(settings, 'LOG_LEVEL', 'INFO'),
        log_file=log_file,
        console=console,
        json_file=True,
    )


# Integration with stdlib logging
class StructuredLogAdapter(logging.LoggerAdapter):
    """LoggerAdapter that adds structured context."""

    def process(self, msg, kwargs):
        extra = kwargs.get('extra', {})
        extra['extra_fields'] = extra.get('extra_fields', {})
        return msg, kwargs


def get_structured_logger(name: str) -> StructuredLogAdapter:
    """Get a logger adapter with structured context support."""
    return StructuredLogAdapter(logging.getLogger(name), {})


# Example usage and testing
if __name__ == "__main__":
    # Demo
    handlers = setup_logging(level="DEBUG")
    log = get_logger("demo")

    with scan_context(target_url="https://example.com") as (sid, cid):
        log.info("Scan started")
        log.log_finding(type="XSS", url="https://example.com/search", severity="High", confidence=0.9)
        log.log_scan_event("discovery_complete", details={"pages": 50, "forms": 12})
        log.log_performance("crawl", 1250.5, {"pages": 50})

        with scanner_context("xss"):
            log.info("XSS scanner running")
            log.log_request("GET", "https://example.com/search?q=test", 200, 45.2)

    # Cleanup
    import asyncio
    asyncio.run(shutdown_logging(handlers))