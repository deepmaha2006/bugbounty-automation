# HydraX — FastAPI platform + scanner toolchain image (spec §26).
#
# Base: Kali Linux (docs/CLAUDE.md's own "Environment Requirements" —
# nmap/nikto/whatweb/dirb/wfuzz and friends are Kali packages; using
# anything else means separately packaging each tool by hand). Multi-stage
# so the final image doesn't carry apt's build caches/lists.
#
# NOT build-tested in this sandbox (no Docker available here, same
# real-infrastructure caveat as Postgres/Redis/Celery throughout
# docs/ROADMAP.md) — verify `docker build` succeeds and every tool in
# webapp/services/kali_tools.py::tool_status()'s list actually resolves via
# `docker run --rm hydrax python -c "from webapp.services import
# kali_tools; print(kali_tools.tool_status())"` before first production use.
#
# Build:  docker build -t hydrax .
# Run:    docker run --rm -p 8000:8000 --env-file .env hydrax

FROM kalilinux/kali-rolling AS base

ARG DEBIAN_FRONTEND=noninteractive

# --- OS packages: Python + the scanner toolchain kali_tools.py shells out to.
# ProjectDiscovery tools (nuclei/subfinder/amass/httpx) are packaged under
# kali-tools-web in recent Kali; httpx's apt package is named httpx-toolkit
# to avoid colliding with the unrelated Python "httpx" package.
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv \
        nmap masscan sqlmap nikto gobuster ffuf wfuzz dirb hydra \
        whatweb dnsrecon curl openssl \
        nuclei subfinder amass httpx-toolkit \
        ca-certificates \
    && ln -sf /usr/bin/httpx-toolkit /usr/local/bin/httpx \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN python3 -m pip install --no-cache-dir --break-system-packages -r requirements.txt \
    && python3 -m playwright install --with-deps chromium

COPY . .

# Non-root: the platform's own SECURITY_MODEL.md expects least-privilege
# execution, not just least-privilege data access.
RUN useradd --create-home --shell /bin/bash hydrax \
    && mkdir -p /app/webapp/data/reports /app/webapp/data/uploads \
    && chown -R hydrax:hydrax /app
USER hydrax

ENV HYDRAX_HOST=0.0.0.0 \
    HYDRAX_PORT=8000 \
    PYTHONUNBUFFERED=1

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${HYDRAX_PORT}/healthz" || exit 1

CMD ["sh", "-c", "uvicorn webapp.main:app --host ${HYDRAX_HOST} --port ${HYDRAX_PORT}"]
