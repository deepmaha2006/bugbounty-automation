#!/bin/sh
# HydraX connector container entrypoint.
# 1. Start nginx (WAF proxy to victim).
# 2. Wait for hydrax-api to be ready.
# 3. Enroll if no identity exists yet (reads token from /connector-home/enrollment.token).
# 4. Run the agent poll loop.

set -e

HYDRAX_API="${HYDRAX_API:-http://hydrax-api:8000}"
IDENTITY_FILE="${HYDRAX_CONNECTOR_HOME:-/connector-home}/.hydrax-connector/identity.json"
TOKEN_FILE="${HYDRAX_CONNECTOR_HOME:-/connector-home}/enrollment.token"

# Create the nginx WAF include directory if it doesn't exist.
mkdir -p /hydrax-waf-rules

# Nginx needs an empty wildcard include to start cleanly even before any rules exist.
touch /hydrax-waf-rules/.gitkeep

# Start nginx in the background.
nginx &

# Wait for hydrax-api to be ready.
echo "Waiting for hydrax-api at $HYDRAX_API ..."
for i in $(seq 1 60); do
    if curl -sf "${HYDRAX_API}/api/health" > /dev/null 2>&1; then
        echo "hydrax-api is ready."
        break
    fi
    sleep 2
    if [ "$i" = "60" ]; then
        echo "ERROR: hydrax-api did not become ready in 120s." >&2
        exit 1
    fi
done

# Enroll if no identity exists yet.
if [ ! -f "$IDENTITY_FILE" ]; then
    if [ ! -f "$TOKEN_FILE" ]; then
        echo "No enrollment token at $TOKEN_FILE — seed.py must run first." >&2
        # Wait for seed to drop the token (retries for 5 minutes).
        for i in $(seq 1 150); do
            sleep 2
            if [ -f "$TOKEN_FILE" ]; then break; fi
        done
    fi
    TOKEN=$(cat "$TOKEN_FILE")
    echo "Enrolling connector with token ..."
    HYDRAX_CONNECTOR_HOME="${HYDRAX_CONNECTOR_HOME:-/connector-home}" \
        python /app/connector/agent.py enroll \
            --server "$HYDRAX_API" \
            --token "$TOKEN" \
            --name lab-connector
fi

echo "Starting connector agent loop ..."
exec python /app/connector/agent.py run
