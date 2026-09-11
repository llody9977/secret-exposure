#!/usr/bin/env bash
set -e

echo "Starting SPIRE Agent entrypoint..."
mkdir -p /run/spire/agent-data /tmp/spire-agent/public

while [ ! -f "/spire/agent-token.txt" ] && [ ! -f "/run/spire/agent-data/keys.json" ]; do
  sleep 1
done

if [ -f "/spire/agent-token.txt" ] && [ ! -f "/run/spire/agent-data/keys.json" ]; then
  TOKEN=$(cat /spire/agent-token.txt)
  rm -f /spire/agent-token.txt
  echo "Attesting SPIRE Agent with join token..."
  exec spire-agent run -config /spire/agent.conf -joinToken "$TOKEN"
fi

echo "Starting SPIRE Agent with existing credentials..."
exec spire-agent run -config /spire/agent.conf
