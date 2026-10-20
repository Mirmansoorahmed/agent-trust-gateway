#!/bin/sh
# MCP servers start only after the gateway has written its public key.
key="${ATG_GATEWAY_PUBLIC_KEY_FILE:-/data/gateway_public.pem}"
i=0
while [ ! -s "$key" ]; do
  i=$((i + 1))
  if [ "$i" -gt 60 ]; then
    echo "timed out waiting for $key" >&2
    exit 1
  fi
  sleep 1
done
exec python -m servers.run "${ATG_SERVER:?set ATG_SERVER}"
