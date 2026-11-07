#!/bin/sh
set -e
export HOME=/tmp
ollama serve >/tmp/ollama.log 2>&1 &
exec python /app/tinfoil_server.py
