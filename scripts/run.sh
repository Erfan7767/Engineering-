#!/bin/bash
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
echo "🚀 Starting NetOps Autopilot REAL..."
echo "Backend on :8000, Frontend on :5173"
cd "$ROOT/backend"
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload &
B_PID=$!
cd "$ROOT/frontend"
npm run dev &
F_PID=$!
wait $B_PID $F_PID
