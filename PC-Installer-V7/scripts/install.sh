#!/bin/bash
set -e
echo "📦 Installing backend..."
cd "$(dirname "$0")/../backend"
pip install -r requirements.txt
echo "📦 Installing frontend..."
cd ../frontend
npm install
echo "✅ Done"
