#!/bin/bash
# ─── UEBA System Startup Script (Linux/Ubuntu) ───
# Usage:
#   bash scripts/start.sh              # Quick start with existing models
#   bash scripts/start.sh --train      # Train models first, then start
#   bash scripts/start.sh --demo       # Run demo, then start
#   bash scripts/start.sh --docker     # Start via Docker Compose

set -e

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR"

echo "╔══════════════════════════════════════════════════╗"
echo "║   UEBA - User & Entity Behavior Analytics       ║"
echo "║   Version 2.0                                   ║"
echo "╚══════════════════════════════════════════════════╝"

# ─── Parse args ───
TRAIN=false
DEMO=false
DOCKER=false

for arg in "$@"; do
    case $arg in
        --train) TRAIN=true ;;
        --demo) DEMO=true ;;
        --docker) DOCKER=true ;;
    esac
done

# ─── Docker mode ───
if [ "$DOCKER" = true ]; then
    echo ""
    echo "Starting via Docker Compose..."
    docker-compose build
    docker-compose up -d
    echo ""
    echo "✓ UEBA running at http://localhost:8000"
    echo "  Dashboard: http://localhost:8000/dashboard"
    echo "  API Docs:  http://localhost:8000/docs"
    exit 0
fi

# ─── Check Python ───
if ! command -v python3 &> /dev/null; then
    echo "✗ Python 3 not found. Install with: sudo apt install python3 python3-pip"
    exit 1
fi

# ─── Install deps ───
echo ""
echo "[1/4] Installing dependencies..."
pip3 install -r requirements.txt -q

# ─── Train if requested ───
if [ "$TRAIN" = true ]; then
    echo ""
    echo "[2/4] Training models (this may take a few minutes)..."
    python3 scripts/train.py --epochs 50
elif [ "$DEMO" = true ]; then
    echo ""
    echo "[2/4] Running quick demo..."
    python3 scripts/demo.py
fi

# ─── Create data dirs ───
echo ""
echo "[3/4] Setting up data directories..."
mkdir -p data/raw data/processed data/models

echo ""
echo "[4/4] Starting UEBA server..."
echo ""
echo "  Dashboard: http://0.0.0.0:8000/dashboard"
echo "  API Docs:  http://0.0.0.0:8000/docs"
echo "  Swagger:   http://0.0.0.0:8000/redoc"
echo ""
echo "  Press Ctrl+C to stop"
echo ""

# ─── Start server ───
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
