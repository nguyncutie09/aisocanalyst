#!/bin/bash
# ============================================================
# SOCal SIEM - Deployment Script
# ============================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

echo "============================================="
echo "  SOCal SIEM - Deployment"
echo "============================================="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info() { echo -e "${CYAN}[INFO]${NC} $1"; }
ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
err()  { echo -e "${RED}[ERR]${NC} $1"; }

# Check prerequisites
info "Checking prerequisites..."

command -v docker >/dev/null 2>&1 || { err "Docker not found. Install Docker first."; exit 1; }
command -v docker-compose >/dev/null 2>&1 || { err "docker-compose not found."; exit 1; }

ok "Docker: $(docker --version)"
ok "docker-compose: $(docker compose version 2>/dev/null || docker-compose --version)"

# Check for NVIDIA GPU for Ollama
if command -v nvidia-smi >/dev/null 2>&1; then
    ok "NVIDIA GPU detected - Ollama will use GPU acceleration"
else
    warn "No NVIDIA GPU detected. Ollama will run on CPU (slower but functional)"
fi

# Create required directories
mkdir -p storage data logs rules

# Generate .env if not exists
if [ ! -f .env ]; then
    info "Creating .env file..."
    cat > .env << EOF
# SOCal SIEM Configuration
DB_HOST=timescaledb
DB_PORT=5432
DB_NAME=socal_siem
DB_USER=socal
DB_PASS=socal_pass
REDIS_HOST=redis
REDIS_PORT=6379
OLLAMA_URL=http://ollama:11434
LLM_MODEL=qwen2.5:7b
LOG_LEVEL=INFO
EOF
    ok ".env created"
fi

# Pull latest Docker images
info "Pulling Docker images..."
docker compose pull || docker-compose pull

# Start services
info "Starting SOCal SIEM services..."
docker compose up -d --build || docker-compose up -d --build

# Wait for services to be healthy
info "Waiting for services to start..."
sleep 10

# Check if services are running
if docker compose ps --services --filter "status=running" 2>/dev/null | grep -q pipeline; then
    ok "Pipeline running"
else
    warn "Pipeline may still be starting..."
fi

# Pull LLM model in background
info "Pulling LLM model (qwen2.5:7b) for AI SOC Analyst..."
docker exec socal-ollama ollama pull qwen2.5:7b 2>/dev/null &
echo "  → Model download started in background (may take a few minutes)"

echo ""
echo "============================================="
echo -e "${GREEN}SOCal SIEM is running!${NC}"
echo "============================================="
echo "  Dashboard:  http://localhost:8080"
echo "  API:        http://localhost:8000"
echo "  API Docs:   http://localhost:8000/docs"
echo "  Ollama:     http://localhost:11434"
echo ""
echo "  To stop:    docker compose down"
echo "  To view logs: docker compose logs -f pipeline"
echo "============================================="
