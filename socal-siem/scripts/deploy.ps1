# ============================================================
# SOCal SIEM - Windows Deployment Script (PowerShell)
# ============================================================

$ProjectDir = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
Set-Location $ProjectDir

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  SOCal SIEM - Deployment (Windows)" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

# Check prerequisites
Write-Host "[INFO] Checking prerequisites..." -ForegroundColor Cyan

$hasDocker = Get-Command docker -ErrorAction SilentlyContinue
if (-not $hasDocker) {
    Write-Host "[ERR] Docker not found! Install Docker Desktop for Windows." -ForegroundColor Red
    Write-Host "  Download: https://www.docker.com/products/docker-desktop/"
    exit 1
}
Write-Host "[OK] Docker: $(docker --version)" -ForegroundColor Green

# Check docker-compose
$hasCompose = Get-Command docker-compose -ErrorAction SilentlyContinue
if (-not $hasCompose) {
    # Docker Compose v2 is included in Docker Desktop
    $hasComposeV2 = docker compose version 2>$null
    if (-not $hasComposeV2) {
        Write-Host "[ERR] docker-compose not found!" -ForegroundColor Red
        exit 1
    }
    Write-Host "[OK] docker compose v2 available" -ForegroundColor Green
    $COMPOSE_CMD = "docker compose"
} else {
    Write-Host "[OK] $(docker-compose --version)" -ForegroundColor Green
    $COMPOSE_CMD = "docker-compose"
}

# Create directories
New-Item -ItemType Directory -Path storage, data, logs, rules -Force | Out-Null

# Generate .env if not exists
if (-not (Test-Path .env)) {
    Write-Host "[INFO] Creating .env file..." -ForegroundColor Cyan
    @"
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
"@ | Out-File -FilePath .env -Encoding UTF8
    Write-Host "[OK] .env created" -ForegroundColor Green
}

# Pull images
Write-Host "[INFO] Pulling Docker images..." -ForegroundColor Cyan
Invoke-Expression "$COMPOSE_CMD pull"

# Start services
Write-Host "[INFO] Starting SOCal SIEM..." -ForegroundColor Cyan
Invoke-Expression "$COMPOSE_CMD up -d --build"

Start-Sleep -Seconds 15

Write-Host ""
Write-Host "=============================================" -ForegroundColor Green
Write-Host "SOCal SIEM is running!" -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Green
Write-Host "  Dashboard:  http://localhost:8080"
Write-Host "  API:        http://localhost:8000"
Write-Host "  API Docs:   http://localhost:8000/docs"
Write-Host ""
Write-Host "  To stop:    $COMPOSE_CMD down"
Write-Host "  To view logs: $COMPOSE_CMD logs -f pipeline"
Write-Host "=============================================" -ForegroundColor Cyan
