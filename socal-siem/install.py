#!/usr/bin/env python3
"""
SOCal SIEM - Single-Command Install & Run
Usage:
    python install.py              # Install & start
    python install.py --stop       # Stop all services
    python install.py --logs       # View logs
    python install.py --restart    # Restart
    python install.py --update     # Update images
"""

import argparse
import os
import platform
import shutil
import subprocess
import sys
import time


def print_banner():
    print("""
╔══════════════════════════════════════════════════════════╗
║                 SOCal SIEM Installer                     ║
║         Local SIEM + AI SOC Analyst                      ║
╚══════════════════════════════════════════════════════════╝
    """)


def check_docker():
    """Check if Docker is installed"""
    if not shutil.which('docker'):
        print("❌ Docker not found. Please install Docker first:")
        print("   https://docs.docker.com/get-docker/")
        return False
    
    # Check Docker is running
    try:
        subprocess.run(['docker', 'info'], capture_output=True, check=True, timeout=5)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        print("❌ Docker is installed but not running. Please start Docker Desktop/Daemon.")
        return False
    
    # Check compose
    compose_cmds = [
        ['docker', 'compose', 'version'],
        ['docker-compose', '--version'],
    ]
    for cmd in compose_cmds:
        try:
            subprocess.run(cmd, capture_output=True, check=True, timeout=5)
            return True
        except (FileNotFoundError, subprocess.CalledProcessError):
            continue
    
    print("❌ docker-compose not found. Install Docker Compose:")
    print("   https://docs.docker.com/compose/install/")
    return False


def run_compose(args: list, capture=False):
    """Run docker-compose command"""
    # Try docker compose v2 first
    compose_v2 = subprocess.run(
        ['docker', 'compose'] + args,
        capture_output=capture,
        text=True,
    )
    if compose_v2.returncode == 0 or 'docker: ' not in compose_v2.stderr:
        return compose_v2
    
    # Fallback to docker-compose
    return subprocess.run(
        ['docker-compose'] + args,
        capture_output=capture,
        text=True,
    )


def create_env():
    """Create .env if not exists"""
    if not os.path.exists('.env'):
        print("📝 Creating .env configuration file...")
        with open('.env', 'w') as f:
            f.write("""DB_HOST=timescaledb
DB_PORT=5432
DB_NAME=socal_siem
DB_USER=socal
DB_PASS=socal_pass
REDIS_HOST=redis
REDIS_PORT=6379
OLLAMA_URL=http://ollama:11434
LLM_MODEL=qwen2.5:7b
LOG_LEVEL=INFO
""")
        print("   ✅ .env created")
    else:
        print("   ✅ .env already exists")


def create_dirs():
    """Create required directories"""
    for d in ['storage', 'data', 'logs', 'rules']:
        os.makedirs(d, exist_ok=True)


def install():
    """Full install and start"""
    print_banner()
    
    # Check system
    print(f"🔍 System: {platform.system()} {platform.release()}")
    
    if not check_docker():
        sys.exit(1)
    
    print("✅ Docker OK")
    
    # Create config
    create_env()
    create_dirs()
    
    # Pull images
    print("📦 Pulling Docker images...")
    result = run_compose(['pull'])
    if result.returncode != 0:
        print("⚠️  Image pull had warnings (non-critical)")
    print("   ✅ Images ready")
    
    # Build and start
    print("🚀 Starting SOCal SIEM services...")
    result = run_compose(['up', '-d', '--build'])
    if result.returncode != 0:
        print(f"❌ Failed to start: {result.stderr}")
        sys.exit(1)
    
    # Wait for services
    print("⏳ Waiting for services to initialize...")
    time.sleep(10)
    
    # Check status
    result = run_compose(['ps', '--services', '--filter', 'status=running'], capture=True)
    if result.returncode == 0:
        running = result.stdout.strip().split('\n')
        print(f"   ✅ Running services: {len(running)}")
        for svc in running:
            if svc:
                print(f"      • {svc}")
    
    # Start LLM model pull in background
    print("\n🧠 Pulling AI model (qwen2.5:7b) - first run may take a few minutes...")
    subprocess.Popen(
        ['docker', 'exec', 'socal-ollama', 'ollama', 'pull', 'qwen2.5:7b'],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    
    print("""
╔══════════════════════════════════════════════════════════╗
║  ✅ SOCal SIEM is RUNNING!                                ║
║                                                          ║
║  📊 Dashboard:  http://localhost:8080                     ║
║  🔌 API:        http://localhost:8000                     ║
║  📖 API Docs:   http://localhost:8000/docs                ║
║                                                          ║
║  Commands:                                                ║
║    python install.py --stop     Stop all services         ║
║    python install.py --logs     View pipeline logs        ║
║    python install.py --restart  Restart services          ║
║    python install.py --update   Update to latest images   ║
╚══════════════════════════════════════════════════════════╝
    """)


def stop():
    print("🛑 Stopping SOCal SIEM...")
    run_compose(['down'])
    print("✅ All services stopped")


def view_logs():
    print("📋 Pipeline logs (Ctrl+C to exit):")
    try:
        run_compose(['logs', '-f', 'pipeline'])
    except KeyboardInterrupt:
        pass


def restart():
    print("🔄 Restarting SOCal SIEM...")
    run_compose(['restart'])
    print("✅ Restarted")


def update():
    print("📦 Updating SOCal SIEM...")
    run_compose(['down'])
    run_compose(['pull'])
    run_compose(['up', '-d', '--build'])
    print("✅ Updated to latest version")


def status():
    print("📊 SOCal SIEM Status:")
    result = run_compose(['ps'], capture=True)
    print(result.stdout if result.returncode == 0 else "❌ Not running")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='SOCal SIEM Installer')
    parser.add_argument('--stop', action='store_true', help='Stop all services')
    parser.add_argument('--logs', action='store_true', help='View pipeline logs')
    parser.add_argument('--restart', action='store_true', help='Restart services')
    parser.add_argument('--update', action='store_true', help='Update images')
    parser.add_argument('--status', action='store_true', help='Show status')
    
    args = parser.parse_args()
    
    # Change to script directory
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    if args.stop:
        stop()
    elif args.logs:
        view_logs()
    elif args.restart:
        restart()
    elif args.update:
        update()
    elif args.status:
        status()
    else:
        install()
