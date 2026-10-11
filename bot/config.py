"""Anime Cloud Discord bot configuration. Secrets are supplied via environment."""
from __future__ import annotations
import os
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
except ImportError:
    pass

DISCORD_TOKEN = os.getenv("DISCORD_TOKEN", "").strip()
API_BASE = os.getenv("PANEL_API_BASE", "http://127.0.0.1:5000/api/v1").rstrip("/")
API_KEY = os.getenv("PANEL_API_KEY", "").strip()
ADMIN_USER_IDS = {
    int(value.strip())
    for value in os.getenv("ADMIN_USER_IDS", "").split(",")
    if value.strip().isdigit()
}

# Separate authenticated node-agent API for KVM/LXC security monitoring.
NODE_AGENT_URL = os.getenv("NODE_AGENT_URL", "").strip().rstrip("/")
NODE_AGENT_TOKEN = os.getenv("NODE_AGENT_TOKEN", "").strip()
MINING_ALERT_CHANNEL_ID = int(os.getenv("MINING_ALERT_CHANNEL_ID", "0") or "0")
MINING_SCAN_INTERVAL_SECONDS = max(60, min(3600, int(os.getenv("MINING_SCAN_INTERVAL_SECONDS", "120") or "120")))

CLR_OK = 0x34d399
CLR_ERR = 0xef4444
CLR_WARN = 0xfbbf24
CLR_INFO = 0x4facfe
CLR_PURPLE = 0xc084fc
