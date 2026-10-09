#!/usr/bin/env python3
"""
StrenoxCloud Panel — Discord Bot
========================
Controls the entire StrenoxCloud Panel through the REST API.

Usage:
  1. Set your Discord bot token in  bot/config.py
  2. Set the StrenoxCloud API key in         bot/config.py
  3. Run:  python bot/bot.py

Slash commands sync on first start. Use /help to see all commands.
"""

from __future__ import annotations
import sys, os, asyncio, logging

# Ensure bot/ is on the import path so cogs can import config/api/helpers
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import discord
from discord.ext import commands
from config import DISCORD_TOKEN

# ── Logging ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("hvm-bot")

# ── Bot setup ───────────────────────────────────────────────────────────
intents = discord.Intents.default()
intents.message_content = True

bot = commands.Bot(
    command_prefix="!",
    intents=intents,
    description="StrenoxCloud Panel Control Bot",
    activity=discord.Activity(type=discord.ActivityType.watching, name="StrenoxCloud Panel"),
)

# ── Cog loader ──────────────────────────────────────────────────────────
COGS = [
    "cogs.vps",
    "cogs.users",
    "cogs.nodes",
    "cogs.system",
]


@bot.event
async def on_ready():
    log.info(f"Logged in as {bot.user} (ID: {bot.user.id})")

    # Load cogs
    for cog in COGS:
        try:
            await bot.load_extension(cog)
            log.info(f"  ✔ Loaded {cog}")
        except Exception as e:
            log.error(f"  ✘ Failed to load {cog}: {e}")

    # Sync slash commands globally
    try:
        synced = await bot.tree.sync()
        log.info(f"Synced {len(synced)} slash commands globally")
    except Exception as e:
        log.error(f"Slash sync failed: {e}")

    log.info("━━━ StrenoxCloud Bot ready ━━━")


# ── Help command ────────────────────────────────────────────────────────
@bot.tree.command(name="help", description="Show all StrenoxCloud bot commands")
async def help_cmd(interaction: discord.Interaction):
    e = discord.Embed(
        title="🤖 StrenoxCloud Panel Bot — Commands",
        description="Full control over the StrenoxCloud Panel via Discord.",
        color=0x4facfe,
    )
    e.add_field(name="📦 VPS Management", value=(
        "`/vps-list` `/vps-info` `/vps-create`\n"
        "`/vps-start` `/vps-stop` `/vps-restart`\n"
        "`/vps-suspend` `/vps-unsuspend` `/vps-delete`\n"
        "`/vps-exec` `/vps-resize` `/vps-renew`\n"
        "`/vps-reinstall` `/vps-password` `/vps-stats`\n"
        "`/vps-whitelist` `/vps-bulk-start` `/vps-bulk-stop`"
    ), inline=False)
    e.add_field(name="👥 User Management", value=(
        "`/users-list` `/user-info` `/user-create`\n"
        "`/user-delete` `/user-update` `/user-reset-password`"
    ), inline=False)
    e.add_field(name="🌐 Node Management", value=(
        "`/nodes-list` `/node-info` `/node-create`\n"
        "`/node-delete` `/node-test` `/node-exec`"
    ), inline=False)
    e.add_field(name="⚙️ System & Admin", value=(
        "`/panel-stats` `/system-info` `/live-stats`\n"
        "`/settings-list` `/setting-set` `/whoami`\n"
        "`/maintenance-on` `/maintenance-off`\n"
        "`/backup-create` `/backup-list` `/db-vacuum`\n"
        "`/os-list` `/ports-list` `/search`"
    ), inline=False)
    e.add_field(name="🚨 Emergency", value=(
        "`/emergency-stop-all` `/emergency-reboot-all`\n"
        "`/emergency-unsuspend-all`"
    ), inline=False)
    e.set_footer(text="StrenoxCloud Panel Bot • Powered by StrenoxCloud REST API v1")
    await interaction.response.send_message(embed=e)


# ── Run ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if DISCORD_TOKEN == "YOUR_DISCORD_BOT_TOKEN_HERE":
        print("╔══════════════════════════════════════════════╗")
        print("║  Set your Discord bot token in config.py !   ║")
        print("╚══════════════════════════════════════════════╝")
        sys.exit(1)
    bot.run(DISCORD_TOKEN, log_handler=None)
