#!/usr/bin/env python3
"""Anime Cloud Panel Discord bot for authorized VPS administration."""
from __future__ import annotations
import sys
import os
import logging

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import discord
from discord import app_commands
from discord.ext import commands
from config import DISCORD_TOKEN, ADMIN_USER_IDS

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("anime-cloud-bot")
COGS = ["cogs.vps", "cogs.users", "cogs.nodes", "cogs.system"]


class AnimeCloudCommandTree(app_commands.CommandTree):
    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        command = interaction.command
        if command and command.name == "help":
            return True
        if not ADMIN_USER_IDS:
            message = "Admin access is disabled. Configure ADMIN_USER_IDS on the panel host."
        elif interaction.user.id not in ADMIN_USER_IDS:
            message = "You are not authorized to use Anime Cloud administration commands."
        else:
            return True
        if interaction.response.is_done():
            await interaction.followup.send(message, ephemeral=True)
        else:
            await interaction.response.send_message(message, ephemeral=True)
        return False


class AnimeCloudBot(commands.Bot):
    async def setup_hook(self) -> None:
        for extension in COGS:
            try:
                await self.load_extension(extension)
                log.info("Loaded extension %s", extension)
            except Exception:
                log.exception("Failed to load extension %s", extension)
        try:
            synced = await self.tree.sync()
            log.info("Synced %s application commands", len(synced))
        except Exception:
            log.exception("Slash command sync failed")


intents = discord.Intents.default()
intents.message_content = True
bot = AnimeCloudBot(
    command_prefix="!",
    intents=intents,
    tree_cls=AnimeCloudCommandTree,
    description="Anime Cloud Panel Control Bot",
    activity=discord.Activity(type=discord.ActivityType.watching, name="Anime Cloud Panel"),
)


@bot.event
async def on_ready():
    log.info("Logged in as %s (ID: %s)", bot.user, bot.user.id if bot.user else "unknown")
    log.info("Anime Cloud Bot ready; %d admin IDs configured", len(ADMIN_USER_IDS))


@bot.tree.command(name="help", description="Show Anime Cloud bot commands")
async def help_cmd(interaction: discord.Interaction):
    embed = discord.Embed(
        title="☁️ Anime Cloud Panel Bot",
        description="VPS management commands for authorized Anime Cloud administrators.",
        color=0xc084fc,
    )
    embed.add_field(name="VPS", value="`/vps-list` `/vps-info` `/vps-create`\n`/vps-start` `/vps-stop` `/vps-restart`\n`/vps-suspend` `/vps-unsuspend` `/vps-delete`\n`/vps-exec` `/vps-resize` `/vps-stats`", inline=False)
    embed.add_field(name="Nodes", value="`/nodes-list` `/node-info` `/node-test` `/node-exec`", inline=False)
    embed.add_field(name="Users", value="`/users-list` `/user-info` `/user-create` `/user-update` `/user-delete`", inline=False)
    embed.add_field(name="System", value="`/panel-stats` `/system-info` `/live-stats` `/backup-list` `/search`", inline=False)
    embed.set_footer(text="Anime Cloud • Authorized administrators only")
    await interaction.response.send_message(embed=embed, ephemeral=True)


if __name__ == "__main__":
    if not DISCORD_TOKEN:
        raise SystemExit("Set DISCORD_TOKEN in the repository-root .env file.")
    if not ADMIN_USER_IDS:
        log.warning("ADMIN_USER_IDS is empty; administrative slash commands will be denied.")
    bot.run(DISCORD_TOKEN, log_handler=None)
