"""Authenticated KVM/LXC mining detection and Discord alerts."""
from __future__ import annotations

import logging
from datetime import datetime, timezone

import aiohttp
import discord
from discord import app_commands
from discord.ext import commands, tasks

from config import (
    NODE_AGENT_URL,
    NODE_AGENT_TOKEN,
    MINING_ALERT_CHANNEL_ID,
    MINING_SCAN_INTERVAL_SECONDS,
)

log = logging.getLogger("hvm-mining")


class MiningSecurity(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot
        self._session: aiohttp.ClientSession | None = None

    async def cog_load(self) -> None:
        if NODE_AGENT_URL and NODE_AGENT_TOKEN and MINING_ALERT_CHANNEL_ID:
            self.scan_loop.change_interval(seconds=MINING_SCAN_INTERVAL_SECONDS)
            self.scan_loop.start()
        else:
            log.warning("Mining monitor disabled: configure NODE_AGENT_URL, NODE_AGENT_TOKEN and MINING_ALERT_CHANNEL_ID")

    async def cog_unload(self) -> None:
        self.scan_loop.cancel()
        if self._session and not self._session.closed:
            await self._session.close()

    async def _client(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=45, connect=8)
            self._session = aiohttp.ClientSession(
                timeout=timeout,
                headers={"Authorization": f"Bearer {NODE_AGENT_TOKEN}"},
            )
        return self._session

    async def _scan(self) -> dict:
        if not NODE_AGENT_URL or not NODE_AGENT_TOKEN:
            raise RuntimeError("Node agent URL/token is not configured")
        client = await self._client()
        async with client.post(f"{NODE_AGENT_URL.rstrip('/')}/security/scan") as response:
            data = await response.json(content_type=None)
            if response.status >= 400 or not isinstance(data, dict) or not data.get("ok"):
                raise RuntimeError(f"Node agent scan failed (HTTP {response.status})")
            return data

    async def _notify(self, data: dict) -> None:
        channel = self.bot.get_channel(MINING_ALERT_CHANNEL_ID)
        if channel is None:
            try:
                channel = await self.bot.fetch_channel(MINING_ALERT_CHANNEL_ID)
            except Exception:
                log.exception("Could not resolve mining alert channel")
                return

        actions = data.get("actions", [])
        if not actions:
            log.info("Mining scan completed: no confirmed miners stopped")
            return

        for action in actions:
            name = str(action.get("name", "unknown"))[:100]
            kind = str(action.get("type", "guest")).upper()
            status = str(action.get("action", "unknown"))
            evidence = action.get("detections", [])
            evidence_lines = []
            for item in evidence[:5]:
                evidence_lines.append(
                    f"- {str(item.get('process', 'miner signature'))[:120]} — "
                    + ", ".join(str(x) for x in item.get("evidence", [])[:3])
                )
            embed = discord.Embed(
                title="Confirmed mining indicators detected",
                description=(
                    f"Target: {kind} / {name}\n"
                    f"Action: {status}\n"
                    "The node agent matched a known miner process and a pool/algorithm indicator."
                ),
                color=0xE74C3C if status == "stopped" else 0xF39C12,
                timestamp=datetime.now(timezone.utc),
            )
            if evidence_lines:
                embed.add_field(name="Evidence", value="\n".join(evidence_lines)[:1024], inline=False)
            embed.add_field(
                name="Important",
                value="The whole guest was stopped to contain the confirmed activity. Review logs before restarting it.",
                inline=False,
            )
            try:
                await channel.send(embed=embed)
            except Exception:
                log.exception("Failed to send mining alert to Discord")

    @tasks.loop(seconds=60)
    async def scan_loop(self) -> None:
        try:
            data = await self._scan()
            await self._notify(data)
        except Exception as exc:
            log.warning("Mining scan failed: %s", type(exc).__name__)

    @scan_loop.before_loop
    async def before_scan_loop(self) -> None:
        await self.bot.wait_until_ready()

    @app_commands.command(name="mining-scan", description="Run an immediate authenticated KVM/LXC mining scan")
    async def mining_scan(self, interaction: discord.Interaction) -> None:
        await interaction.response.defer(ephemeral=True, thinking=True)
        try:
            data = await self._scan()
            actions = data.get("actions", [])
            await self._notify(data)
            scanned = len(data.get("targets", []))
            await interaction.followup.send(
                f"Scan completed. Targets checked: {scanned}. "
                f"Automatic containment actions: {len(actions)}. "
                "See the configured security channel for evidence.",
                ephemeral=True,
            )
        except Exception as exc:
            log.exception("Manual mining scan failed")
            await interaction.followup.send(
                f"Scan failed: {type(exc).__name__}. Check the node-agent URL, token, and logs.",
                ephemeral=True,
            )


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(MiningSecurity(bot))
