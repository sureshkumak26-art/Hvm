"""Admin-only direct KVM/LXC management through the authenticated HVM node agent."""
from __future__ import annotations
import logging
from datetime import datetime, timezone
import aiohttp
import discord
from discord import app_commands
from discord.ext import commands
from config import NODE_AGENT_URL, NODE_AGENT_TOKEN, ADMIN_AUDIT_CHANNEL_ID

log = logging.getLogger("hvm-hypervisor")

class DeleteGuestView(discord.ui.View):
    def __init__(self, cog, requester_id: int, kind: str, name: str):
        super().__init__(timeout=45)
        self.cog, self.requester_id, self.kind, self.name = cog, requester_id, kind, name

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.requester_id:
            await interaction.response.send_message("Only the requesting admin can confirm deletion.", ephemeral=True)
            return False
        return True

    @discord.ui.button(label="Confirm permanent delete", style=discord.ButtonStyle.danger)
    async def confirm(self, interaction: discord.Interaction, _button: discord.ui.Button):
        await interaction.response.defer(ephemeral=True, thinking=True)
        result = await self.cog._request("POST", f"/guests/{self.kind}/{self.name}/delete", {"confirm": True})
        self.stop()
        for child in self.children:
            child.disabled = True
        if result.get("ok"):
            await interaction.followup.send(f"Deleted {self.kind.upper()} {self.name}. Storage removal was requested.", ephemeral=True)
            await self.cog._audit(interaction.user, "guest-delete", self.kind, self.name, "success")
        else:
            await interaction.followup.send(f"Delete failed: {result.get('error', 'node agent error')}", ephemeral=True)
            await self.cog._audit(interaction.user, "guest-delete", self.kind, self.name, "failed")

    @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary)
    async def cancel(self, interaction: discord.Interaction, _button: discord.ui.Button):
        self.stop()
        for child in self.children:
            child.disabled = True
        await interaction.response.edit_message(content="Deletion cancelled.", view=self)

class HypervisorCommands(commands.Cog, name="Hypervisor"):
    def __init__(self, bot: commands.Bot):
        self.bot = bot

    async def _request(self, method: str, path: str, data: dict | None = None, timeout: int = 35) -> dict:
        if not NODE_AGENT_URL or not NODE_AGENT_TOKEN:
            return {"ok": False, "error": "NODE_AGENT_URL and NODE_AGENT_TOKEN must be configured"}
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout, connect=8),
                                             headers={"Authorization": f"Bearer {NODE_AGENT_TOKEN}"}) as session:
                async with session.request(method, f"{NODE_AGENT_URL.rstrip('/')}{path}", json=data) as response:
                    result = await response.json(content_type=None)
                    if not isinstance(result, dict):
                        return {"ok": False, "error": f"Node agent returned HTTP {response.status}"}
                    if response.status >= 400:
                        result.setdefault("ok", False)
                        result.setdefault("error", f"Node agent returned HTTP {response.status}")
                    return result
        except (aiohttp.ClientError, TimeoutError):
            return {"ok": False, "error": "Node agent is unreachable; check private network, URL and token"}

    async def _audit(self, actor: discord.abc.User, action: str, kind: str, name: str, result: str) -> None:
        log.info("admin_action actor=%s action=%s type=%s name=%s result=%s", actor.id, action, kind, name, result)
        if not ADMIN_AUDIT_CHANNEL_ID:
            return
        channel = self.bot.get_channel(ADMIN_AUDIT_CHANNEL_ID)
        if channel is None:
            try:
                channel = await self.bot.fetch_channel(ADMIN_AUDIT_CHANNEL_ID)
            except Exception:
                log.warning("Could not resolve admin audit channel")
                return
        embed = discord.Embed(title="HVM Admin Audit", color=0x22C55E if result == "success" else 0xEF4444,
                              timestamp=datetime.now(timezone.utc))
        embed.add_field(name="Actor", value=f"{actor} ({actor.id})", inline=False)
        embed.add_field(name="Action", value=action, inline=True)
        embed.add_field(name="Guest", value=f"{kind.upper()} {name}", inline=True)
        embed.add_field(name="Result", value=result, inline=True)
        try:
            await channel.send(embed=embed)
        except Exception:
            log.warning("Could not post HVM admin audit event")

    @app_commands.command(name="vm-list", description="List KVM VMs and LXC containers on the configured node")
    async def vm_list(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True, thinking=True)
        result = await self._request("GET", "/guests")
        if not result.get("ok"):
            return await interaction.followup.send(f"VM listing failed: {result.get('error', 'unknown error')}", ephemeral=True)
        guests = result.get("guests", [])
        embed = discord.Embed(title=f"HVM Guests ({len(guests)})", color=0x8B5CF6)
        if not guests:
            embed.description = "No KVM VMs or LXC containers found."
        for guest in guests[:25]:
            state = str(guest.get("state", "unknown"))
            icon = "🟢" if state == "running" else "🔴"
            ip = ", ".join(guest.get("ipv4", [])[:2])
            value = f"{icon} {state}" + (f"\nIP: {ip}" if ip else "")
            embed.add_field(name=f"{guest.get('type', '?').upper()} · {guest.get('name', '?')}", value=value, inline=False)
        if len(guests) > 25:
            embed.set_footer(text=f"Showing 25 of {len(guests)} guests")
        if result.get("lxcWarning"):
            embed.add_field(name="LXC warning", value=str(result["lxcWarning"])[:900], inline=False)
        await interaction.followup.send(embed=embed, ephemeral=True)

    @app_commands.command(name="vm-info", description="Show details for a KVM VM or LXC container")
    @app_commands.describe(kind="Guest type", name="Exact guest name")
    @app_commands.choices(kind=[app_commands.Choice(name="KVM VM", value="kvm"),
                                app_commands.Choice(name="LXC container", value="lxc")])
    async def vm_info(self, interaction: discord.Interaction, kind: app_commands.Choice[str], name: str):
        await interaction.response.defer(ephemeral=True, thinking=True)
        result = await self._request("GET", f"/guests/{kind.value}/{name}/info")
        if not result.get("ok"):
            return await interaction.followup.send(f"VM info failed: {result.get('error', 'unknown error')}", ephemeral=True)
        guest = result.get("guest", {})
        embed = discord.Embed(title=f"{kind.name}: {name}", color=0x8B5CF6)
        for key, label in (("info", "Details"), ("ip_info", "IP information"), ("config", "Expanded config")):
            value = guest.get(key)
            if value:
                embed.add_field(name=label, value=str(value)[:950], inline=False)
        await interaction.followup.send(embed=embed, ephemeral=True)

    @app_commands.command(name="vm-create", description="Create a KVM VM or LXC container with generated credentials")
    @app_commands.describe(kind="Guest type", hostname="Unique lowercase hostname", cpu="CPU cores (1–16)",
                           ram_gb="RAM in GB (1–64)", storage_gb="Disk in GB (5–500)",
                           owner="Discord user who receives credentials by private DM", os_image="LXC OS image")
    @app_commands.choices(kind=[app_commands.Choice(name="KVM VM", value="kvm"),
                                app_commands.Choice(name="LXC container", value="lxc")],
                          os_image=[app_commands.Choice(name="Ubuntu 24.04", value="images:ubuntu/24.04"),
                                    app_commands.Choice(name="Ubuntu 22.04", value="images:ubuntu/22.04"),
                                    app_commands.Choice(name="Debian 12", value="images:debian/12"),
                                    app_commands.Choice(name="Debian 13", value="images:debian/13")])
    async def vm_create(self, interaction: discord.Interaction, kind: app_commands.Choice[str], hostname: str,
                        cpu: app_commands.Range[int, 1, 16], ram_gb: app_commands.Range[int, 1, 64],
                        storage_gb: app_commands.Range[int, 5, 500], owner: discord.User,
                        os_image: app_commands.Choice[str] | None = None):
        await interaction.response.defer(ephemeral=True, thinking=True)
        body = {"type": kind.value, "name": hostname.strip().lower(), "cpu": cpu,
                "ram_gb": ram_gb, "storage_gb": storage_gb}
        if kind.value == "lxc":
            body["image"] = os_image.value if os_image else "images:ubuntu/24.04"
        result = await self._request("POST", "/guests", body, timeout=240)
        if not result.get("ok"):
            await self._audit(interaction.user, "guest-create", kind.value, body["name"], "failed")
            return await interaction.followup.send(f"VM creation failed: {result.get('error', 'unknown error')}", ephemeral=True)
        guest = result.get("guest", {})
        username, password = str(guest.get("username", "")), str(guest.get("password", ""))
        if not username or not password:
            await self._audit(interaction.user, "guest-create", kind.value, body["name"], "failed-no-credentials")
            return await interaction.followup.send("Guest created but no credentials were returned. Check node-agent logs before assigning access.", ephemeral=True)
        embed = discord.Embed(title="Your HVM guest is ready",
                              description="Save these credentials securely and change the password after first login.",
                              color=0x22C55E)
        embed.add_field(name="Type", value=kind.value.upper(), inline=True)
        embed.add_field(name="Hostname", value=str(guest.get("name", body["name"])), inline=True)
        embed.add_field(name="Username", value=username, inline=False)
        embed.add_field(name="Temporary password", value=password, inline=False)
        embed.add_field(name="Resources", value=f"CPU: {cpu}\nRAM: {ram_gb} GB\nDisk: {storage_gb} GB", inline=False)
        try:
            await owner.send(embed=embed)
        except (discord.Forbidden, discord.HTTPException):
            await self._request("POST", f"/guests/{kind.value}/{body['name']}/delete", {"confirm": True}, timeout=60)
            await self._audit(interaction.user, "guest-create", kind.value, body["name"], "rolled-back-dm-failed")
            return await interaction.followup.send(
                f"Could not DM {owner.mention}; the new guest was rolled back to avoid stranding credentials. Ask the user to enable DMs and retry.",
                ephemeral=True)
        await self._audit(interaction.user, "guest-create", kind.value, body["name"], "success")
        await interaction.followup.send(
            f"Created {kind.value.upper()} {guest.get('name', body['name'])} and sent credentials privately to {owner.mention}.",
            ephemeral=True)

    @app_commands.command(name="vm-action", description="Start, stop, or restart a KVM/LXC guest")
    @app_commands.describe(kind="Guest type", name="Exact guest name", action="Action")
    @app_commands.choices(kind=[app_commands.Choice(name="KVM VM", value="kvm"),
                                app_commands.Choice(name="LXC container", value="lxc")],
                          action=[app_commands.Choice(name="Start", value="start"),
                                  app_commands.Choice(name="Stop", value="stop"),
                                  app_commands.Choice(name="Restart", value="restart")])
    async def vm_action(self, interaction: discord.Interaction, kind: app_commands.Choice[str], name: str,
                        action: app_commands.Choice[str]):
        await interaction.response.defer(ephemeral=True, thinking=True)
        result = await self._request("POST", f"/guests/{kind.value}/{name}/{action.value}", {})
        success = bool(result.get("ok"))
        await self._audit(interaction.user, f"guest-{action.value}", kind.value, name, "success" if success else "failed")
        message = f"{action.name} requested for {kind.value.upper()} {name}." if success else f"Action failed: {result.get('error', 'unknown error')}"
        await interaction.followup.send(message, ephemeral=True)

    @app_commands.command(name="vm-delete", description="Permanently delete a KVM VM or LXC container")
    @app_commands.describe(kind="Guest type", name="Exact guest name")
    @app_commands.choices(kind=[app_commands.Choice(name="KVM VM", value="kvm"),
                                app_commands.Choice(name="LXC container", value="lxc")])
    async def vm_delete(self, interaction: discord.Interaction, kind: app_commands.Choice[str], name: str):
        embed = discord.Embed(title="Confirm permanent guest deletion",
                              description=f"Delete {kind.value.upper()} {name} and request storage removal? This is irreversible.",
                              color=0xEF4444)
        await interaction.response.send_message(embed=embed,
            view=DeleteGuestView(self, interaction.user.id, kind.value, name), ephemeral=True)

    @app_commands.command(name="hypervisor-status", description="Check HVM node-agent health")
    async def hypervisor_status(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True, thinking=True)
        result = await self._request("GET", "/health")
        if result.get("ok"):
            await interaction.followup.send(f"Node agent online. Hypervisor: {result.get('hypervisor', 'unknown')}", ephemeral=True)
        else:
            await interaction.followup.send(f"Node agent unavailable: {result.get('error', 'unknown error')}", ephemeral=True)

async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(HypervisorCommands(bot))
