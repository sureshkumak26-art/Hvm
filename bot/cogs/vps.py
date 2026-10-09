"""VPS management cog — the biggest set of commands."""

from __future__ import annotations
import discord
from discord import app_commands
from discord.ext import commands
import api, helpers as h
from config import CLR_INFO, CLR_PURPLE


class VPSCog(commands.Cog, name="VPS"):
    def __init__(self, bot: commands.Bot):
        self.bot = bot

    # ── List ────────────────────────────────────────────────────────────
    @app_commands.command(name="vps-list", description="List all VPS instances")
    async def vps_list(self, interaction: discord.Interaction):
        await interaction.response.defer()
        r = await api.get("/vps")
        if not r.get("success"):
            return await interaction.followup.send(embed=h.err("Failed", r.get("error", "?")))
        vps = r.get("vps", [])
        if not vps:
            return await interaction.followup.send(embed=h.info("VPS List", "No VPS found."))
        e = discord.Embed(title=f"📦 VPS List  ({len(vps)})", color=CLR_INFO)
        for v in vps[:25]:
            status = h.fmt_status(v.get("status"))
            owner = v.get("username", f"UID {v.get('user_id','?')}")
            e.add_field(
                name=f"#{v['id']} — {v.get('hostname', v.get('container_name','?'))}",
                value=f"{status}\n👤 {owner}  •  🖥️ {v.get('config','—')}", inline=False,
            )
        if len(vps) > 25:
            e.set_footer(text=f"Showing 25 of {len(vps)}")
        await interaction.followup.send(embed=e)

    # ── Info ────────────────────────────────────────────────────────────
    @app_commands.command(name="vps-info", description="Get detailed VPS info")
    @app_commands.describe(vps_id="VPS ID")
    async def vps_info(self, interaction: discord.Interaction, vps_id: int):
        await interaction.response.defer()
        r = await api.get(f"/vps/{vps_id}")
        if not r.get("success"):
            return await interaction.followup.send(embed=h.err("Not Found", r.get("error", "?")))
        v = r["vps"]
        e = discord.Embed(title=f"📦 {v.get('hostname', v.get('container_name'))}", color=CLR_INFO)
        e.add_field(name="ID", value=v["id"])
        e.add_field(name="Status", value=h.fmt_status(v.get("status")))
        e.add_field(name="Container", value=v.get("container_name", "—"))
        e.add_field(name="OS", value=v.get("os_version", "—"))
        e.add_field(name="Config", value=v.get("config", "—"), inline=False)
        e.add_field(name="IP", value=v.get("ip_address") or "—")
        e.add_field(name="Node", value=v.get("node_name") or v.get("node_id", "—"))
        e.add_field(name="Owner", value=v.get("username") or v.get("user_id", "—"))
        if v.get("expires_at"):
            e.add_field(name="Expires", value=v["expires_at"][:19])
        await interaction.followup.send(embed=e)

    # ── Start / Stop / Restart ──────────────────────────────────────────
    @app_commands.command(name="vps-start", description="Start a VPS")
    @app_commands.describe(vps_id="VPS ID")
    async def vps_start(self, interaction: discord.Interaction, vps_id: int):
        await interaction.response.defer()
        r = await api.post(f"/vps/{vps_id}/start")
        e = h.ok("VPS Started", f"VPS **#{vps_id}** started.") if r.get("success") else h.err("Failed", r.get("error","?"))
        await interaction.followup.send(embed=e)

    @app_commands.command(name="vps-stop", description="Stop a VPS")
    @app_commands.describe(vps_id="VPS ID")
    async def vps_stop(self, interaction: discord.Interaction, vps_id: int):
        await interaction.response.defer()
        r = await api.post(f"/vps/{vps_id}/stop")
        e = h.ok("VPS Stopped", f"VPS **#{vps_id}** stopped.") if r.get("success") else h.err("Failed", r.get("error","?"))
        await interaction.followup.send(embed=e)

    @app_commands.command(name="vps-restart", description="Restart a VPS")
    @app_commands.describe(vps_id="VPS ID")
    async def vps_restart(self, interaction: discord.Interaction, vps_id: int):
        await interaction.response.defer()
        r = await api.post(f"/vps/{vps_id}/restart")
        e = h.ok("VPS Restarted", f"VPS **#{vps_id}** restarted.") if r.get("success") else h.err("Failed", r.get("error","?"))
        await interaction.followup.send(embed=e)

    # ── Suspend / Unsuspend ─────────────────────────────────────────────
    @app_commands.command(name="vps-suspend", description="Suspend a VPS")
    @app_commands.describe(vps_id="VPS ID", reason="Suspension reason")
    async def vps_suspend(self, interaction: discord.Interaction, vps_id: int, reason: str = "Suspended via Discord"):
        await interaction.response.defer()
        r = await api.post(f"/vps/{vps_id}/suspend", {"reason": reason})
        e = h.ok("VPS Suspended", f"VPS **#{vps_id}** suspended.\nReason: {reason}") if r.get("success") else h.err("Failed", r.get("error","?"))
        await interaction.followup.send(embed=e)

    @app_commands.command(name="vps-unsuspend", description="Unsuspend a VPS")
    @app_commands.describe(vps_id="VPS ID")
    async def vps_unsuspend(self, interaction: discord.Interaction, vps_id: int):
        await interaction.response.defer()
        r = await api.post(f"/vps/{vps_id}/unsuspend")
        e = h.ok("VPS Unsuspended", f"VPS **#{vps_id}** unsuspended.") if r.get("success") else h.err("Failed", r.get("error","?"))
        await interaction.followup.send(embed=e)

    # ── Delete ──────────────────────────────────────────────────────────
    @app_commands.command(name="vps-delete", description="Delete a VPS (irreversible!)")
    @app_commands.describe(vps_id="VPS ID")
    async def vps_delete(self, interaction: discord.Interaction, vps_id: int):
        await interaction.response.defer()
        r = await api.delete(f"/vps/{vps_id}")
        e = h.ok("VPS Deleted", f"VPS **#{vps_id}** has been deleted.") if r.get("success") else h.err("Failed", r.get("error","?"))
        await interaction.followup.send(embed=e)

    # ── Create ──────────────────────────────────────────────────────────
    @app_commands.command(name="vps-create", description="Create a new VPS")
    @app_commands.describe(
        hostname="Hostname", user_id="Owner user ID", node_id="Node ID",
        cpu="CPU cores", ram="RAM in GB", storage="Storage in GB",
        os_version="OS image (e.g. ubuntu:22.04)",
    )
    async def vps_create(self, interaction: discord.Interaction, hostname: str,
                         user_id: int, node_id: int, cpu: int, ram: int,
                         storage: int, os_version: str = "ubuntu:22.04"):
        await interaction.response.defer()
        r = await api.post("/vps", {
            "hostname": hostname, "user_id": user_id, "node_id": node_id,
            "cpu": cpu, "ram": ram, "storage": storage, "os_version": os_version,
        })
        if r.get("success"):
            e = h.ok("VPS Created", f"**{hostname}** is installing.\nID: `{r.get('vps_id')}`\nContainer: `{r.get('container_name')}`")
        else:
            e = h.err("Failed", r.get("error", "?"))
        await interaction.followup.send(embed=e)

    # ── Resize ──────────────────────────────────────────────────────────
    @app_commands.command(name="vps-resize", description="Resize VPS resources")
    @app_commands.describe(vps_id="VPS ID", cpu="New CPU cores", ram="New RAM", storage="New storage")
    async def vps_resize(self, interaction: discord.Interaction, vps_id: int,
                         cpu: str = None, ram: str = None, storage: str = None):
        await interaction.response.defer()
        data = {}
        if cpu: data["cpu"] = cpu
        if ram: data["ram"] = ram
        if storage: data["storage"] = storage
        if not data:
            return await interaction.followup.send(embed=h.err("Missing Args", "Provide at least one of cpu/ram/storage"))
        r = await api.post(f"/vps/{vps_id}/resize", data)
        e = h.ok("VPS Resized", r.get("message","Done")) if r.get("success") else h.err("Failed", r.get("error","?"))
        await interaction.followup.send(embed=e)

    # ── Execute command ─────────────────────────────────────────────────
    @app_commands.command(name="vps-exec", description="Execute a command inside a VPS")
    @app_commands.describe(vps_id="VPS ID", command="Shell command")
    async def vps_exec(self, interaction: discord.Interaction, vps_id: int, command: str):
        await interaction.response.defer()
        r = await api.post(f"/vps/{vps_id}/execute", {"command": command})
        if r.get("success"):
            output = r.get("output", "(no output)")
            if len(output) > 1900:
                output = output[:1900] + "\n… (truncated)"
            e = h.ok(f"VPS #{vps_id}", f"```\n{output}\n```")
        else:
            e = h.err("Failed", r.get("error","?"))
        await interaction.followup.send(embed=e)

    # ── Renew ───────────────────────────────────────────────────────────
    @app_commands.command(name="vps-renew", description="Extend VPS expiration")
    @app_commands.describe(vps_id="VPS ID", days="Days to add (default 30)")
    async def vps_renew(self, interaction: discord.Interaction, vps_id: int, days: int = 30):
        await interaction.response.defer()
        r = await api.post(f"/vps/{vps_id}/renew", {"days": days})
        if r.get("success"):
            e = h.ok("VPS Renewed", f"VPS **#{vps_id}** extended by **{days}** days.\nNew expiry: `{r.get('new_expires_at','?')}`")
        else:
            e = h.err("Failed", r.get("error","?"))
        await interaction.followup.send(embed=e)

    # ── Reinstall ───────────────────────────────────────────────────────
    @app_commands.command(name="vps-reinstall", description="Reinstall VPS with new OS")
    @app_commands.describe(vps_id="VPS ID", os_version="New OS (e.g. ubuntu:22.04)")
    async def vps_reinstall(self, interaction: discord.Interaction, vps_id: int, os_version: str):
        await interaction.response.defer()
        r = await api.post(f"/vps/{vps_id}/reinstall", {"os_version": os_version})
        e = h.ok("Reinstalling", f"VPS **#{vps_id}** → `{os_version}`") if r.get("success") else h.err("Failed", r.get("error","?"))
        await interaction.followup.send(embed=e)

    # ── Password ────────────────────────────────────────────────────────
    @app_commands.command(name="vps-password", description="Get or change VPS root password")
    @app_commands.describe(vps_id="VPS ID", new_password="Leave empty to view current")
    async def vps_password(self, interaction: discord.Interaction, vps_id: int, new_password: str = None):
        await interaction.response.defer(ephemeral=True)
        if new_password:
            r = await api.post(f"/vps/{vps_id}/password", {"password": new_password})
            e = h.ok("Password Changed") if r.get("success") else h.err("Failed", r.get("error","?"))
        else:
            r = await api.get(f"/vps/{vps_id}/password")
            pw = r.get("password", "?")
            e = h.info(f"VPS #{vps_id} Password", f"||`{pw}`||")
        await interaction.followup.send(embed=e, ephemeral=True)

    # ── Stats ───────────────────────────────────────────────────────────
    @app_commands.command(name="vps-stats", description="Get live VPS resource stats")
    @app_commands.describe(vps_id="VPS ID")
    async def vps_stats(self, interaction: discord.Interaction, vps_id: int):
        await interaction.response.defer()
        r = await api.get(f"/vps/{vps_id}/stats")
        if r.get("success") and r.get("stats"):
            s = r["stats"]
            e = h.field_embed(f"📊 VPS #{vps_id} Stats", {
                "Status": s.get("status", "?"), "CPU": f"{s.get('cpu','?')}%",
                "RAM": f"{s.get('ram',{}).get('pct','?')}%",
                "Disk": f"{s.get('disk',{}).get('pct','?')}%",
            }, color=CLR_PURPLE)
        else:
            e = h.err("Failed", r.get("error","Could not get stats"))
        await interaction.followup.send(embed=e)

    # ── Whitelist toggle ────────────────────────────────────────────────
    @app_commands.command(name="vps-whitelist", description="Toggle VPS whitelist (skip expiry checks)")
    @app_commands.describe(vps_id="VPS ID")
    async def vps_whitelist(self, interaction: discord.Interaction, vps_id: int):
        await interaction.response.defer()
        r = await api.post(f"/vps/{vps_id}/whitelist")
        if r.get("success"):
            wl = "✅ Whitelisted" if r.get("is_whitelisted") else "❌ Not whitelisted"
            e = h.ok(f"VPS #{vps_id}", wl)
        else:
            e = h.err("Failed", r.get("error","?"))
        await interaction.followup.send(embed=e)

    # ── Bulk ops ────────────────────────────────────────────────────────
    @app_commands.command(name="vps-bulk-start", description="Start multiple VPS by IDs")
    @app_commands.describe(ids="Comma-separated VPS IDs (e.g. 1,2,3)")
    async def vps_bulk_start(self, interaction: discord.Interaction, ids: str):
        await interaction.response.defer()
        vps_ids = [int(x.strip()) for x in ids.split(",") if x.strip().isdigit()]
        r = await api.post("/vps/bulk/start", {"vps_ids": vps_ids})
        if r.get("success"):
            e = h.ok("Bulk Start", r.get("message","Done"))
        else:
            e = h.err("Failed", r.get("error","?"))
        await interaction.followup.send(embed=e)

    @app_commands.command(name="vps-bulk-stop", description="Stop multiple VPS by IDs")
    @app_commands.describe(ids="Comma-separated VPS IDs (e.g. 1,2,3)")
    async def vps_bulk_stop(self, interaction: discord.Interaction, ids: str):
        await interaction.response.defer()
        vps_ids = [int(x.strip()) for x in ids.split(",") if x.strip().isdigit()]
        r = await api.post("/vps/bulk/stop", {"vps_ids": vps_ids})
        if r.get("success"):
            e = h.ok("Bulk Stop", r.get("message","Done"))
        else:
            e = h.err("Failed", r.get("error","?"))
        await interaction.followup.send(embed=e)


async def setup(bot: commands.Bot):
    await bot.add_cog(VPSCog(bot))
