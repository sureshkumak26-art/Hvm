"""System, settings, maintenance, backups, emergency, search, stats cog."""

from __future__ import annotations
import discord
from discord import app_commands
from discord.ext import commands
import api, helpers as h
from config import CLR_INFO, CLR_PURPLE, CLR_WARN


class SystemCog(commands.Cog, name="System"):
    def __init__(self, bot: commands.Bot):
        self.bot = bot

    # ── Stats / Info ────────────────────────────────────────────────────
    @app_commands.command(name="panel-stats", description="Overview statistics")
    async def panel_stats(self, interaction: discord.Interaction):
        await interaction.response.defer()
        r = await api.get("/stats/overview")
        if not r.get("success"):
            return await interaction.followup.send(embed=h.err("Failed", r.get("error","?")))
        s = r["stats"]
        vps = s.get("vps", {})
        e = discord.Embed(title="📊 Panel Statistics", color=CLR_PURPLE)
        e.add_field(name="👥 Users", value=s.get("users","—"))
        e.add_field(name="📦 Total VPS", value=vps.get("total", 0))
        e.add_field(name="🟢 Running", value=vps.get("running", 0))
        e.add_field(name="🔴 Stopped", value=vps.get("stopped", 0))
        e.add_field(name="🟠 Suspended", value=vps.get("suspended", 0))
        e.add_field(name="🌐 Nodes", value=s.get("nodes","—"))
        e.add_field(name="🔌 Ports", value=s.get("ports","—"))
        await interaction.followup.send(embed=e)

    @app_commands.command(name="system-info", description="Host system info (CPU, RAM, disk)")
    async def system_info(self, interaction: discord.Interaction):
        await interaction.response.defer()
        r = await api.get("/system/info")
        if not r.get("success"):
            return await interaction.followup.send(embed=h.err("Failed", r.get("error","?")))
        s = r["system"]
        e = discord.Embed(title="🖥️ System Info", color=CLR_INFO)
        e.add_field(name="Host", value=s.get("hostname","?"))
        e.add_field(name="Platform", value=s.get("platform","?")[:40])
        e.add_field(name="Python", value=s.get("python_version","?"))
        cpu = s.get("cpu", {})
        e.add_field(name="CPU Cores", value=cpu.get("cores","?"))
        e.add_field(name="CPU Usage", value=f"{cpu.get('usage','?')}%")
        mem = s.get("memory", {})
        if isinstance(mem, dict):
            e.add_field(name="RAM", value=f"{mem.get('percent', mem.get('pct','?'))}%")
        e.add_field(name="Uptime", value=s.get("uptime","—"))
        await interaction.followup.send(embed=e)

    @app_commands.command(name="live-stats", description="Real-time server stats")
    async def live_stats(self, interaction: discord.Interaction):
        await interaction.response.defer()
        r = await api.get("/system/live-stats")
        if not r.get("success"):
            return await interaction.followup.send(embed=h.err("Failed", r.get("error","?")))
        e = discord.Embed(title="⚡ Live Stats", color=CLR_PURPLE)
        e.add_field(name="Running VPS", value=r.get("running_vps","?"))
        e.add_field(name="Total VPS", value=r.get("total_vps","?"))
        e.add_field(name="Nodes", value=r.get("total_nodes","?"))
        local = r.get("local", {})
        if local:
            e.add_field(name="CPU%", value=f"{local.get('cpu_percent','?')}%")
            e.add_field(name="RAM%", value=f"{local.get('memory_percent','?')}%")
        await interaction.followup.send(embed=e)

    # ── Settings ────────────────────────────────────────────────────────
    @app_commands.command(name="settings-list", description="List all panel settings")
    async def settings_list(self, interaction: discord.Interaction):
        await interaction.response.defer()
        r = await api.get("/settings")
        if not r.get("success"):
            return await interaction.followup.send(embed=h.err("Failed", r.get("error","?")))
        settings = r.get("settings", {})
        desc_lines = [f"`{k}` = `{v.get('value','')}`" for k, v in list(settings.items())[:30]]
        e = discord.Embed(title="⚙️ Settings", description="\n".join(desc_lines) or "No settings", color=CLR_INFO)
        if len(settings) > 30:
            e.set_footer(text=f"Showing 30 of {len(settings)}")
        await interaction.followup.send(embed=e)

    @app_commands.command(name="setting-set", description="Update a panel setting")
    @app_commands.describe(key="Setting key", value="New value")
    async def setting_set(self, interaction: discord.Interaction, key: str, value: str):
        await interaction.response.defer()
        r = await api.put(f"/settings/{key}", {"value": value})
        e = h.ok("Setting Updated", f"`{key}` = `{value}`") if r.get("success") else h.err("Failed", r.get("error","?"))
        await interaction.followup.send(embed=e)

    # ── Maintenance ─────────────────────────────────────────────────────
    @app_commands.command(name="maintenance-on", description="Enable maintenance mode")
    @app_commands.describe(message="Maintenance message to display")
    async def maintenance_on(self, interaction: discord.Interaction, message: str = "Site is under maintenance."):
        await interaction.response.defer()
        r = await api.post("/maintenance/enable", {"message": message})
        e = h.ok("Maintenance ON", message) if r.get("success") else h.err("Failed", r.get("error","?"))
        await interaction.followup.send(embed=e)

    @app_commands.command(name="maintenance-off", description="Disable maintenance mode")
    async def maintenance_off(self, interaction: discord.Interaction):
        await interaction.response.defer()
        r = await api.post("/maintenance/disable")
        e = h.ok("Maintenance OFF") if r.get("success") else h.err("Failed", r.get("error","?"))
        await interaction.followup.send(embed=e)

    # ── Backups ─────────────────────────────────────────────────────────
    @app_commands.command(name="backup-create", description="Create a database backup")
    async def backup_create(self, interaction: discord.Interaction):
        await interaction.response.defer()
        r = await api.post("/backups/create")
        if r.get("success"):
            e = h.ok("Backup Created", f"File: `{r.get('backup_file','?')}`")
        else:
            e = h.err("Failed", r.get("error","?"))
        await interaction.followup.send(embed=e)

    @app_commands.command(name="backup-list", description="List all backups")
    async def backup_list(self, interaction: discord.Interaction):
        await interaction.response.defer()
        r = await api.get("/backups")
        if not r.get("success"):
            return await interaction.followup.send(embed=h.err("Failed", r.get("error","?")))
        backups = r.get("backups", [])
        if not backups:
            return await interaction.followup.send(embed=h.info("Backups", "No backups found."))
        desc = "\n".join(f"📁 `{b['filename']}` — {b.get('created_at','?')[:19]}" for b in backups[:15])
        await interaction.followup.send(embed=discord.Embed(title="💾 Backups", description=desc, color=CLR_INFO))

    # ── Emergency ───────────────────────────────────────────────────────
    @app_commands.command(name="emergency-stop-all", description="⚠️ Stop ALL running VPS")
    async def emergency_stop(self, interaction: discord.Interaction):
        await interaction.response.defer()
        r = await api.post("/emergency/stop-all")
        if r.get("success"):
            e = h.ok("Emergency Stop", f"Stopped: {len(r.get('stopped',[]))} | Failed: {len(r.get('failed',[]))}")
        else:
            e = h.err("Failed", r.get("error","?"))
        await interaction.followup.send(embed=e)

    @app_commands.command(name="emergency-reboot-all", description="⚠️ Reboot ALL running VPS")
    async def emergency_reboot(self, interaction: discord.Interaction):
        await interaction.response.defer()
        r = await api.post("/emergency/reboot-all")
        if r.get("success"):
            e = h.ok("Emergency Reboot", f"Rebooted: {len(r.get('rebooted',[]))} | Failed: {len(r.get('failed',[]))}")
        else:
            e = h.err("Failed", r.get("error","?"))
        await interaction.followup.send(embed=e)

    @app_commands.command(name="emergency-unsuspend-all", description="Unsuspend all suspended VPS")
    async def emergency_unsuspend(self, interaction: discord.Interaction):
        await interaction.response.defer()
        r = await api.post("/emergency/clear-suspensions")
        e = h.ok("Suspensions Cleared", f"Unsuspended: {r.get('unsuspended',0)}") if r.get("success") else h.err("Failed", r.get("error","?"))
        await interaction.followup.send(embed=e)

    # ── Search ──────────────────────────────────────────────────────────
    @app_commands.command(name="search", description="Search across VPS, users, nodes")
    @app_commands.describe(query="Search term")
    async def search(self, interaction: discord.Interaction, query: str):
        await interaction.response.defer()
        r = await api.get("/search", q=query)
        if not r.get("success"):
            return await interaction.followup.send(embed=h.err("Failed", r.get("error","?")))
        res = r.get("results", {})
        e = discord.Embed(title=f"🔍 Search: {query}", description=f"Total: {r.get('total',0)}", color=CLR_INFO)
        for v in res.get("vps", [])[:5]:
            e.add_field(name=f"VPS #{v['id']}", value=v.get("hostname","?"), inline=True)
        for u in res.get("users", [])[:5]:
            e.add_field(name=f"User #{u['id']}", value=u.get("username","?"), inline=True)
        for n in res.get("nodes", [])[:5]:
            e.add_field(name=f"Node #{n['id']}", value=n.get("name","?"), inline=True)
        await interaction.followup.send(embed=e)

    # ── OS Templates ────────────────────────────────────────────────────
    @app_commands.command(name="os-list", description="List available OS templates")
    async def os_list(self, interaction: discord.Interaction):
        await interaction.response.defer()
        r = await api.get("/os-templates")
        if not r.get("success"):
            return await interaction.followup.send(embed=h.err("Failed", r.get("error","?")))
        templates = r.get("templates", [])
        desc = "\n".join(f"• `{t['key']}` — {t['name']}" for t in templates[:30])
        await interaction.followup.send(embed=discord.Embed(title="🐧 OS Templates", description=desc or "None", color=CLR_INFO))

    # ── DB Vacuum ───────────────────────────────────────────────────────
    @app_commands.command(name="db-vacuum", description="Compact the SQLite database")
    async def db_vacuum(self, interaction: discord.Interaction):
        await interaction.response.defer()
        r = await api.post("/system/vacuum")
        e = h.ok("Database Vacuumed") if r.get("success") else h.err("Failed", r.get("error","?"))
        await interaction.followup.send(embed=e)

    # ── Ports ───────────────────────────────────────────────────────────
    @app_commands.command(name="ports-list", description="List port forwards")
    async def ports_list(self, interaction: discord.Interaction):
        await interaction.response.defer()
        r = await api.get("/ports")
        if not r.get("success"):
            return await interaction.followup.send(embed=h.err("Failed", r.get("error","?")))
        ports = r.get("ports", [])
        if not ports:
            return await interaction.followup.send(embed=h.info("Ports", "No port forwards."))
        desc = "\n".join(f"#{p.get('id')} — `:{p.get('external_port',p.get('public_port','?'))}` → `:{p.get('internal_port',p.get('private_port','?'))}` ({p.get('protocol','tcp')})" for p in ports[:20])
        await interaction.followup.send(embed=discord.Embed(title="🔌 Port Forwards", description=desc, color=CLR_INFO))

    # ── Who Am I ────────────────────────────────────────────────────────
    @app_commands.command(name="whoami", description="Show API key identity")
    async def whoami(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True)
        r = await api.get("/me")
        if not r.get("success"):
            return await interaction.followup.send(embed=h.err("Failed", r.get("error","?")), ephemeral=True)
        u = r.get("user", {})
        e = h.field_embed("🪪 API Identity", {
            "User": u.get("username","?"), "ID": u.get("id","?"),
            "Email": u.get("email","—"), "Admin": "✅" if u.get("is_admin") else "❌",
        })
        await interaction.followup.send(embed=e, ephemeral=True)


async def setup(bot: commands.Bot):
    await bot.add_cog(SystemCog(bot))
