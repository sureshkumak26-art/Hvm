"""Node management cog."""

from __future__ import annotations
import discord
from discord import app_commands
from discord.ext import commands
import api, helpers as h
from config import CLR_INFO


class NodesCog(commands.Cog, name="Nodes"):
    def __init__(self, bot: commands.Bot):
        self.bot = bot

    @app_commands.command(name="nodes-list", description="List all nodes")
    async def nodes_list(self, interaction: discord.Interaction):
        await interaction.response.defer()
        r = await api.get("/nodes")
        if not r.get("success"):
            return await interaction.followup.send(embed=h.err("Failed", r.get("error","?")))
        nodes = r.get("nodes", [])
        e = discord.Embed(title=f"🌐 Nodes ({len(nodes)})", color=CLR_INFO)
        for n in nodes[:25]:
            local = " (Local)" if n.get("is_local") else ""
            e.add_field(
                name=f"#{n['id']} — {n.get('name','?')}{local}",
                value=f"📍 {n.get('location','—')}  •  🔗 {n.get('url') or 'local'}",
                inline=False,
            )
        await interaction.followup.send(embed=e)

    @app_commands.command(name="node-info", description="Get node details")
    @app_commands.describe(node_id="Node ID")
    async def node_info(self, interaction: discord.Interaction, node_id: int):
        await interaction.response.defer()
        r = await api.get(f"/nodes/{node_id}")
        if not r.get("success"):
            return await interaction.followup.send(embed=h.err("Not Found", r.get("error","?")))
        n = r["node"]
        e = h.field_embed(f"🌐 {n.get('name','Node')}", {
            "ID": n["id"], "Location": n.get("location","—"),
            "URL": n.get("url") or "local", "Local": "✅" if n.get("is_local") else "❌",
            "Max VPS": n.get("total_vps","—"),
        })
        if n.get("stats"):
            s = n["stats"]
            e.add_field(name="CPU", value=f"{s.get('cpu','?')}%")
            e.add_field(name="RAM", value=f"{s.get('ram','?')}%")
        await interaction.followup.send(embed=e)

    @app_commands.command(name="node-create", description="Add a new node")
    @app_commands.describe(name="Node name", url="Agent URL", location="Location", api_key="Node agent API key")
    async def node_create(self, interaction: discord.Interaction, name: str, url: str, location: str = "", api_key: str = None):
        await interaction.response.defer()
        data = {"name": name, "url": url, "location": location}
        if api_key: data["api_key"] = api_key
        r = await api.post("/nodes", data)
        if r.get("success"):
            e = h.ok("Node Created", f"**{name}** (ID: `{r.get('node_id')}`)")
        else:
            e = h.err("Failed", r.get("error","?"))
        await interaction.followup.send(embed=e)

    @app_commands.command(name="node-delete", description="Delete a node")
    @app_commands.describe(node_id="Node ID")
    async def node_delete(self, interaction: discord.Interaction, node_id: int):
        await interaction.response.defer()
        r = await api.delete(f"/nodes/{node_id}")
        e = h.ok("Node Deleted") if r.get("success") else h.err("Failed", r.get("error","?"))
        await interaction.followup.send(embed=e)

    @app_commands.command(name="node-test", description="Test node agent connectivity")
    @app_commands.describe(node_id="Node ID")
    async def node_test(self, interaction: discord.Interaction, node_id: int):
        await interaction.response.defer()
        r = await api.post(f"/nodes/{node_id}/test-connection")
        if r.get("reachable"):
            e = h.ok("Node Reachable", r.get("message","Connection OK"))
        else:
            e = h.err("Unreachable", r.get("error","Connection failed"))
        await interaction.followup.send(embed=e)

    @app_commands.command(name="node-exec", description="Execute command on node host")
    @app_commands.describe(node_id="Node ID", command="Shell command")
    async def node_exec(self, interaction: discord.Interaction, node_id: int, command: str):
        await interaction.response.defer()
        r = await api.post(f"/nodes/{node_id}/execute", {"command": command})
        if r.get("success"):
            output = r.get("output", "(no output)")
            if len(output) > 1900:
                output = output[:1900] + "\n… (truncated)"
            e = h.ok(f"Node #{node_id}", f"```\n{output}\n```")
        else:
            e = h.err("Failed", r.get("error","?"))
        await interaction.followup.send(embed=e)


async def setup(bot: commands.Bot):
    await bot.add_cog(NodesCog(bot))
