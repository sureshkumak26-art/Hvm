"""User management cog."""

from __future__ import annotations
import discord
from discord import app_commands
from discord.ext import commands
import api, helpers as h
from config import CLR_INFO


class UsersCog(commands.Cog, name="Users"):
    def __init__(self, bot: commands.Bot):
        self.bot = bot

    @app_commands.command(name="users-list", description="List all panel users")
    async def users_list(self, interaction: discord.Interaction):
        await interaction.response.defer()
        r = await api.get("/users")
        if not r.get("success"):
            return await interaction.followup.send(embed=h.err("Failed", r.get("error","?")))
        users = r.get("users", [])
        e = discord.Embed(title=f"👥 Users ({len(users)})", color=CLR_INFO)
        for u in users[:25]:
            role = "🛡️ Admin" if u.get("is_admin") else "👤 User"
            e.add_field(name=f"#{u['id']} — {u['username']}", value=f"{role}  •  {u.get('email','—')}", inline=False)
        await interaction.followup.send(embed=e)

    @app_commands.command(name="user-info", description="Get user details")
    @app_commands.describe(user_id="User ID")
    async def user_info(self, interaction: discord.Interaction, user_id: int):
        await interaction.response.defer()
        r = await api.get(f"/users/{user_id}")
        if not r.get("success"):
            return await interaction.followup.send(embed=h.err("Not Found", r.get("error","?")))
        u = r["user"]
        e = h.field_embed(f"👤 {u['username']}", {
            "ID": u["id"], "Email": u.get("email","—"), "Admin": "✅" if u.get("is_admin") else "❌",
            "VPS Count": u.get("vps_count", 0), "Created": str(u.get("created_at","?"))[:19],
            "Last Login": str(u.get("last_login","—"))[:19],
        })
        await interaction.followup.send(embed=e)

    @app_commands.command(name="user-create", description="Create a new user")
    @app_commands.describe(username="Username", email="Email", password="Password", is_admin="Admin?")
    async def user_create(self, interaction: discord.Interaction, username: str, email: str, password: str, is_admin: bool = False):
        await interaction.response.defer(ephemeral=True)
        r = await api.post("/users", {"username": username, "email": email, "password": password, "is_admin": is_admin})
        if r.get("success"):
            e = h.ok("User Created", f"**{username}** (ID: `{r.get('user_id')}`) created.")
        else:
            e = h.err("Failed", r.get("error","?"))
        await interaction.followup.send(embed=e, ephemeral=True)

    @app_commands.command(name="user-delete", description="Delete a user")
    @app_commands.describe(user_id="User ID")
    async def user_delete(self, interaction: discord.Interaction, user_id: int):
        await interaction.response.defer()
        r = await api.delete(f"/users/{user_id}")
        e = h.ok("User Deleted", f"User **#{user_id}** deleted.") if r.get("success") else h.err("Failed", r.get("error","?"))
        await interaction.followup.send(embed=e)

    @app_commands.command(name="user-reset-password", description="Reset a user's password")
    @app_commands.describe(user_id="User ID", new_password="New password (min 6 chars)")
    async def user_reset_password(self, interaction: discord.Interaction, user_id: int, new_password: str):
        await interaction.response.defer(ephemeral=True)
        r = await api.post(f"/users/{user_id}/reset-password", {"new_password": new_password})
        e = h.ok("Password Reset", r.get("message","Done")) if r.get("success") else h.err("Failed", r.get("error","?"))
        await interaction.followup.send(embed=e, ephemeral=True)

    @app_commands.command(name="user-update", description="Update user email/admin status")
    @app_commands.describe(user_id="User ID", email="New email", is_admin="Admin?")
    async def user_update(self, interaction: discord.Interaction, user_id: int, email: str = None, is_admin: bool = None):
        await interaction.response.defer()
        data = {}
        if email: data["email"] = email
        if is_admin is not None: data["is_admin"] = is_admin
        if not data:
            return await interaction.followup.send(embed=h.err("Missing Args", "Provide email or is_admin"))
        r = await api.put(f"/users/{user_id}", data)
        e = h.ok("User Updated") if r.get("success") else h.err("Failed", r.get("error","?"))
        await interaction.followup.send(embed=e)


async def setup(bot: commands.Bot):
    await bot.add_cog(UsersCog(bot))
