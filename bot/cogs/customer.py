"""Customer-facing registration link and VM request workflow."""
from __future__ import annotations

import logging
import discord
from discord import app_commands
from discord.ext import commands

from config import PANEL_REGISTER_URL, VM_REQUEST_CHANNEL_ID

log = logging.getLogger("hvm-customer")


class CustomerCommands(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot

    @app_commands.command(name="register", description="Get the HVM Panel registration/login link")
    async def register(self, interaction: discord.Interaction) -> None:
        if not PANEL_REGISTER_URL:
            return await interaction.response.send_message(
                "Panel registration link is not configured yet. Please contact an administrator.",
                ephemeral=True,
            )
        view = discord.ui.View()
        view.add_item(discord.ui.Button(
            label="Open HVM Panel",
            style=discord.ButtonStyle.link,
            url=PANEL_REGISTER_URL,
        ))
        await interaction.response.send_message(
            "Register or sign in to your HVM Panel account here. After registering, use "
            "`/vm-request` to request a KVM VM or LXC container. Never share your panel password in Discord.",
            view=view,
            ephemeral=True,
        )

    @app_commands.command(name="vm-request", description="Request a KVM VM or LXC container")
    @app_commands.describe(
        kind="Virtual machine type",
        hostname="Desired hostname (letters, numbers, and hyphens)",
        cpu="Requested CPU cores",
        ram_gb="Requested RAM in GB",
        storage_gb="Requested disk in GB",
        os_image="OS image, for example Ubuntu 24.04",
    )
    @app_commands.choices(kind=[
        app_commands.Choice(name="KVM Virtual Machine", value="kvm"),
        app_commands.Choice(name="LXC Container", value="lxc"),
    ])
    async def vm_request(
        self,
        interaction: discord.Interaction,
        kind: app_commands.Choice[str],
        hostname: str,
        cpu: app_commands.Range[int, 1, 16],
        ram_gb: app_commands.Range[int, 1, 64],
        storage_gb: app_commands.Range[int, 5, 500],
        os_image: str = "Ubuntu 24.04",
    ) -> None:
        # This command is intentionally a request, not direct root-level provisioning.
        # The current panel API requires a panel database user_id and node_id; a Discord
        # user ID is not interchangeable with the panel user ID.
        safe_host = hostname.strip().lower()
        if not safe_host or len(safe_host) > 40 or not all(c.isalnum() or c == "-" for c in safe_host):
            return await interaction.response.send_message(
                "Hostname must be 1–40 characters using only letters, numbers, and hyphens.",
                ephemeral=True,
            )
        if not VM_REQUEST_CHANNEL_ID:
            return await interaction.response.send_message(
                "VM requests are not configured yet. Please contact an administrator.",
                ephemeral=True,
            )
        channel = self.bot.get_channel(VM_REQUEST_CHANNEL_ID)
        if channel is None:
            try:
                channel = await self.bot.fetch_channel(VM_REQUEST_CHANNEL_ID)
            except Exception:
                log.exception("Cannot resolve VM request channel")
                return await interaction.response.send_message(
                    "The request channel is unavailable. Please try again later.",
                    ephemeral=True,
                )
        embed = discord.Embed(
            title="New VM provisioning request",
            color=0x8B5CF6,
            description="Review this request and verify the user's HVM Panel registration before provisioning.",
        )
        embed.add_field(name="Discord user", value=f"{interaction.user.mention}\nID: `{interaction.user.id}`", inline=False)
        embed.add_field(name="Type", value=kind.name, inline=True)
        embed.add_field(name="Hostname", value=f"`{safe_host}`", inline=True)
        embed.add_field(name="Resources", value=f"CPU: {cpu} cores\nRAM: {ram_gb} GB\nDisk: {storage_gb} GB", inline=True)
        embed.add_field(name="OS image", value=os_image[:100], inline=True)
        embed.set_footer(text="Do not post passwords or API keys in this channel.")
        try:
            await channel.send(embed=embed)
        except Exception:
            log.exception("Could not send VM request")
            return await interaction.response.send_message(
                "Could not submit your request. Please contact an administrator.",
                ephemeral=True,
            )
        await interaction.response.send_message(
            "Your VM request was sent to the HVM administrators. This is a request only; "
            "the VM is not provisioned until the panel user and node are verified.",
            ephemeral=True,
        )


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(CustomerCommands(bot))
