"""Shared helpers — embed builders, pagination, permission check."""

from __future__ import annotations
import discord
from config import ADMIN_USER_IDS, CLR_OK, CLR_ERR, CLR_INFO


def is_admin(interaction: discord.Interaction) -> bool:
    if not ADMIN_USER_IDS:
        return True
    return interaction.user.id in ADMIN_USER_IDS


def ok(title: str, desc: str = "", **kw) -> discord.Embed:
    e = discord.Embed(title=f"✅ {title}", description=desc, color=CLR_OK, **kw)
    return e


def err(title: str, desc: str = "") -> discord.Embed:
    return discord.Embed(title=f"❌ {title}", description=desc, color=CLR_ERR)


def info(title: str, desc: str = "") -> discord.Embed:
    return discord.Embed(title=title, description=desc, color=CLR_INFO)


def field_embed(title: str, fields: dict, *, inline: bool = True, color: int = CLR_INFO) -> discord.Embed:
    e = discord.Embed(title=title, color=color)
    for k, v in fields.items():
        e.add_field(name=k, value=str(v) if v not in (None, "") else "—", inline=inline)
    return e


def fmt_status(s: str | None) -> str:
    m = {"running": "🟢 Running", "stopped": "🔴 Stopped", "installing": "🟡 Installing",
         "suspended": "🟠 Suspended", "transferring": "🔵 Transferring"}
    return m.get(s or "", s or "Unknown")
