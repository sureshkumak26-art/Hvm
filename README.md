# Anime Cloud Panel — existing HVM panel

This repository contains the existing Flask VPS panel, not a separate replacement app. Branding, background settings, and the existing Discord bot are being updated in place.

## Panel installation
Quick installer for Ubuntu/Debian (run from an interactive SSH terminal):
```bash
curl -fsSL https://raw.githubusercontent.com/sureshkumak26-art/Hvm/main/install.sh -o /tmp/anime-cloud-panel-install.sh
sudo bash /tmp/anime-cloud-panel-install.sh
```
The installer prompts for a strong admin password and an optional domain. Review [install.sh](install.sh) before running it.

- **[Panel Install Guide](PANEL_INSTALL_GUIDE.md)** — install from GitHub, configure environment variables, run the panel with systemd, configure Nginx + HTTPS, and optionally run the Discord bot.
- Repository: https://github.com/sureshkumak26-art/Hvm

## Appearance
- User profile supports dark, light, and automatic themes.
- Admin Settings supports an optional custom image background URL.
- Image background takes priority over video background when enabled.

## Discord VPS bot
Configure the root `.env` using `.env.example`. Set `DISCORD_TOKEN`, `PANEL_API_KEY`, and `ADMIN_USER_IDS` (comma-separated Discord user IDs). Then install dependencies and run `python bot/bot.py` after the panel is online.

## Security
A previous version included a panel API key in source code. Consider it compromised and rotate/revoke it in the panel before deploying. Never commit your real `.env`, Discord token, or API key. The bot now denies administrative slash commands unless a Discord user ID is explicitly allowlisted.
