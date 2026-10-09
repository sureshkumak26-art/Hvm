# BreezeVM Panel Discord Bot

A complete Discord bot for managing the BreezeVM Panel via its REST API.

## Setup Instructions

1. **Get a Discord Bot Token**
   - Go to the [Discord Developer Portal](https://discord.com/developers/applications).
   - Create a new application, add a Bot, and copy the **Token**.
   - Ensure the bot has the `Message Content Intent` enabled (under the Bot tab).
   - Invite the bot to your server using the URL Generator (OAuth2) with the `bot` and `applications.commands` scopes.

2. **Configure the Bot**
   - Open `config.py` in this folder.
   - Replace `YOUR_DISCORD_BOT_TOKEN_HERE` with your actual bot token.
   - The API base and API key are already pre-configured to point to your local panel (`http://127.0.0.1:5000/api/v1`) using the master API key.
   - (Optional) Set `ADMIN_USER_IDS` to a list of Discord user IDs to restrict who can use these commands. (e.g., `ADMIN_USER_IDS = [123456789012345678]`). If left empty, anyone in the server can use them.

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the Bot**
   ```bash
   python bot.py
   ```
   *Note: On its first run, it will automatically sync all the slash commands to Discord. This might take a few seconds.*

## Features

The bot uses Discord's modern Slash Commands (`/`) to provide an interactive and responsive experience. It includes 4 modules (Cogs):

- **VPS Management (`/vps-...`)**: Full control over VPS instances. List, create, stop, start, restart, execute shell commands, suspend, resize, check live stats, etc.
- **Node Management (`/node-...`)**: Manage LXD node servers. List nodes, add new ones, check connectivity, and execute commands directly on the host nodes.
- **User Management (`/user-...`)**: Manage panel clients. Create users, reset passwords, delete, or update roles.
- **System & Admin (`/panel-stats`, `/system-info`, etc.)**: View host machine stats, manage backups, enable maintenance mode, search across the panel, and access emergency controls.

Type `/help` in Discord to see the full list of commands and options.
