# HVM Discord Customer Onboarding

This feature adds two public slash commands to the existing HVM Discord bot:

- `/register` — sends the configured HVM Panel registration/login link privately.
- `/vm-request` — collects a KVM/LXC request and posts it to the configured private admin review channel.

## Configure

In the repository-root `.env` file:

```env
PANEL_REGISTER_URL=https://YOUR-REAL-PANEL-DOMAIN/register
VM_REQUEST_CHANNEL_ID=YOUR_PRIVATE_DISCORD_CHANNEL_ID
```

Use the actual registration URL supported by your panel (some panels use `/register`, others `/signup` or a combined login page). The bot cannot guess the correct URL. The request channel should be private to trusted administrators.

Restart the bot after editing `.env`:

```bash
python bot/bot.py
```

Then test `/register` and `/vm-request` in Discord.

## Important provisioning limitation

The current bot's existing `POST /api/v1/vps` command requires a panel database `user_id` and a `node_id`. A Discord snowflake is **not** the same as a panel user ID. Therefore this implementation safely collects requests but does not yet automatically create a VM or set its guest username/password. Do not map Discord IDs directly to panel user IDs.

For end-to-end automatic provisioning, add a server-side authenticated panel API workflow that:
1. Verifies the user has registered and links their Discord account to their panel account.
2. Applies plan/resource quotas and an admin approval or billing rule.
3. Provisions KVM/LXC through the panel's existing backend, not by exposing libvirt to Discord.
4. Generates a random initial guest password, sets it inside the guest, and returns it only in a private DM (or, preferably, asks the user to set it through a one-time password-reset link).
5. Stores only a password hash where applicable, redacts credentials from logs, and supports password rotation.

The current repository's panel backend route/identity mapping must be inspected and extended before enabling the last step. The request workflow is intentionally not advertised as completed VM provisioning.
