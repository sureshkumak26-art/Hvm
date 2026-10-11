# HVM / Anime Cloud Discord bot

This bot extends the existing HVM panel bot. It does not replace the panel.

## Mining detection (KVM + LXC)

The bot calls the authenticated HVM node agent at `NODE_AGENT_URL/security/scan` on a schedule and exposes `/mining-scan` for an authorized manual scan. The node agent checks running KVM guests through QEMU Guest Agent and LXC guests through the LXC CLI. It stops a whole guest only when a known miner process signature and a mining-pool/algorithm indicator match. A KVM guest without QEMU Guest Agent is reported as unsupported and is **not** stopped.

**Automatic containment is disruptive:** a confirmed match powers off the entire VM or force-stops the entire container. Review the evidence and guest logs before restarting it. The detector is signature-based, not a full malware scanner; test it in a lab first.

### Configure the bot

1. Copy the root `.env.example` to `.env`.
2. Set `DISCORD_TOKEN`, `ADMIN_USER_IDS`, `NODE_AGENT_URL`, `NODE_AGENT_TOKEN`, and `MINING_ALERT_CHANNEL_ID`.
3. Use a strong random token for `HVM_NODE_TOKEN` on the node agent and put the **same** value in `NODE_AGENT_TOKEN` on the bot host.
4. Keep the agent on loopback/private networking or protect it with TLS and firewall rules. Do not expose port 8787 publicly.
5. Install and run:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r bot/requirements.txt
python bot/bot.py
```

The bot schedules scans every `MINING_SCAN_INTERVAL_SECONDS` (minimum 60 seconds, default 120) and sends containment alerts to the configured Discord text channel. Slash commands are restricted to IDs in `ADMIN_USER_IDS`.

## Node prerequisites

On every KVM node, install and enable QEMU Guest Agent in each guest you want to inspect. The agent must be reachable through libvirt. On LXC nodes, the `lxc` CLI must be installed and configured for the correct LXD/Incus daemon. Run the node agent with least privilege that still permits `virsh` and `lxc` inspection/stop operations.

## Security

Never commit real `.env` files, Discord tokens, panel API keys, or node tokens. Rotate any key that was ever committed to source control.
