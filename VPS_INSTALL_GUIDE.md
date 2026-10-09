# Anime Cloud Panel — VPS Installation Guide

This guide installs the existing Anime Cloud Panel from GitHub on an Ubuntu VPS. Commands below target Ubuntu 22.04/24.04 with a sudo-capable account.

> **Security warning:** This panel can expose powerful VPS-management functions. Do not publish it with default credentials or without HTTPS and firewall rules. Review the code and permissions before giving it access to production hosts.

## 1. Prepare the VPS

Connect over SSH, then install the required tools:

```bash
sudo apt update
sudo apt upgrade -y
sudo apt install -y git python3 python3-venv python3-pip build-essential nginx
```

## 2. Download the repository

```bash
sudo mkdir -p /opt/anime-cloud-panel
sudo chown "$USER":"$USER" /opt/anime-cloud-panel
git clone https://github.com/sureshkumak26-art/Hvm.git /opt/anime-cloud-panel
cd /opt/anime-cloud-panel
```

If the directory already exists, use `cd /opt/anime-cloud-panel && git pull` to update it. Back up your database/configuration before updating a live installation.

## 3. Install Python dependencies

```bash
cd /opt/anime-cloud-panel
python3 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip wheel
pip install -r requirements.txt
```

If a dependency fails to build, read the complete error before continuing; do not skip security-related dependencies blindly.

## 4. Create the server environment file

Generate a strong secret and API key. Keep both private:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Create a protected environment file:

```bash
sudo nano /etc/anime-cloud-panel.env
```

Add the following, replacing every example value with your own:

```dotenv
PANEL_NAME=Anime Cloud Panel
SECRET_KEY=PASTE_A_LONG_RANDOM_SECRET_HERE
PANEL_API_BASE=http://127.0.0.1:5000/api/v1
PANEL_API_KEY=PASTE_A_DIFFERENT_RANDOM_API_KEY_HERE
DISCORD_TOKEN=
ADMIN_USER_IDS=
```

Save, then restrict access:

```bash
sudo chown root:root /etc/anime-cloud-panel.env
sudo chmod 600 /etc/anime-cloud-panel.env
```

Set `DISCORD_TOKEN` and `ADMIN_USER_IDS` only if you plan to run the Discord bot. `ADMIN_USER_IDS` must be comma-separated numeric Discord user IDs. The panel reads environment variables from its process; the systemd service below loads this file.

**Important:** Before public deployment, inspect the login code and explicitly set/change the panel's administrator username and password using the configuration mechanism supported by the checked-out version. Never assume the default `admin/admin` credentials are safe. If the application does not expose a secure way to change them, do not expose it publicly until that is fixed.

## 5. Test the panel locally

```bash
cd /opt/anime-cloud-panel
source venv/bin/activate
set -a
source /etc/anime-cloud-panel.env
set +a
python hvm.py
```

From the VPS, test in another SSH session:

```bash
curl -I http://127.0.0.1:5000/
```

Stop the test process with `Ctrl+C` after confirming it responds.

## 6. Run the panel with systemd

Create a service:

```bash
sudo nano /etc/systemd/system/anime-cloud-panel.service
```

Paste:

```ini
[Unit]
Description=Anime Cloud Panel
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/anime-cloud-panel
EnvironmentFile=/etc/anime-cloud-panel.env
Environment=PYTHONUNBUFFERED=1
ExecStart=/opt/anime-cloud-panel/venv/bin/python /opt/anime-cloud-panel/hvm.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now anime-cloud-panel
sudo systemctl status anime-cloud-panel --no-pager
sudo journalctl -u anime-cloud-panel -n 100 --no-pager
```

The panel should listen on port 5000. Keep this port private; expose only HTTP/HTTPS through Nginx.

## 7. Configure a domain and HTTPS

Point a domain or subdomain (for example, `panel.example.com`) to the VPS public IP. Then create an Nginx site:

```bash
sudo nano /etc/nginx/sites-available/anime-cloud-panel
```

Use this basic reverse-proxy configuration:

```nginx
server {
    listen 80;
    server_name panel.example.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600;
    }
}
```

Replace `panel.example.com` with your real domain, then enable the site:

```bash
sudo ln -s /etc/nginx/sites-available/anime-cloud-panel /etc/nginx/sites-enabled/anime-cloud-panel
sudo nginx -t
sudo systemctl reload nginx
```

Install Certbot and issue a TLS certificate after DNS points to this VPS:

```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d panel.example.com
```

Allow SSH and web traffic in your provider firewall and UFW. Do **not** open port 5000 to the public internet:

```bash
sudo ufw allow OpenSSH
sudo ufw allow 'Nginx Full'
sudo ufw enable
sudo ufw status
```

## 8. Optional: run the Discord bot

The bot uses the same repository-root environment file and connects to the panel API locally. First ensure `DISCORD_TOKEN`, `PANEL_API_KEY`, and `ADMIN_USER_IDS` are correctly configured in `/etc/anime-cloud-panel.env`.

Create a bot service:

```bash
sudo nano /etc/systemd/system/anime-cloud-discord-bot.service
```

Paste:

```ini
[Unit]
Description=Anime Cloud Panel Discord Bot
After=network.target anime-cloud-panel.service
Requires=anime-cloud-panel.service

[Service]
Type=simple
WorkingDirectory=/opt/anime-cloud-panel
EnvironmentFile=/etc/anime-cloud-panel.env
Environment=PYTHONUNBUFFERED=1
ExecStart=/opt/anime-cloud-panel/venv/bin/python /opt/anime-cloud-panel/bot/bot.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Then enable it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now anime-cloud-discord-bot
sudo systemctl status anime-cloud-discord-bot --no-pager
sudo journalctl -u anime-cloud-discord-bot -n 100 --no-pager
```

Make sure the Discord bot has the required intents and is invited to the correct server. Only trusted Discord IDs should be included in `ADMIN_USER_IDS`.

## 9. Useful maintenance commands

```bash
# Panel logs
sudo journalctl -u anime-cloud-panel -f

# Bot logs
sudo journalctl -u anime-cloud-discord-bot -f

# Restart services
sudo systemctl restart anime-cloud-panel
sudo systemctl restart anime-cloud-discord-bot

# Update code (review changes and back up data first)
cd /opt/anime-cloud-panel
git pull
sudo systemctl restart anime-cloud-panel
sudo systemctl restart anime-cloud-discord-bot
```

## Troubleshooting

- **Service fails:** check `sudo journalctl -u anime-cloud-panel -n 150 --no-pager`.
- **Port 5000 already used:** stop the conflicting process or change the app's configured listening port and update Nginx accordingly.
- **Discord bot exits:** check the bot journal and verify `DISCORD_TOKEN` and `ADMIN_USER_IDS`.
- **Nginx 502:** confirm the panel service is active and responds to `curl -I http://127.0.0.1:5000/`.
- **Browser cannot connect:** verify DNS, provider firewall rules, UFW, Nginx configuration, and HTTPS certificate status.
- **Features report missing Python modules:** check the service logs and install the corresponding dependency in the virtual environment; do not install packages into system Python.

## Links

- Repository: https://github.com/sureshkumak26-art/Hvm
- GitHub Issues: https://github.com/sureshkumak26-art/Hvm/issues
