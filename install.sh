#!/usr/bin/env bash
set -Eeuo pipefail

REPO_URL="https://github.com/sureshkumak26-art/Hvm.git"
APP_DIR="/opt/anime-cloud-panel"
ENV_FILE="/etc/anime-cloud-panel.env"
SERVICE_FILE="/etc/systemd/system/anime-cloud-panel.service"
NGINX_FILE="/etc/nginx/sites-available/anime-cloud-panel"

log() { printf '\n\033[1;36m[Anime Cloud Panel]\033[0m %s\n' "$*"; }
fail() { printf '\nERROR: %s\n' "$*" >&2; exit 1; }
trap 'fail "Installer stopped at line $LINENO. Review the error above before retrying."' ERR

[[ "$(id -u)" -eq 0 ]] || fail "Run as root, for example: curl -fsSL https://raw.githubusercontent.com/sureshkumak26-art/Hvm/main/install.sh | sudo bash"
[[ -r /etc/os-release ]] || fail "Cannot identify Linux distribution."
. /etc/os-release
[[ "${ID:-}" == "ubuntu" || "${ID:-}" == "debian" ]] || fail "Supported systems: Ubuntu or Debian."
[[ "${VERSION_ID%%.*}" =~ ^(22|24|12)$ ]] || log "This OS version is not the primary tested target; continuing best-effort."

if [[ -t 0 ]]; then
  read -r -p "Panel admin username [paneladmin]: " ADMIN_USER
  ADMIN_USER="${ADMIN_USER:-paneladmin}"
  while [[ -z "$ADMIN_USER" || "$ADMIN_USER" =~ [[:space:]] ]]; do
    read -r -p "Use a non-empty username without spaces: " ADMIN_USER
  done
  while true; do
    read -r -s -p "Set a strong panel admin password (minimum 16 characters): " ADMIN_PASS; printf '\n'
    [[ "${#ADMIN_PASS}" -ge 16 ]] && break
    printf 'Password must be at least 16 characters.\n'
  done
  read -r -s -p "Confirm admin password: " ADMIN_PASS_CONFIRM; printf '\n'
  [[ "$ADMIN_PASS" == "$ADMIN_PASS_CONFIRM" ]] || fail "Passwords did not match."
  read -r -p "Panel domain for HTTPS (e.g. panel.example.com), or leave blank for SSH-tunnel-only: " PANEL_DOMAIN
else
  fail "Run interactively so you can set a secure administrator password. Do not pipe this script into a non-interactive unattended job."
fi

[[ "$PANEL_DOMAIN" != *"/"* && "$PANEL_DOMAIN" != *" "* ]] || fail "Enter only a domain name, without a URL or spaces."
if [[ -n "$PANEL_DOMAIN" && ! "$PANEL_DOMAIN" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]; then
  fail "That domain does not look valid. Use a hostname such as panel.example.com."
fi

log "Installing system packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y git python3 python3-venv python3-pip build-essential libffi-dev libssl-dev nginx curl

if [[ -d "$APP_DIR/.git" ]]; then
  log "Updating existing repository in $APP_DIR"
  git -C "$APP_DIR" pull --ff-only origin main
elif [[ -e "$APP_DIR" ]]; then
  fail "$APP_DIR exists but is not a Git repository. Move it aside or back it up, then retry."
else
  git clone --depth 1 "$REPO_URL" "$APP_DIR"
fi

log "Installing Python dependencies"
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/python" -m pip install --upgrade pip wheel
"$APP_DIR/venv/bin/pip" install -r "$APP_DIR/requirements.txt"

SECRET_KEY="$("$APP_DIR/venv/bin/python" -c 'import secrets; print(secrets.token_urlsafe(48))')"
PANEL_API_KEY="$("$APP_DIR/venv/bin/python" -c 'import secrets; print(secrets.token_urlsafe(48))')"

if [[ -e "$ENV_FILE" ]]; then
  cp -a "$ENV_FILE" "${ENV_FILE}.backup.$(date +%Y%m%d%H%M%S)"
  log "Backed up existing environment file; keeping it intact. Check admin settings and keys manually."
else
  umask 077
  cat > "$ENV_FILE" <<EOF
PANEL_NAME=Anime Cloud Panel
SECRET_KEY=$SECRET_KEY
PANEL_API_BASE=http://127.0.0.1:5000/api/v1
PANEL_API_KEY=$PANEL_API_KEY
DISCORD_TOKEN=
ADMIN_USER_IDS=
MAIN_ADMIN_USERNAME=$ADMIN_USER
MAIN_ADMIN_PASSWORD=$ADMIN_PASS
MAIN_ADMIN_EMAIL=admin@localhost
HOST=127.0.0.1
PORT=5000
DEBUG_MODE=False
EOF
  chown root:root "$ENV_FILE"
  chmod 600 "$ENV_FILE"
fi
unset ADMIN_PASS ADMIN_PASS_CONFIRM SECRET_KEY PANEL_API_KEY

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Anime Cloud Panel
After=network.target

[Service]
Type=simple
WorkingDirectory=$APP_DIR
EnvironmentFile=$ENV_FILE
Environment=PYTHONUNBUFFERED=1
ExecStart=$APP_DIR/venv/bin/python $APP_DIR/hvm.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

if [[ -n "$PANEL_DOMAIN" ]]; then
  log "Configuring Nginx for $PANEL_DOMAIN"
  cat > "$NGINX_FILE" <<EOF
server {
    listen 80;
    server_name $PANEL_DOMAIN;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600;
    }
}
EOF
  ln -sfn "$NGINX_FILE" /etc/nginx/sites-enabled/anime-cloud-panel
  nginx -t
  systemctl reload nginx || systemctl restart nginx
fi

systemctl daemon-reload
systemctl enable --now anime-cloud-panel
sleep 2
systemctl --no-pager --full status anime-cloud-panel || true

if [[ -n "$PANEL_DOMAIN" ]]; then
  log "Installing Certbot and requesting HTTPS certificate"
  apt-get install -y certbot python3-certbot-nginx
  certbot --nginx --non-interactive --agree-tos --register-unsafely-without-email -d "$PANEL_DOMAIN" || {
    printf '\nHTTPS setup did not complete. Confirm DNS points to this server and ports 80/443 are reachable, then run:\n'
    printf '  sudo certbot --nginx -d %s\n' "$PANEL_DOMAIN"
  }
  printf '\nPanel URL: https://%s\n' "$PANEL_DOMAIN"
else
  printf '\nPanel installed and bound to localhost only.\n'
  printf 'From your computer, create an SSH tunnel:\n'
  printf '  ssh -L 5000:127.0.0.1:5000 YOUR_USER@YOUR_SERVER_IP\n'
  printf 'Then open http://127.0.0.1:5000 in your browser.\n'
  printf 'To publish it, rerun/configure Nginx with a real domain and HTTPS first.\n'
fi

printf '\nUseful commands:\n'
printf '  sudo systemctl status anime-cloud-panel\n'
printf '  sudo journalctl -u anime-cloud-panel -n 100 --no-pager\n'
printf '  sudo systemctl restart anime-cloud-panel\n'
printf '\nSecurity: review the application before exposing it publicly; keep port 5000 private and never share /etc/anime-cloud-panel.env.\n'
