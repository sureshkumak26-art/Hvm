# StrenoxCloud Panel Discord Bot — Configuration
# ========================================

# Discord Bot Token (get from https://discord.com/developers/applications)
DISCORD_TOKEN = "YOUR_DISCORD_BOT_TOKEN_HERE"

# StrenoxCloud Panel API
API_BASE = "http://127.0.0.1:5000/api/v1"
API_KEY  = "hvmpanel_6tkiDPpn5Tqn6q3Ecg5wAj65okpFca6xAY4ktOlPkcUM8aozy1SLFV0fx-UWIk9Y"

# Restrict bot commands to these Discord user IDs (empty = anyone can use)
ADMIN_USER_IDS: list[int] = []

# Embed colours
CLR_OK      = 0x34d399   # green
CLR_ERR     = 0xef4444   # red
CLR_WARN    = 0xfbbf24   # yellow
CLR_INFO    = 0x4facfe   # blue
CLR_PURPLE  = 0xc084fc   # purple
