module.exports = {
  apps: [
    {
      name: "hvm-panel",
      script: "hvm.py",
      cwd: "./",
      interpreter: "python",
      env: {
        "FLASK_ENV": "production",
        "YOUR_SERVER_IP": "127.0.0.1"
      },
      log_date_format: "YYYY-MM-DD HH:mm Z",
      error_file: "logs/panel-error.log",
      out_file: "logs/panel-out.log"
    },
    {
      name: "hvm-discord-bot",
      script: "bot.py",
      cwd: "./bot",
      interpreter: "python",
      env: {
        "PYTHONUNBUFFERED": "1"
      },
      log_date_format: "YYYY-MM-DD HH:mm Z",
      error_file: "../logs/bot-error.log",
      out_file: "../logs/bot-out.log",
      depends_on: "hvm-panel"
    }
  ]
};
