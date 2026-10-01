# EnAuth Discord Bot

The bot provides private slash commands for license, session, build, news,
variable, and HWID management. Every protected command requires the exact role
configured through `BOT_ALLOWED_ROLE_ID`. Members holding that role can run
`/setup`, `/disconnect`, and the operational commands.

License operations include `/bulkgen` (up to 500 keys), `/deletekey`,
`/revealkey`, `/license`, `/keyhistory`, and `/extendproduct`. Use
`/extendproduct key:all ... confirm:true` to extend every non-lifetime license
that owns the selected product. `/addproduct` asks for the license and duration,
then displays a product dropdown instead of requiring a product ID.

Operational controls include `/pauseapp` and `/resumeapp`. Resuming first shows
a compensation preview unless `confirm:true` is supplied. `/resellers` lists
reseller IDs and `/creditreseller` credits a balance after explicit
confirmation. These higher-impact commands require an `admin`-scope EnAuth API
key in addition to the configured Discord role. Treat that role as privileged:
members who have it can replace or remove the Discord server's EnAuth connection.

The bot intentionally uses a revocable EnAuth API key instead of an application
secret. Create an `admin`-scope API key in the EnAuth dashboard. `/setup` opens
a private modal and stores that key encrypted with `BOT_CONFIG_KEY`.

## Ubuntu installation

```bash
cd /root/enauth/discord_bot
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Put the Discord bot token and generated encryption key in `.env`, then install
the service:

Enable Discord Developer Mode, right-click the role that should control the bot,
choose **Copy Role ID**, and put that number in `.env` as
`BOT_ALLOWED_ROLE_ID=...`.

```bash
cp enauth-bot.service.example /etc/systemd/system/enauth-bot.service
systemctl daemon-reload
systemctl enable --now enauth-bot
journalctl -u enauth-bot -f
```

Invite the bot with `bot` and `applications.commands` scopes. Assign the
configured role only to trusted staff, then have a member holding it run
`/setup`.
