# EnAuth Discord Bot

The bot provides private slash commands for license, session, build, news,
variable, and HWID management. Operational commands require a Discord role
named exactly `keygen` (matching is case-insensitive). Only the Discord server
owner can run `/setup` or `/disconnect`.

License operations include `/bulkgen` (up to 500 keys), `/deletekey`,
`/revealkey`, `/license`, `/keyhistory`, and `/extendproduct`. Use
`/extendproduct key:all ... confirm:true` to extend every non-lifetime license
that owns the selected product. `/addproduct` asks for the license and duration,
then displays a product dropdown instead of requiring a product ID.

Operational controls include `/pauseapp` and `/resumeapp`. Resuming first shows
a compensation preview unless `confirm:true` is supplied. `/resellers` lists
reseller IDs and `/creditreseller` credits a balance after explicit
confirmation. These higher-impact commands require an `admin`-scope EnAuth API
key in addition to the Discord `keygen` role.

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

```bash
cp enauth-bot.service.example /etc/systemd/system/enauth-bot.service
systemctl daemon-reload
systemctl enable --now enauth-bot
journalctl -u enauth-bot -f
```

Invite the bot with `bot` and `applications.commands` scopes. Create the
`keygen` role, assign it only to trusted staff, then have the Discord server
owner run `/setup`.
