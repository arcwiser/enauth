import io
import json
import os
import sqlite3
from datetime import datetime

import aiohttp
import discord
from cryptography.fernet import Fernet
from discord import app_commands
from discord.ext import commands
from dotenv import load_dotenv

load_dotenv()

TOKEN = os.environ["DISCORD_BOT_TOKEN"]
FERNET = Fernet(os.environ["BOT_CONFIG_KEY"].encode())
DB_PATH = os.getenv("BOT_DB_PATH", "bot-config.db")
KEYGEN_ROLE = "keygen"


def db():
    connection = sqlite3.connect(DB_PATH)
    connection.execute(
        """CREATE TABLE IF NOT EXISTS guild_config (
               guild_id INTEGER PRIMARY KEY,
               server_url TEXT NOT NULL,
               app_id TEXT NOT NULL,
               api_key BLOB NOT NULL,
               configured_by INTEGER NOT NULL,
               configured_at TEXT NOT NULL
           )"""
    )
    return connection


def get_config(guild_id: int):
    with db() as connection:
        row = connection.execute(
            "SELECT server_url, app_id, api_key FROM guild_config WHERE guild_id = ?", (guild_id,)
        ).fetchone()
    if not row:
        return None
    return row[0].rstrip("/"), row[1], FERNET.decrypt(row[2]).decode()


def save_config(guild_id: int, server_url: str, app_id: str, api_key: str, user_id: int):
    encrypted = FERNET.encrypt(api_key.encode())
    with db() as connection:
        connection.execute(
            """INSERT INTO guild_config VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(guild_id) DO UPDATE SET server_url=excluded.server_url,
               app_id=excluded.app_id, api_key=excluded.api_key,
               configured_by=excluded.configured_by, configured_at=excluded.configured_at""",
            (guild_id, server_url.rstrip("/"), app_id, encrypted, user_id, datetime.utcnow().isoformat()),
        )


def delete_config(guild_id: int):
    with db() as connection:
        connection.execute("DELETE FROM guild_config WHERE guild_id = ?", (guild_id,))


def parse_duration(value: str):
    value = value.strip().lower()
    if value in {"lifetime", "forever", "never"}:
        return None
    units = {"m": 1 / 60, "h": 1, "d": 24, "w": 168, "y": 8760}
    if len(value) < 2 or value[-1] not in units:
        raise ValueError("Use formats such as 30m, 12h, 7d, 4w, 1y, or lifetime")
    amount = float(value[:-1])
    if amount <= 0:
        raise ValueError("Duration must be positive")
    return amount * units[value[-1]]


async def api(interaction: discord.Interaction, method: str, path: str, **kwargs):
    config = get_config(interaction.guild_id)
    if not config:
        raise RuntimeError("This server is not configured. The server owner must run /setup.")
    server, _, api_key = config
    headers = kwargs.pop("headers", {})
    headers["X-API-Key"] = api_key
    timeout = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.request(method, server + path, headers=headers, **kwargs) as response:
            content_type = response.headers.get("content-type", "")
            payload = await response.json() if "json" in content_type else {"detail": await response.text()}
            if response.status >= 400:
                raise RuntimeError(payload.get("detail", f"API error {response.status}"))
            return payload


def configured_app(interaction: discord.Interaction):
    config = get_config(interaction.guild_id)
    if not config:
        raise RuntimeError("This server is not configured. The server owner must run /setup.")
    return config[1]


async def require_keygen(interaction: discord.Interaction):
    if not interaction.guild or not isinstance(interaction.user, discord.Member):
        raise app_commands.CheckFailure("Commands can only be used inside a Discord server.")
    if not any(role.name.lower() == KEYGEN_ROLE for role in interaction.user.roles):
        raise app_commands.CheckFailure("You need the keygen role to use this command.")
    return True


keygen = app_commands.check(require_keygen)


class SetupModal(discord.ui.Modal, title="Connect EnAuth"):
    server_url = discord.ui.TextInput(label="Server URL", default="https://auth.olsoftwares.com", max_length=200)
    app_id = discord.ui.TextInput(label="Application ID", max_length=100)
    api_key = discord.ui.TextInput(label="EnAuth API key", placeholder="enauth_...", max_length=200)

    async def on_submit(self, interaction: discord.Interaction):
        if interaction.user.id != interaction.guild.owner_id:
            await interaction.response.send_message("Only the Discord server owner can configure the bot.", ephemeral=True)
            return
        server = str(self.server_url).rstrip("/")
        if not server.startswith("https://") or not str(self.api_key).startswith("enauth_"):
            await interaction.response.send_message("Use an HTTPS URL and a valid EnAuth API key.", ephemeral=True)
            return
        save_config(interaction.guild_id, server, str(self.app_id), str(self.api_key), interaction.user.id)
        try:
            await api(interaction, "GET", f"/api/integrations/apps/{self.app_id}")
        except Exception as exc:
            delete_config(interaction.guild_id)
            await interaction.response.send_message(f"Connection rejected: {exc}", ephemeral=True)
            return
        await interaction.response.send_message("EnAuth connected securely.", ephemeral=True)


class EnAuthBot(commands.Bot):
    def __init__(self):
        super().__init__(command_prefix=commands.when_mentioned, intents=discord.Intents.none())

    async def setup_hook(self):
        await self.tree.sync()


bot = EnAuthBot()


@bot.tree.command(description="Connect this Discord server to EnAuth")
@app_commands.guild_only()
async def setup(interaction: discord.Interaction):
    if interaction.user.id != interaction.guild.owner_id:
        await interaction.response.send_message("Only the Discord server owner can run setup.", ephemeral=True)
        return
    await interaction.response.send_modal(SetupModal())


@bot.tree.command(description="Remove this server's stored EnAuth integration")
@app_commands.guild_only()
async def disconnect(interaction: discord.Interaction):
    if interaction.user.id != interaction.guild.owner_id:
        await interaction.response.send_message("Only the Discord server owner can disconnect EnAuth.", ephemeral=True)
        return
    delete_config(interaction.guild_id)
    await interaction.response.send_message("Integration removed.", ephemeral=True)


@bot.tree.command(name="help", description="Show all EnAuth commands")
@keygen
async def help_command(interaction: discord.Interaction):
    commands_text = """**Licenses**
`/gen`, `/bulkgen`, `/license`, `/licenses`, `/ban`, `/unban`, `/extend`, `/deletekey`, `/resethwid`
**Sessions and security**
`/sessions`, `/killsession`, `/killallsessions`, `/hwids`, `/banhwid`, `/unbanhwid`, `/logs`
**Application**
`/status`, `/stats`, `/levels`, `/apps`, `/setapp`, `/builds`, `/uploadbuild`, `/deletebuild`
**Content**
`/news`, `/addnews`, `/deletenews`, `/variables`, `/setvariable`, `/deletevariable`
**Integration**
`/config`, `/whoami`, `/setup`, `/disconnect`

Every operational command requires the `keygen` role."""
    await interaction.response.send_message(commands_text, ephemeral=True)


@bot.tree.command(description="Generate one license key")
@keygen
async def gen(interaction: discord.Interaction, level: str, time: str, notes: str = ""):
    await interaction.response.defer(ephemeral=True)
    hours = parse_duration(time)
    app_id = configured_app(interaction)
    result = await api(interaction, "POST", f"/api/integrations/apps/{app_id}/licenses",
                       json={"product_level": level, "duration_hours": hours, "notes": notes, "count": 1})
    item = result["created"][0]
    await interaction.followup.send(f"License: `{item['key']}`\nExpires: `{item['expires_at'] or 'lifetime'}`", ephemeral=True)


@bot.tree.command(description="Generate multiple license keys")
@keygen
async def bulkgen(interaction: discord.Interaction, level: str, time: str, count: app_commands.Range[int, 1, 50], notes: str = ""):
    await interaction.response.defer(ephemeral=True)
    result = await api(interaction, "POST", f"/api/integrations/apps/{configured_app(interaction)}/licenses",
                       json={"product_level": level, "duration_hours": parse_duration(time), "notes": notes, "count": count})
    text = "\n".join(item["key"] for item in result["created"])
    await interaction.followup.send(file=discord.File(io.BytesIO(text.encode()), filename="licenses.txt"), ephemeral=True)


async def simple_license_action(interaction, action, identifier):
    await interaction.response.defer(ephemeral=True)
    result = await api(interaction, "POST", f"/api/integrations/apps/{configured_app(interaction)}/licenses/{identifier}/{action}")
    await interaction.followup.send(f"Done. License ID: `{result['id']}`", ephemeral=True)


@bot.tree.command(description="Ban a license and terminate its session")
@keygen
async def ban(interaction: discord.Interaction, license: str): await simple_license_action(interaction, "ban", license)


@bot.tree.command(description="Unban a license")
@keygen
async def unban(interaction: discord.Interaction, license: str): await simple_license_action(interaction, "unban", license)


@bot.tree.command(description="Reset a license's HWID bindings")
@keygen
async def resethwid(interaction: discord.Interaction, license: str): await simple_license_action(interaction, "reset-hwid", license)


@bot.tree.command(description="Extend a license")
@keygen
async def extend(interaction: discord.Interaction, license: str, time: str):
    await interaction.response.defer(ephemeral=True)
    hours = parse_duration(time)
    if hours is None: raise RuntimeError("Extension must have a duration")
    result = await api(interaction, "POST", f"/api/integrations/apps/{configured_app(interaction)}/licenses/{license}/extend", json={"hours": hours})
    await interaction.followup.send(f"New expiry: `{result['expires_at']}`", ephemeral=True)


@bot.tree.command(description="Permanently delete a license")
@keygen
async def deletekey(interaction: discord.Interaction, license: str, confirm: bool):
    if not confirm:
        await interaction.response.send_message("Set confirm to true to delete.", ephemeral=True); return
    await api(interaction, "DELETE", f"/api/integrations/apps/{configured_app(interaction)}/licenses/{license}")
    await interaction.response.send_message("License deleted.", ephemeral=True)


def render_rows(rows, fields):
    if not rows: return "No results."
    lines = []
    for row in rows:
        lines.append(" | ".join(str(row.get(field) or "-") for field in fields))
    return "```\n" + "\n".join(lines)[:1800] + "\n```"


@bot.tree.command(description="Show recent licenses")
@keygen
async def licenses(interaction: discord.Interaction, search: str = ""):
    rows = await api(interaction, "GET", f"/api/integrations/apps/{configured_app(interaction)}/licenses", params={"search": search or None})
    await interaction.response.send_message(render_rows(rows, ["id", "key", "status", "expires_at"]), ephemeral=True)


@bot.tree.command(description="Inspect a license")
@keygen
async def license(interaction: discord.Interaction, identifier: str):
    item = await api(interaction, "GET", f"/api/integrations/apps/{configured_app(interaction)}/licenses/{identifier}")
    await interaction.response.send_message(f"```json\n{json.dumps(item, indent=2)[:1800]}\n```", ephemeral=True)


@bot.tree.command(description="Show product levels")
@keygen
async def levels(interaction: discord.Interaction):
    item = await api(interaction, "GET", f"/api/integrations/apps/{configured_app(interaction)}")
    await interaction.response.send_message(render_rows(item["products"], ["level", "name", "is_active"]), ephemeral=True)


@bot.tree.command(description="Show EnAuth service status")
@keygen
async def status(interaction: discord.Interaction):
    config = get_config(interaction.guild_id)
    async with aiohttp.ClientSession() as session:
        async with session.get(config[0] + "/health") as response: payload = await response.text()
    await interaction.response.send_message(f"HTTP {response.status}: `{payload}`", ephemeral=True)


@bot.tree.command(description="Show application statistics")
@keygen
async def stats(interaction: discord.Interaction):
    item = await api(interaction, "GET", f"/api/integrations/apps/{configured_app(interaction)}/stats")
    await interaction.response.send_message(render_rows([item], list(item.keys())), ephemeral=True)


@bot.tree.command(description="List applications available to the integration")
@keygen
async def apps(interaction: discord.Interaction):
    rows = await api(interaction, "GET", "/api/integrations/apps")
    await interaction.response.send_message(render_rows(rows, ["id", "name", "version"]), ephemeral=True)


@bot.tree.command(description="Select the application managed by this Discord")
@keygen
async def setapp(interaction: discord.Interaction, app_id: str):
    server, _, api_key = get_config(interaction.guild_id)
    await api(interaction, "GET", f"/api/integrations/apps/{app_id}")
    save_config(interaction.guild_id, server, app_id, api_key, interaction.user.id)
    await interaction.response.send_message("Application updated.", ephemeral=True)


@bot.tree.command(description="Show this server's non-secret integration settings")
@keygen
async def config(interaction: discord.Interaction):
    server, app_id, _ = get_config(interaction.guild_id)
    await interaction.response.send_message(f"Server: `{server}`\nApp: `{app_id}`\nRequired role: `{KEYGEN_ROLE}`", ephemeral=True)


@bot.tree.command(description="Show your bot authorization")
@keygen
async def whoami(interaction: discord.Interaction):
    await interaction.response.send_message(f"Authorized as {interaction.user.mention} with the `{KEYGEN_ROLE}` role.", ephemeral=True)


@bot.tree.command(description="Show recent authentication logs")
@keygen
async def logs(interaction: discord.Interaction, limit: app_commands.Range[int, 1, 50] = 20):
    rows = await api(interaction, "GET", f"/api/integrations/apps/{configured_app(interaction)}/logs", params={"limit": limit})
    await interaction.response.send_message(render_rows(rows, ["timestamp", "action", "license_key", "ip"]), ephemeral=True)


@bot.tree.command(description="List active client sessions")
@keygen
async def sessions(interaction: discord.Interaction):
    rows = await api(interaction, "GET", f"/api/integrations/apps/{configured_app(interaction)}/sessions")
    await interaction.response.send_message(render_rows(rows, ["id", "license_key", "ip", "last_heartbeat"]), ephemeral=True)


@bot.tree.command(description="Terminate one client session")
@keygen
async def killsession(interaction: discord.Interaction, session_id: str):
    await api(interaction, "DELETE", f"/api/integrations/apps/{configured_app(interaction)}/sessions/{session_id}")
    await interaction.response.send_message("Session terminated.", ephemeral=True)


@bot.tree.command(description="Terminate every client session for this app")
@keygen
async def killallsessions(interaction: discord.Interaction, confirm: bool):
    if not confirm: await interaction.response.send_message("Set confirm to true.", ephemeral=True); return
    result = await api(interaction, "DELETE", f"/api/integrations/apps/{configured_app(interaction)}/sessions")
    await interaction.response.send_message(f"Terminated {result['deleted']} sessions.", ephemeral=True)


@bot.tree.command(description="Upload or replace a protected application build")
@keygen
async def uploadbuild(interaction: discord.Interaction, file: discord.Attachment, name: str = ""):
    await interaction.response.defer(ephemeral=True)
    data = await file.read()
    form = aiohttp.FormData()
    form.add_field("name", name or file.filename)
    form.add_field("file", data, filename=file.filename, content_type=file.content_type or "application/octet-stream")
    result = await api(interaction, "POST", f"/api/integrations/apps/{configured_app(interaction)}/builds", data=form)
    await interaction.followup.send(f"Uploaded `{result['name']}` ({result['size']} bytes).", ephemeral=True)


@bot.tree.command(description="List protected builds")
@keygen
async def builds(interaction: discord.Interaction):
    rows = await api(interaction, "GET", f"/api/integrations/apps/{configured_app(interaction)}/builds")
    await interaction.response.send_message(render_rows(rows, ["id", "name", "created_at"]), ephemeral=True)


@bot.tree.command(description="Delete a protected build")
@keygen
async def deletebuild(interaction: discord.Interaction, file_id: str, confirm: bool):
    if not confirm: await interaction.response.send_message("Set confirm to true.", ephemeral=True); return
    await api(interaction, "DELETE", f"/api/integrations/apps/{configured_app(interaction)}/builds/{file_id}")
    await interaction.response.send_message("Build deleted.", ephemeral=True)


@bot.tree.command(description="List application news")
@keygen
async def news(interaction: discord.Interaction):
    rows = await api(interaction, "GET", f"/api/integrations/apps/{configured_app(interaction)}/news")
    await interaction.response.send_message(render_rows(rows, ["id", "title", "created_at"]), ephemeral=True)


@bot.tree.command(description="Publish application news")
@keygen
async def addnews(interaction: discord.Interaction, title: str, content: str):
    result = await api(interaction, "POST", f"/api/integrations/apps/{configured_app(interaction)}/news", json={"title": title, "content": content})
    await interaction.response.send_message(f"News published: `{result['id']}`", ephemeral=True)


@bot.tree.command(description="Delete application news")
@keygen
async def deletenews(interaction: discord.Interaction, news_id: str):
    await api(interaction, "DELETE", f"/api/integrations/apps/{configured_app(interaction)}/news/{news_id}")
    await interaction.response.send_message("News deleted.", ephemeral=True)


@bot.tree.command(description="List global SDK variables")
@keygen
async def variables(interaction: discord.Interaction):
    rows = await api(interaction, "GET", "/api/integrations/variables")
    await interaction.response.send_message(render_rows(rows, ["name", "value", "created_at"]), ephemeral=True)


@bot.tree.command(description="Create or update a global SDK variable")
@keygen
async def setvariable(interaction: discord.Interaction, name: str, value: str, secret: bool = False):
    await api(interaction, "PUT", "/api/integrations/variables", json={"name": name, "value": value, "is_secret": secret})
    await interaction.response.send_message("Variable saved.", ephemeral=True)


@bot.tree.command(description="Delete a global SDK variable")
@keygen
async def deletevariable(interaction: discord.Interaction, name: str):
    await api(interaction, "DELETE", f"/api/integrations/variables/{name}")
    await interaction.response.send_message("Variable deleted.", ephemeral=True)


@bot.tree.command(description="List banned hardware IDs")
@keygen
async def hwids(interaction: discord.Interaction):
    rows = await api(interaction, "GET", f"/api/integrations/apps/{configured_app(interaction)}/banned-hwids")
    await interaction.response.send_message(render_rows(rows, ["hwid", "reason", "banned_at"]), ephemeral=True)


@bot.tree.command(description="Ban a hardware ID")
@keygen
async def banhwid(interaction: discord.Interaction, hwid: str, reason: str = "Discord bot"):
    await api(interaction, "POST", f"/api/integrations/apps/{configured_app(interaction)}/banned-hwids", json={"hwid": hwid, "reason": reason})
    await interaction.response.send_message("HWID banned.", ephemeral=True)


@bot.tree.command(description="Unban a hardware ID")
@keygen
async def unbanhwid(interaction: discord.Interaction, hwid: str):
    await api(interaction, "DELETE", f"/api/integrations/apps/{configured_app(interaction)}/banned-hwids/{hwid}")
    await interaction.response.send_message("HWID unbanned.", ephemeral=True)


@bot.tree.error
async def command_error(interaction: discord.Interaction, error):
    original = getattr(error, "original", error)
    message = str(original) or "Command failed."
    if interaction.response.is_done():
        await interaction.followup.send(message[:1900], ephemeral=True)
    else:
        await interaction.response.send_message(message[:1900], ephemeral=True)


if __name__ == "__main__":
    bot.run(TOKEN, log_handler=None)
