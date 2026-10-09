import io
import json
import logging
import os
import sqlite3
from datetime import datetime

import aiohttp
import discord
from cryptography.fernet import Fernet
from discord import app_commands
from discord.ext import commands, tasks
from dotenv import load_dotenv

load_dotenv()

TOKEN = os.environ["DISCORD_BOT_TOKEN"]
FERNET = Fernet(os.environ["BOT_CONFIG_KEY"].encode())
DB_PATH = os.getenv("BOT_DB_PATH", "bot-config.db")
ALLOWED_ROLE_ID_TEXT = os.getenv("BOT_ALLOWED_ROLE_ID", "").strip()
if not ALLOWED_ROLE_ID_TEXT.isdigit():
    raise RuntimeError("BOT_ALLOWED_ROLE_ID must be set to a Discord role ID")
ALLOWED_ROLE_ID = int(ALLOWED_ROLE_ID_TEXT)
logger = logging.getLogger("enauth.discord_bot")


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


def get_all_configs():
    with db() as connection:
        rows = connection.execute("SELECT server_url, app_id, api_key FROM guild_config").fetchall()
    return [(row[0].rstrip("/"), row[1], FERNET.decrypt(row[2]).decode()) for row in rows]


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
    headers["X-Discord-Key"] = api_key
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


def has_bot_access(interaction: discord.Interaction) -> bool:
    if not interaction.guild or not isinstance(interaction.user, discord.Member):
        return False
    return any(role.id == ALLOWED_ROLE_ID for role in interaction.user.roles)


def detected_role_ids(interaction: discord.Interaction) -> str:
    if not isinstance(interaction.user, discord.Member):
        return "Discord did not resolve your account as a server member"
    role_ids = [str(role.id) for role in interaction.user.roles if not role.is_default()]
    return ", ".join(role_ids) if role_ids else "none"


async def require_keygen(interaction: discord.Interaction):
    if not interaction.guild or not isinstance(interaction.user, discord.Member):
        raise app_commands.CheckFailure("Commands can only be used inside a Discord server.")
    if not has_bot_access(interaction):
        raise app_commands.CheckFailure(
            f"Required role ID: `{ALLOWED_ROLE_ID}`\n"
            f"Role IDs Discord detected on your account: `{detected_role_ids(interaction)}`"
        )
    return True


keygen = app_commands.check(require_keygen)


class SetupModal(discord.ui.Modal, title="Connect EnAuth"):
    server_url = discord.ui.TextInput(label="Server URL", default="https://auth.olsoftwares.com", max_length=200)
    app_id = discord.ui.TextInput(label="Application ID", max_length=100)
    api_key = discord.ui.TextInput(label="Discord integration key", placeholder="enauth_discord_...", max_length=200)

    async def on_submit(self, interaction: discord.Interaction):
        if not has_bot_access(interaction):
            await interaction.response.send_message(
                f"You need the configured bot role (`{ALLOWED_ROLE_ID}`) to configure the bot.", ephemeral=True
            )
            return
        server = str(self.server_url).rstrip("/")
        if not server.startswith("https://") or not str(self.api_key).startswith("enauth_discord_"):
            await interaction.response.send_message("Use an HTTPS URL and a valid Discord integration key.", ephemeral=True)
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
        intents = discord.Intents.none()
        intents.guilds = True
        super().__init__(command_prefix=commands.when_mentioned, intents=intents)

    async def setup_hook(self):
        await self.tree.sync()
        self.integration_heartbeat.start()

    @tasks.loop(minutes=1)
    async def integration_heartbeat(self):
        timeout = aiohttp.ClientTimeout(total=15)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            for server, app_id, api_key in get_all_configs():
                try:
                    async with session.get(f"{server}/api/integrations/apps/{app_id}",
                                           headers={"X-Discord-Key": api_key}) as response:
                        await response.read()
                        if response.status >= 400:
                            logger.warning("EnAuth heartbeat rejected for app %s: HTTP %s", app_id, response.status)
                except Exception as exc:
                    logger.warning("EnAuth heartbeat failed for app %s: %s", app_id, exc)

    @integration_heartbeat.before_loop
    async def before_integration_heartbeat(self):
        await self.wait_until_ready()

    async def on_ready(self):
        logger.info("Connected to Discord as %s (%s)", self.user, self.user.id if self.user else "unknown")


bot = EnAuthBot()


@bot.tree.command(description="Connect this Discord server to EnAuth")
@app_commands.guild_only()
@keygen
async def setup(interaction: discord.Interaction):
    await interaction.response.send_modal(SetupModal())


@bot.tree.command(description="Remove this server's stored EnAuth integration")
@app_commands.guild_only()
@keygen
async def disconnect(interaction: discord.Interaction):
    delete_config(interaction.guild_id)
    await interaction.response.send_message("Integration removed.", ephemeral=True)


@bot.tree.command(name="help", description="Show all EnAuth commands")
@keygen
async def help_command(interaction: discord.Interaction):
    commands_text = """**Licenses**
`/gen`, `/bulkgen`, `/license`, `/revealkey`, `/licenses`, `/keyhistory`, `/ban`, `/unban`, `/extend`, `/extendproduct`, `/addproduct`, `/deletekey`, `/resethwid`
**Sessions and security**
`/sessions`, `/killsession`, `/killallsessions`, `/hwids`, `/banhwid`, `/unbanhwid`, `/logs`, `/securitysummary`, `/resetrequests`, `/reviewreset`
**Application**
`/status`, `/health`, `/stats`, `/sdkstatus`, `/expiring`, `/levels`, `/productstatus`, `/apps`, `/setapp`, `/pauseapp`, `/resumeapp`, `/builds`, `/upload`, `/uploadbuild`, `/deletebuild`
**Content**
`/news`, `/addnews`, `/deletenews`, `/variables`, `/setvariable`, `/deletevariable`
**Integration**
`/config`, `/whoami`, `/setup`, `/disconnect`

Use `/upload` for the normal guided path. Use `/uploadbuild` only when you need
advanced channel, platform, visibility, or replacement controls.

Every operational command requires the configured Discord role."""
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
async def bulkgen(interaction: discord.Interaction, level: str, time: str, count: app_commands.Range[int, 1, 500], notes: str = ""):
    await interaction.response.defer(ephemeral=True)
    result = await api(interaction, "POST", f"/api/integrations/apps/{configured_app(interaction)}/licenses",
                       json={"product_level": level, "duration_hours": parse_duration(time), "notes": notes, "count": count})
    text = "\n".join(item["key"] for item in result["created"])
    await interaction.followup.send(file=discord.File(io.BytesIO(text.encode()), filename="licenses.txt"), ephemeral=True)


async def simple_license_action(interaction, action, identifier):
    await interaction.response.defer(ephemeral=True)
    result = await api(interaction, "POST", f"/api/integrations/apps/{configured_app(interaction)}/licenses/{identifier}/{action}")
    await interaction.followup.send(f"Done. License ID: `{result['id']}`", ephemeral=True)


class DangerConfirmView(discord.ui.View):
    def __init__(self, requester_id: int, prompt: str, action):
        super().__init__(timeout=90)
        self.requester_id = requester_id
        self.prompt = prompt
        self.action = action

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.requester_id or not has_bot_access(interaction):
            await interaction.response.send_message("This confirmation belongs to another authorized user.", ephemeral=True)
            return False
        return True

    @discord.ui.button(label="Confirm", style=discord.ButtonStyle.danger)
    async def confirm(self, interaction: discord.Interaction, button: discord.ui.Button):
        for child in self.children:
            child.disabled = True
        await interaction.response.edit_message(content=f"Processing: {self.prompt}", view=self)
        try:
            message = await self.action(interaction)
            await interaction.followup.send(message, ephemeral=True)
        except Exception as exc:
            await interaction.followup.send(f"Action failed: {exc}", ephemeral=True)
        self.stop()

    @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary)
    async def cancel(self, interaction: discord.Interaction, button: discord.ui.Button):
        for child in self.children:
            child.disabled = True
        await interaction.response.edit_message(content="Action cancelled.", view=self)
        self.stop()


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
async def deletekey(interaction: discord.Interaction, license: str):
    async def perform(button_interaction):
        await api(button_interaction, "DELETE", f"/api/integrations/apps/{configured_app(button_interaction)}/licenses/{license}")
        return f"License `{license}` was permanently deleted."
    await interaction.response.send_message(
        f"Permanently delete `{license}`? This cannot be undone.",
        view=DangerConfirmView(interaction.user.id, f"delete license {license}", perform), ephemeral=True,
    )


def render_rows(rows, fields):
    if not rows: return "No results."
    lines = []
    for row in rows:
        lines.append(" | ".join(str(row.get(field) or "-") for field in fields))
    return "```\n" + "\n".join(lines)[:1800] + "\n```"


def operational_embed(snapshot):
    app = snapshot.get("app", {})
    licenses = snapshot.get("licenses", {})
    sessions = snapshot.get("sessions", {})
    activity = snapshot.get("activity_24h", {})
    paused = bool(app.get("is_paused"))
    embed = discord.Embed(
        title=f"{app.get('name', 'EnAuth')} operations",
        description="Paused" if paused else "Operational",
        color=discord.Color.orange() if paused else discord.Color.green(),
        timestamp=datetime.utcnow(),
    )
    embed.add_field(name="Licenses", value=(
        f"Total **{licenses.get('total') or 0}**\n"
        f"Active **{licenses.get('active') or 0}** · Banned **{licenses.get('banned') or 0}**"
    ))
    embed.add_field(name="Live usage", value=(
        f"Sessions **{sessions.get('active_sessions') or 0}**\n"
        f"Users **{sessions.get('active_users') or 0}**"
    ))
    embed.add_field(name="Last 24 hours", value=(
        f"Events **{activity.get('authentications') or 0}**\n"
        f"Failures **{activity.get('failures') or 0}**"
    ))
    embed.set_footer(text=f"App {app.get('id', 'unknown')} · Version {app.get('version', 'unknown')}")
    return embed


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


@bot.tree.command(description="Reveal a stored license key")
@keygen
async def revealkey(interaction: discord.Interaction, key: str):
    item = await api(interaction, "GET", f"/api/integrations/apps/{configured_app(interaction)}/licenses/{key}")
    await interaction.response.send_message(
        f"License ID: `{item['id']}`\nFull key: `{item['key']}`\nStatus: `{item['status']}`", ephemeral=True
    )


@bot.tree.command(description="Show a license's audit history")
@keygen
async def keyhistory(interaction: discord.Interaction, key: str, limit: app_commands.Range[int, 1, 100] = 50):
    result = await api(
        interaction, "GET", f"/api/integrations/apps/{configured_app(interaction)}/licenses/{key}/history",
        params={"limit": limit},
    )
    await interaction.response.send_message(
        render_rows(result["events"], ["timestamp", "action", "ip", "details"]), ephemeral=True
    )


async def product_choices(interaction: discord.Interaction, current: str):
    try:
        item = await api(interaction, "GET", f"/api/integrations/apps/{configured_app(interaction)}")
    except Exception:
        return []
    query = current.lower()
    return [
        app_commands.Choice(name=f"{row['name']} ({row['level']})"[:100], value=row["id"])
        for row in item.get("products", [])
        if query in row["name"].lower() or query in row["level"].lower()
    ][:25]


@bot.tree.command(description="Extend one product on one key, or use key=all")
@app_commands.autocomplete(product=product_choices)
@keygen
async def extendproduct(interaction: discord.Interaction, key: str, product: str, duration: str, confirm: bool = False):
    if key.lower() == "all" and not confirm:
        await interaction.response.send_message("Set confirm to true when key is `all`.", ephemeral=True)
        return
    hours = parse_duration(duration)
    if hours is None:
        raise RuntimeError("Extension must have a duration")
    await interaction.response.defer(ephemeral=True)
    result = await api(
        interaction, "POST",
        f"/api/integrations/apps/{configured_app(interaction)}/products/{product}/licenses/{key}/extend",
        json={"hours": hours},
    )
    await interaction.followup.send(
        f"Extended `{result['product']}` for `{result['affected']}` license(s).", ephemeral=True
    )


class AddProductSelect(discord.ui.Select):
    def __init__(self, license_key: str, duration_hours, products):
        self.license_key = license_key
        self.duration_hours = duration_hours
        options = [
            discord.SelectOption(label=row["name"][:100], description=f"Level: {row['level']}"[:100], value=row["id"])
            for row in products[:25]
        ]
        super().__init__(placeholder="Choose a product to add", min_values=1, max_values=1, options=options)

    async def callback(self, interaction: discord.Interaction):
        if not has_bot_access(interaction):
            await interaction.response.send_message(
                f"You need the configured bot role (`{ALLOWED_ROLE_ID}`).", ephemeral=True
            )
            return
        await interaction.response.defer(ephemeral=True)
        result = await api(
            interaction, "POST",
            f"/api/integrations/apps/{configured_app(interaction)}/licenses/{self.license_key}/products",
            json={"product_id": self.values[0], "duration_hours": self.duration_hours},
        )
        await interaction.followup.send(
            f"Added `{result['product']}`. Expires: `{result['expires_at'] or 'lifetime'}`", ephemeral=True
        )


class AddProductView(discord.ui.View):
    def __init__(self, license_key: str, duration_hours, products):
        super().__init__(timeout=120)
        self.add_item(AddProductSelect(license_key, duration_hours, products))


@bot.tree.command(description="Add another product to a license using a dropdown")
@keygen
async def addproduct(interaction: discord.Interaction, key: str, duration: str = "lifetime"):
    hours = parse_duration(duration)
    item = await api(interaction, "GET", f"/api/integrations/apps/{configured_app(interaction)}")
    products = [row for row in item.get("products", []) if row.get("is_active")]
    if not products:
        await interaction.response.send_message("This application has no active products.", ephemeral=True)
        return
    await interaction.response.send_message(
        "Choose the product to add:", view=AddProductView(key, hours, products), ephemeral=True
    )


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


@bot.tree.command(description="Show application health, active users, and authentication activity")
@keygen
async def health(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    snapshot = await api(
        interaction, "GET", f"/api/integrations/apps/{configured_app(interaction)}/operations"
    )
    await interaction.followup.send(embed=operational_embed(snapshot), ephemeral=True)


@bot.tree.command(description="Show SDK enforcement policy and versions currently connected")
@keygen
async def sdkstatus(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    snapshot = await api(
        interaction, "GET", f"/api/integrations/apps/{configured_app(interaction)}/operations"
    )
    policy = snapshot.get("sdk_policy") or {}
    usage = snapshot.get("sdk_usage") or []
    embed = discord.Embed(title="SDK compatibility", color=discord.Color.blurple())
    embed.add_field(name="Minimum", value=f"`{policy.get('minimum_version') or 'not set'}`")
    embed.add_field(name="Recommended", value=f"`{policy.get('recommended_version') or 'not set'}`")
    embed.add_field(name="Enforcement", value="Enabled" if policy.get("enforce_minimum") else "Advisory")
    versions = "\n".join(f"`{row.get('sdk_version') or 'unknown'}` — {row.get('sessions', 0)} session(s)" for row in usage)
    embed.add_field(name="Connected versions", value=versions or "No active SDK sessions", inline=False)
    if policy.get("upgrade_message"):
        embed.add_field(name="Upgrade notice", value=str(policy["upgrade_message"])[:1000], inline=False)
    await interaction.followup.send(embed=embed, ephemeral=True)


@bot.tree.command(description="Forecast product entitlements expiring soon")
@keygen
async def expiring(interaction: discord.Interaction, days: app_commands.Range[int, 1, 365] = 7):
    await interaction.response.defer(ephemeral=True)
    result = await api(
        interaction, "GET", f"/api/integrations/apps/{configured_app(interaction)}/expiring",
        params={"days": days, "limit": 25},
    )
    rows = result.get("items") or []
    if not rows:
        await interaction.followup.send(f"No entitlements expire within {days} day(s).", ephemeral=True)
        return
    embed = discord.Embed(title=f"Expiring within {days} day(s)", color=discord.Color.orange())
    for row in rows[:12]:
        embed.add_field(
            name=f"{row.get('product')} · {row.get('level')}",
            value=f"`{row.get('key')}`\n{row.get('client_username') or 'Unregistered'} · `{row.get('expires_at')}`",
            inline=False,
        )
    embed.set_footer(text=f"Showing {min(len(rows), 12)} of {len(rows)}")
    await interaction.followup.send(embed=embed, ephemeral=True)


@bot.tree.command(description="Summarize suspicious authentication activity from the last 24 hours")
@keygen
async def securitysummary(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    result = await api(
        interaction, "GET", f"/api/integrations/apps/{configured_app(interaction)}/security-summary"
    )
    embed = discord.Embed(title="Security summary · 24 hours", color=discord.Color.red())
    embed.add_field(name="Suspicious devices", value=str(result.get("suspicious_devices") or 0))
    embed.add_field(name="Banned HWIDs", value=str(result.get("banned_hwids") or 0))
    events = result.get("events") or []
    embed.add_field(
        name="Security events",
        value="\n".join(f"`{row['action']}` — **{row['count']}**" for row in events) or "No security events recorded",
        inline=False,
    )
    await interaction.followup.send(embed=embed, ephemeral=True)


@bot.tree.command(description="Set the public status and message for one product")
@app_commands.autocomplete(product=product_choices)
@app_commands.choices(status=[
    app_commands.Choice(name="Operational", value="operational"),
    app_commands.Choice(name="Degraded", value="degraded"),
    app_commands.Choice(name="Maintenance", value="maintenance"),
    app_commands.Choice(name="Offline", value="offline"),
])
@keygen
async def productstatus(interaction: discord.Interaction, product: str,
                        status: app_commands.Choice[str], message: str = "", color: str = "#22c55e"):
    await interaction.response.defer(ephemeral=True)
    result = await api(
        interaction, "PUT",
        f"/api/integrations/apps/{configured_app(interaction)}/products/{product}/status",
        json={"status": status.value, "message": message, "color": color},
    )
    embed = discord.Embed(
        title=f"{result['product']} status updated",
        description=message or "No public message",
        color=int(result["color"].lstrip("#"), 16),
    )
    embed.add_field(name="Status", value=result["status"])
    await interaction.followup.send(embed=embed, ephemeral=True)


@bot.tree.command(description="List customer HWID reset requests")
@app_commands.choices(status=[
    app_commands.Choice(name="Pending", value="pending"),
    app_commands.Choice(name="Approved", value="approved"),
    app_commands.Choice(name="Rejected", value="rejected"),
    app_commands.Choice(name="All", value="all"),
])
@keygen
async def resetrequests(interaction: discord.Interaction, status: str = "pending"):
    selected_status = status
    await interaction.response.defer(ephemeral=True)
    rows = await api(
        interaction, "GET", f"/api/integrations/apps/{configured_app(interaction)}/hwid-reset-requests",
        params={"status": selected_status},
    )
    if not rows:
        await interaction.followup.send(f"No `{selected_status}` HWID reset requests.", ephemeral=True)
        return
    embed = discord.Embed(title=f"HWID reset requests · {selected_status}", color=discord.Color.gold())
    for row in rows[:10]:
        embed.add_field(
            name=f"{row.get('client_username') or 'Customer'} · {row['id'][:8]}",
            value=f"Key `{row.get('key') or '-'}`\n{str(row.get('reason') or 'No reason')[:180]}\n`{row.get('created_at')}`",
            inline=False,
        )
    if len(rows) > 10:
        embed.set_footer(text=f"Showing 10 of {len(rows)} requests")
    await interaction.followup.send(embed=embed, ephemeral=True)


@bot.tree.command(description="Approve or reject a customer HWID reset request")
@app_commands.choices(decision=[
    app_commands.Choice(name="Approve and reset devices", value="approve"),
    app_commands.Choice(name="Reject request", value="reject"),
])
@keygen
async def reviewreset(interaction: discord.Interaction, request_id: str, decision: app_commands.Choice[str]):
    await interaction.response.defer(ephemeral=True)
    result = await api(
        interaction, "POST",
        f"/api/integrations/apps/{configured_app(interaction)}/hwid-reset-requests/{request_id}/{decision.value}",
    )
    await interaction.followup.send(f"Request `{request_id}` is now **{result['status']}**.", ephemeral=True)


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


@bot.tree.command(description="Pause the configured application and stop its sessions")
@keygen
async def pauseapp(interaction: discord.Interaction, reason: str = "Application outage", confirm: bool = False):
    if not confirm:
        await interaction.response.send_message("Set confirm to true to pause the application.", ephemeral=True)
        return
    result = await api(
        interaction, "POST", f"/api/integrations/apps/{configured_app(interaction)}/pause",
        json={"reason": reason},
    )
    await interaction.response.send_message(f"Application paused at `{result['paused_at']}`.", ephemeral=True)


@bot.tree.command(description="Resume the app and restore downtime plus compensation")
@keygen
async def resumeapp(interaction: discord.Interaction, compensation: str = "0h", confirm: bool = False):
    hours = 0 if compensation.strip().lower() in {"0", "0h"} else parse_duration(compensation)
    if hours is None:
        raise RuntimeError("Compensation must have a duration")
    app_id = configured_app(interaction)
    preview = await api(
        interaction, "GET", f"/api/integrations/apps/{app_id}/resume-preview",
        params={"compensation_hours": hours},
    )
    if not confirm:
        await interaction.response.send_message(
            f"Preview: `{preview['affected_licenses']}` licenses; downtime `{preview['downtime_seconds']}` seconds; "
            f"extra compensation `{preview['compensation_seconds']}` seconds. Run again with confirm=true.",
            ephemeral=True,
        )
        return
    result = await api(
        interaction, "POST", f"/api/integrations/apps/{app_id}/resume",
        json={"compensation_hours": hours},
    )
    await interaction.response.send_message(
        f"Application resumed. Extended `{result['affected_licenses']}` licenses by "
        f"`{result['extended_by_seconds']}` seconds.", ephemeral=True
    )


@bot.tree.command(description="Show this server's non-secret integration settings")
@keygen
async def config(interaction: discord.Interaction):
    server, app_id, _ = get_config(interaction.guild_id)
    await interaction.response.send_message(f"Server: `{server}`\nApp: `{app_id}`\nRequired role ID: `{ALLOWED_ROLE_ID}`", ephemeral=True)


@bot.tree.command(description="Show your bot authorization")
@keygen
async def whoami(interaction: discord.Interaction):
    await interaction.response.send_message(
        f"Authorized as {interaction.user.mention} with role ID `{ALLOWED_ROLE_ID}`.", ephemeral=True
    )


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
@app_commands.autocomplete(product=product_choices)
@app_commands.choices(
    file_type=[app_commands.Choice(name=x.title(), value=x) for x in ("loader", "payload", "update", "config", "symbols", "documentation")],
    channel=[app_commands.Choice(name=x.title(), value=x) for x in ("stable", "beta", "nightly", "private")],
    platform=[app_commands.Choice(name=x.title(), value=x) for x in ("windows", "linux", "macos", "any")],
    architecture=[app_commands.Choice(name=x.upper(), value=x) for x in ("x64", "x86", "arm64", "any")],
)
@keygen
async def uploadbuild(interaction: discord.Interaction, file: discord.Attachment, version: str,
                      product: str = "", file_type: str = "payload", channel: str = "stable",
                      platform: str = "windows", architecture: str = "x64",
                      auto_replace: bool = False, customer_download: bool = False,
                      mandatory: bool = False, name: str = "", release_notes: str = ""):
    await interaction.response.defer(ephemeral=True)
    result = await upload_build_file(interaction, file, version, product, file_type, channel, platform,
                                     architecture, auto_replace, customer_download, mandatory, name, release_notes)
    await send_upload_result(interaction, result)


async def upload_build_file(interaction, file, version, product="", file_type="payload", channel="stable",
                            platform="windows", architecture="x64", auto_replace=False,
                            customer_download=False, mandatory=False, name="", release_notes=""):
    if file.size > 100 * 1024 * 1024:
        raise RuntimeError("Build exceeds EnAuth's 100 MB upload limit")
    data = await file.read()
    form = aiohttp.FormData()
    form.add_field("name", name or file.filename)
    form.add_field("release_version", version)
    form.add_field("product_ids", product)
    form.add_field("file_type", file_type)
    form.add_field("channel", channel)
    form.add_field("platform", platform)
    form.add_field("architecture", architecture)
    form.add_field("auto_replace", str(auto_replace).lower())
    form.add_field("portal_visible", str(customer_download).lower())
    form.add_field("is_mandatory", str(mandatory).lower())
    form.add_field("release_notes", release_notes)
    form.add_field("file", data, filename=file.filename, content_type=file.content_type or "application/octet-stream")
    return await api(interaction, "POST", f"/api/integrations/apps/{configured_app(interaction)}/builds", data=form)


async def send_upload_result(interaction, result):
    replaced = f" Replaced and archived `{result['replaced_file_id']}`." if result.get("replaced_file_id") else ""
    embed = discord.Embed(title="Build published", color=discord.Color.green())
    embed.add_field(name="File", value=f"`{result['name']}`", inline=False)
    embed.add_field(name="Version", value=f"`{result['version']}`")
    embed.add_field(name="Channel", value=f"`{result['channel']}`")
    embed.add_field(name="Size", value=f"{result['size'] / 1048576:.2f} MB")
    embed.add_field(name="SHA-256", value=f"`{result['sha256']}`", inline=False)
    if replaced:
        embed.add_field(name="Previous release", value=replaced, inline=False)
    await interaction.followup.send(embed=embed, ephemeral=True)


@bot.tree.command(name="upload", description="Quickly publish a build with safe production defaults")
@app_commands.autocomplete(product=product_choices)
@app_commands.choices(kind=[
    app_commands.Choice(name="Protected payload", value="payload"),
    app_commands.Choice(name="Auto-updating loader", value="loader"),
])
@keygen
async def quick_upload(interaction: discord.Interaction, file: discord.Attachment, version: str,
                       kind: app_commands.Choice[str], product: str = "", release_notes: str = ""):
    await interaction.response.defer(ephemeral=True)
    result = await upload_build_file(
        interaction, file, version, product=product, file_type=kind.value,
        auto_replace=True, customer_download=(kind.value == "loader"),
        mandatory=(kind.value == "loader"), release_notes=release_notes,
    )
    await send_upload_result(interaction, result)


@bot.tree.command(description="List protected builds")
@keygen
async def builds(interaction: discord.Interaction):
    rows = await api(interaction, "GET", f"/api/integrations/apps/{configured_app(interaction)}/builds")
    await interaction.response.send_message(
        render_rows(rows, ["id", "name", "release_version", "channel", "file_type", "is_active"]), ephemeral=True
    )


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
    logger.error(
        "Slash command %s failed: %r",
        interaction.command.name if interaction.command else "unknown",
        original,
        exc_info=(type(original), original, original.__traceback__),
    )
    message = str(original) or "Command failed."
    if interaction.response.is_done():
        await interaction.followup.send(message[:1900], ephemeral=True)
    else:
        await interaction.response.send_message(message[:1900], ephemeral=True)


if __name__ == "__main__":
    bot.run(TOKEN, log_level=logging.INFO)
