import os
import re
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

import discord
from discord.ext import commands, tasks
from dotenv import load_dotenv

from blocklist import Blocklist

load_dotenv()
TOKEN = os.getenv("DISCORD_TOKEN")
LOG_CHANNEL_ID = int(os.getenv("LOG_CHANNEL_ID", "0"))
HONEYPOT_CHANNEL_ID = int(os.getenv("HONEYPOT_CHANNEL_ID", "0"))

# ---------- Settings ----------
SPAM_MSG_LIMIT = 6           # messages ...
SPAM_WINDOW = 8              # ... within this many seconds
DUPLICATE_LIMIT = 3          # same message this many times in a row
MAX_MENTIONS = 5             # mentions per message
MIN_ACCOUNT_AGE_DAYS = 7     # younger accounts get logged + a short timeout
RAID_JOINS = 8               # joins ...
RAID_WINDOW = 15             # ... within this many seconds = raid
HONEYPOT_TIMEOUT_HOURS = 24  # honeypot: timeout instead of ban (a mod decides afterwards)
RECENT_DELETE_SECONDS = 900  # honeypot: messages from the last 15 min are deleted everywhere
STRIKE_RESET_HOURS = 24      # strikes expire after this time
TIMEOUT_STEPS = [10, 60]     # timeout minutes for strike 2 and 3; kick from strike 4

LEGIT_DOMAINS = {
    "discord.com", "discord.gg", "discordapp.com", "discordapp.net",
    "discord.media", "steamcommunity.com", "steampowered.com",
}
SUSPICIOUS_WORDS = ("discord", "nitro", "steam", "gift", "airdrop")
SCAM_PHRASES = re.compile(
    r"free\s*nitro|nitro\s*giveaway|claim\s*your\s*(gift|reward)|"
    r"you\s*(have\s*)?been\s*selected|airdrop|wallet\s*connect",
    re.IGNORECASE,
)
URL_RE = re.compile(r"https?://([^\s/]+)", re.IGNORECASE)
INVITE_RE = re.compile(
    r"(?:discord\.gg|discord(?:app)?\.com/invite)/[\w-]+", re.IGNORECASE
)

# ---------- Bot ----------
intents = discord.Intents.default()
intents.message_content = True
intents.members = True
bot = commands.Bot(command_prefix="!", intents=intents)
blocklist = Blocklist()

recent_msgs = defaultdict(lambda: deque(maxlen=20))  # user_id -> (time, text)
strikes = defaultdict(list)                           # user_id -> [timestamps]
recent_joins = deque(maxlen=50)
recent_refs = defaultdict(lambda: deque(maxlen=30))   # user_id -> (time, channel_id, message_id)


def track(message: discord.Message):
    recent_refs[message.author.id].append((time.time(), message.channel.id, message.id))


async def delete_recent(guild: discord.Guild, user_id: int) -> int:
    """Deletes a user's most recent messages across all channels."""
    now = time.time()
    deleted = 0
    for t, channel_id, message_id in list(recent_refs.get(user_id, [])):
        if now - t > RECENT_DELETE_SECONDS:
            continue
        channel = guild.get_channel_or_thread(channel_id)
        if channel is None:
            continue
        try:
            await channel.get_partial_message(message_id).delete()
            deleted += 1
        except (discord.HTTPException, AttributeError):
            pass
    recent_refs.pop(user_id, None)
    return deleted


async def log(guild: discord.Guild, title: str, text: str, color=0xE67E22):
    channel = guild.get_channel(LOG_CHANNEL_ID)
    if channel:
        embed = discord.Embed(title=title, description=text, color=color)
        embed.timestamp = datetime.now(timezone.utc)
        await channel.send(embed=embed)


def is_staff(member: discord.Member) -> bool:
    return member.guild_permissions.manage_messages or member.guild_permissions.administrator


def check_links(content: str):
    for host in URL_RE.findall(content):
        host = host.lower().split("@")[-1].split(":")[0]
        base = ".".join(host.split(".")[-2:])
        if base not in LEGIT_DOMAINS and any(w in host for w in SUSPICIOUS_WORDS):
            return f"Suspicious domain: {host}"
    if INVITE_RE.search(content):
        return "Foreign server invite"
    if SCAM_PHRASES.search(content):
        return "Scam phrase"
    return None


def check_spam(message: discord.Message):
    now = time.time()
    history = recent_msgs[message.author.id]
    history.append((now, message.content))

    recent = [t for t, _ in history if now - t <= SPAM_WINDOW]
    if len(recent) >= SPAM_MSG_LIMIT:
        return "Message flood"
    last = [c for _, c in list(history)[-DUPLICATE_LIMIT:]]
    if len(last) == DUPLICATE_LIMIT and len(set(last)) == 1 and last[0]:
        return "Repeated message"
    if len(message.mentions) + len(message.role_mentions) > MAX_MENTIONS:
        return "Mass mention"
    if message.mention_everyone and not message.author.guild_permissions.mention_everyone:
        return "@everyone abuse"
    return None


async def punish(message: discord.Message, reason: str, severe: bool = False):
    member = message.author
    try:
        await message.delete()
    except discord.HTTPException:
        pass

    if severe:
        # Blocklist hit: usually a hacked account -> 24h timeout right away,
        # a mod then decides about kick/ban based on the log.
        await member.timeout(timedelta(hours=24), reason=reason)
        await log(
            message.guild,
            "Overwatch: SCAM LINK blocked",
            f"**User:** {member} ({member.id})\n**Reason:** {reason}\n"
            f"**Action:** Message deleted + 24h timeout\n"
            f"**Channel:** {message.channel.mention}\n**Content:** {message.content[:300]}",
            0xE74C3C,
        )
        return

    now = time.time()
    strikes[member.id] = [t for t in strikes[member.id] if now - t < STRIKE_RESET_HOURS * 3600]
    strikes[member.id].append(now)
    n = len(strikes[member.id])

    if n == 1:
        action = "Message deleted + warning"
        await message.channel.send(
            f"{member.mention} please do not spam or post suspicious links.", delete_after=8
        )
    elif n - 2 < len(TIMEOUT_STEPS):
        minutes = TIMEOUT_STEPS[n - 2]
        action = f"{minutes} min timeout"
        await member.timeout(timedelta(minutes=minutes), reason=reason)
    else:
        action = "Kick"
        await member.kick(reason=reason)

    await log(
        message.guild,
        "Overwatch: Action taken",
        f"**User:** {member} ({member.id})\n**Reason:** {reason}\n"
        f"**Action:** {action} (strike {n})\n**Channel:** {message.channel.mention}\n"
        f"**Content:** {message.content[:300]}",
    )


@tasks.loop(hours=6)
async def update_blocklist():
    count = await blocklist.update()
    print(f"[Blocklist] updated: {count} domains")


@bot.event
async def on_ready():
    print(f"Overwatch online as {bot.user}")
    if not update_blocklist.is_running():
        update_blocklist.start()  # loads immediately on start, then every 6 hours


@bot.event
async def on_message(message: discord.Message):
    if message.author.bot or not message.guild:
        return

    # remember messages so they can be deleted on a honeypot hit
    track(message)

    # Honeypot: whoever writes here is a bot OR a hacked account.
    # So: no ban, just cleanup + timeout. A mod decides afterwards.
    if message.channel.id == HONEYPOT_CHANNEL_ID and not is_staff(message.author):
        member = message.author
        deleted = await delete_recent(message.guild, member.id)
        try:
            await member.timeout(timedelta(hours=HONEYPOT_TIMEOUT_HOURS), reason="Honeypot")
            action = f"{HONEYPOT_TIMEOUT_HOURS}h timeout"
        except discord.HTTPException:
            action = "Timeout failed (check permissions / role order!)"
        await log(
            message.guild,
            "Overwatch: Honeypot triggered",
            f"**User:** {member} ({member.id})\n"
            f"**Action:** {deleted} message(s) deleted, {action}\n"
            f"**Note:** This is a bot OR a hacked account. "
            f"Please review it and kick/ban manually if it is a bot.",
            0xE74C3C,
        )
        return

    if not is_staff(message.author):
        hit = blocklist.find(message.content)
        if hit:
            await punish(message, f"Blocklist hit: {hit}", severe=True)
            return
        reason = check_links(message.content) or check_spam(message)
        if reason:
            await punish(message, reason)
            return

    await bot.process_commands(message)


@bot.event
async def on_member_join(member: discord.Member):
    now = time.time()
    recent_joins.append(now)
    age = datetime.now(timezone.utc) - member.created_at

    if age < timedelta(days=MIN_ACCOUNT_AGE_DAYS):
        await member.timeout(timedelta(hours=1), reason="Very new account")
        await log(member.guild, "Overwatch: New account",
                  f"{member} ({member.id}) is only {age.days} days old. 1h timeout.")

    joins = [t for t in recent_joins if now - t <= RAID_WINDOW]
    if len(joins) >= RAID_JOINS:
        await member.timeout(timedelta(minutes=10), reason="Suspected raid")
        await log(member.guild, "Overwatch: RAID ALERT",
                  f"{len(joins)} joins within {RAID_WINDOW}s. New members get a 10 min timeout.",
                  0xE74C3C)


@bot.command()
@commands.has_permissions(manage_messages=True)
async def status(ctx):
    await ctx.send(
        f"Overwatch is running and protecting the server. Blocklist: {len(blocklist)} domains."
    )


@bot.command()
@commands.has_permissions(manage_messages=True)
async def updatelist(ctx):
    """Reloads the scam domain list immediately."""
    count = await blocklist.update()
    await ctx.send(f"Blocklist updated: {count} domains.")


@bot.command()
@commands.has_permissions(manage_guild=True)
async def blockdomain(ctx, domain: str):
    """!blockdomain evil.com -> block a domain permanently."""
    added = blocklist.add_block(domain)
    await ctx.send(f"`{added}` is now blocked." if added else "Invalid domain.")


@bot.command()
@commands.has_permissions(manage_guild=True)
async def allowdomain(ctx, domain: str):
    """!allowdomain example.com -> whitelist a domain after a false positive."""
    added = blocklist.add_allow(domain)
    await ctx.send(f"`{added}` is now allowed." if added else "Invalid domain.")


@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.MissingPermissions):
        await ctx.send("You do not have permission to use this command.")
    elif isinstance(error, commands.MissingRequiredArgument):
        await ctx.send(f"Missing argument: `{error.param.name}`")
    elif isinstance(error, commands.CommandNotFound):
        return
    else:
        print(f"[Command error] {error}")


bot.run(TOKEN)
