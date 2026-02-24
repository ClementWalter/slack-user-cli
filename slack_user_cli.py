#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "slack-sdk>=3.33",
#     "slacktokens>=0.2.6",
#     "click>=8.0",
#     "rich>=13.0",
# ]
# ///
"""Slack User CLI — terminal access to Slack using browser session credentials.

Provides read/write access to Slack channels, DMs, threads, and search
using xoxc- tokens and d cookies extracted from the Slack desktop app
or browser DevTools. No Slack app registration needed.
"""

import json
import logging
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.text import Text
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

logger = logging.getLogger(__name__)

# -- Config management --------------------------------------------------------

CONFIG_DIR = Path.home() / ".config" / "slack-user-cli"
CONFIG_FILE = CONFIG_DIR / "config.json"

console = Console()


def load_config() -> dict:
    """Load config from disk, returning empty dict if missing."""
    if CONFIG_FILE.exists():
        return json.loads(CONFIG_FILE.read_text())
    return {}


def save_config(config: dict) -> None:
    """Persist config to disk, creating parent dirs as needed."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(config, indent=2))


def get_client(config: dict | None = None) -> WebClient:
    """Build an authenticated WebClient from stored credentials.

    The xoxc- token goes in the standard token param while the d cookie
    must be injected via a custom Cookie header — this mirrors how the
    Slack web client authenticates.
    """
    if config is None:
        config = load_config()
    token = config.get("token")
    cookie = config.get("cookie")
    if not token or not cookie:
        raise click.ClickException(
            "Not logged in. Run 'login' first to set credentials."
        )
    return WebClient(token=token, headers={"cookie": f"d={cookie}"})


# -- User cache for display name resolution -----------------------------------

# Module-level cache to avoid repeated API calls within a session
_user_cache: dict[str, str] = {}


def resolve_user(client: WebClient, user_id: str) -> str:
    """Resolve a Slack user ID to a display name, with caching."""
    if user_id in _user_cache:
        return _user_cache[user_id]
    try:
        resp = client.users_info(user=user_id)
        user = resp["user"]
        # Prefer display_name, fall back to real_name, then user ID
        name = (
            user.get("profile", {}).get("display_name")
            or user.get("real_name")
            or user_id
        )
        _user_cache[user_id] = name
        return name
    except SlackApiError:
        logger.debug("Failed to resolve user %s", user_id)
        _user_cache[user_id] = user_id
        return user_id


def resolve_channel(client: WebClient, name_or_id: str) -> str:
    """Resolve a channel name (without #) to its ID, or pass through an ID."""
    # Already an ID — starts with C, D, or G
    if name_or_id[0] in ("C", "D", "G") and name_or_id[1:].isalnum():
        return name_or_id

    # Walk paginated channel list looking for a name match
    cursor = None
    while True:
        kwargs: dict = {
            "types": "public_channel,private_channel,mpim,im",
            "limit": 200,
        }
        if cursor:
            kwargs["cursor"] = cursor
        resp = client.conversations_list(**kwargs)
        for ch in resp["channels"]:
            if ch.get("name") == name_or_id:
                return ch["id"]
        cursor = resp.get("response_metadata", {}).get("next_cursor")
        if not cursor:
            break

    raise click.ClickException(f"Channel '{name_or_id}' not found.")


# -- CLI group ----------------------------------------------------------------


@click.group()
@click.option(
    "--debug", is_flag=True, default=False, help="Enable debug logging."
)
def cli(debug: bool) -> None:
    """Slack User CLI — read and write Slack from your terminal."""
    level = logging.DEBUG if debug else logging.WARNING
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")


# -- login --------------------------------------------------------------------


@cli.command()
@click.option(
    "--auto",
    "mode",
    flag_value="auto",
    help="Extract credentials from Slack desktop app.",
)
@click.option(
    "--manual",
    "mode",
    flag_value="manual",
    help="Paste credentials from browser DevTools.",
)
def login(mode: str | None) -> None:
    """Authenticate with Slack using session credentials."""
    if mode is None:
        mode = "auto"

    if mode == "auto":
        try:
            # slacktokens extracts from Slack desktop's LevelDB + macOS Keychain
            from slacktokens import get_tokens_and_cookie  # noqa: PLC0415
        except ImportError as exc:
            raise click.ClickException(
                "slacktokens not available. Use --manual instead."
            ) from exc

        console.print(
            "[yellow]Extracting credentials from Slack desktop app…[/]"
        )
        console.print(
            "[dim]Note: close Slack desktop first (LevelDB lock) "
            "and allow Keychain access when prompted.[/]"
        )
        result = get_tokens_and_cookie()
        cookie = result.get("cookie", "")

        # slacktokens returns {cookie: str, tokens: {workspace: token, ...}}
        tokens = result.get("tokens", {})
        if not tokens:
            raise click.ClickException(
                "No tokens found. Is Slack desktop installed and logged in?"
            )

        if len(tokens) == 1:
            workspace, token = next(iter(tokens.items()))
            console.print(f"Found workspace: [bold]{workspace}[/]")
        else:
            console.print("Found multiple workspaces:")
            workspaces = list(tokens.keys())
            for i, ws in enumerate(workspaces, 1):
                console.print(f"  {i}. {ws}")
            choice = click.prompt(
                "Select workspace", type=int, default=1
            )
            workspace = workspaces[choice - 1]
            token = tokens[workspace]
    else:
        token = click.prompt("Paste xoxc- token")
        cookie = click.prompt("Paste d cookie value (xoxd-…)")

    # Validate before saving
    client = WebClient(token=token, headers={"cookie": f"d={cookie}"})
    try:
        resp = client.auth_test()
    except SlackApiError as exc:
        raise click.ClickException(
            f"Auth validation failed: {exc.response['error']}"
        ) from exc

    config = load_config()
    config["token"] = token
    config["cookie"] = cookie
    config["team"] = resp.get("team")
    config["user"] = resp.get("user")
    save_config(config)

    console.print(
        f"[green]Logged in as [bold]{resp['user']}[/bold] "
        f"in [bold]{resp['team']}[/bold][/]"
    )


# -- channels -----------------------------------------------------------------


@cli.command()
@click.option(
    "--type",
    "channel_types",
    default="public_channel,private_channel",
    help="Comma-separated channel types to list.",
)
def channels(channel_types: str) -> None:
    """List joined channels."""
    client = get_client()
    table = Table(title="Channels")
    table.add_column("Name", style="cyan")
    table.add_column("Type", style="magenta")
    table.add_column("Members", justify="right")
    table.add_column("Topic")

    cursor = None
    while True:
        kwargs: dict = {"types": channel_types, "limit": 200}
        if cursor:
            kwargs["cursor"] = cursor
        try:
            resp = client.conversations_list(**kwargs)
        except SlackApiError as exc:
            raise click.ClickException(str(exc)) from exc

        for ch in resp["channels"]:
            ch_type = _channel_type_label(ch)
            topic = ch.get("topic", {}).get("value", "")
            # Truncate long topics for table readability
            if len(topic) > 60:
                topic = topic[:57] + "…"
            table.add_row(
                ch.get("name", ch["id"]),
                ch_type,
                str(ch.get("num_members", "")),
                topic,
            )

        cursor = resp.get("response_metadata", {}).get("next_cursor")
        if not cursor:
            break

    console.print(table)


def _channel_type_label(ch: dict) -> str:
    """Derive a human-readable type label from channel metadata."""
    if ch.get("is_im"):
        return "DM"
    if ch.get("is_mpim"):
        return "Group DM"
    if ch.get("is_private"):
        return "Private"
    return "Public"


# -- read ---------------------------------------------------------------------


@cli.command()
@click.argument("channel")
@click.option("--limit", default=20, help="Number of messages to show.")
def read(channel: str, limit: int) -> None:
    """Read recent messages from a channel."""
    client = get_client()
    channel_id = resolve_channel(client, channel)

    messages: list[dict] = []
    cursor = None
    while len(messages) < limit:
        kwargs: dict = {
            "channel": channel_id,
            "limit": min(limit - len(messages), 200),
        }
        if cursor:
            kwargs["cursor"] = cursor
        try:
            resp = client.conversations_history(**kwargs)
        except SlackApiError as exc:
            raise click.ClickException(str(exc)) from exc

        messages.extend(resp.get("messages", []))
        cursor = resp.get("response_metadata", {}).get("next_cursor")
        if not cursor:
            break

    # Messages come newest-first; reverse for chronological display
    messages = messages[:limit]
    messages.reverse()
    _print_messages(client, messages)


# -- thread -------------------------------------------------------------------


@cli.command()
@click.argument("channel")
@click.argument("ts")
@click.option("--limit", default=50, help="Number of replies to show.")
def thread(channel: str, ts: str, limit: int) -> None:
    """Read thread replies for a given message timestamp."""
    client = get_client()
    channel_id = resolve_channel(client, channel)

    replies: list[dict] = []
    cursor = None
    while len(replies) < limit:
        kwargs: dict = {
            "channel": channel_id,
            "ts": ts,
            "limit": min(limit - len(replies), 200),
        }
        if cursor:
            kwargs["cursor"] = cursor
        try:
            resp = client.conversations_replies(**kwargs)
        except SlackApiError as exc:
            raise click.ClickException(str(exc)) from exc

        replies.extend(resp.get("messages", []))
        cursor = resp.get("response_metadata", {}).get("next_cursor")
        if not cursor:
            break

    replies = replies[:limit]
    _print_messages(client, replies)


# -- users --------------------------------------------------------------------


@cli.command()
def users() -> None:
    """List workspace members."""
    client = get_client()
    table = Table(title="Users")
    table.add_column("Display Name", style="cyan")
    table.add_column("Real Name")
    table.add_column("Status")

    cursor = None
    while True:
        kwargs: dict = {"limit": 200}
        if cursor:
            kwargs["cursor"] = cursor
        try:
            resp = client.users_list(**kwargs)
        except SlackApiError as exc:
            raise click.ClickException(str(exc)) from exc

        for member in resp["members"]:
            # Skip bots and deactivated users for cleaner output
            if member.get("is_bot") or member.get("deleted"):
                continue
            profile = member.get("profile", {})
            display = profile.get("display_name") or member.get("name", "")
            real = profile.get("real_name", "")
            status_emoji = profile.get("status_emoji", "")
            status_text = profile.get("status_text", "")
            status = f"{status_emoji} {status_text}".strip()
            table.add_row(display, real, status)

        cursor = resp.get("response_metadata", {}).get("next_cursor")
        if not cursor:
            break

    console.print(table)


# -- send ---------------------------------------------------------------------


@cli.command()
@click.argument("channel")
@click.argument("message")
def send(channel: str, message: str) -> None:
    """Send a message to a channel."""
    client = get_client()
    channel_id = resolve_channel(client, channel)

    try:
        resp = client.chat_postMessage(channel=channel_id, text=message)
    except SlackApiError as exc:
        raise click.ClickException(str(exc)) from exc

    ts = resp.get("ts", "")
    console.print(f"[green]Message sent[/] (ts={ts})")


# -- dm -----------------------------------------------------------------------


@cli.command()
@click.argument("user")
@click.argument("message", required=False, default=None)
@click.option("--limit", default=20, help="Messages to show when reading.")
def dm(user: str, message: str | None, limit: int) -> None:
    """Open a DM with a user. Send a message or read recent history."""
    client = get_client()

    # Resolve user name to ID if needed (simple heuristic: IDs start with U)
    user_id = user
    if not (user.startswith("U") and user[1:].isalnum()):
        user_id = _resolve_user_by_name(client, user)

    # Open (or retrieve) the DM channel
    try:
        resp = client.conversations_open(users=[user_id])
    except SlackApiError as exc:
        raise click.ClickException(str(exc)) from exc

    dm_channel = resp["channel"]["id"]

    if message:
        try:
            send_resp = client.chat_postMessage(
                channel=dm_channel, text=message
            )
        except SlackApiError as exc:
            raise click.ClickException(str(exc)) from exc
        console.print(
            f"[green]DM sent[/] (ts={send_resp.get('ts', '')})"
        )
    else:
        # Read recent DM history
        try:
            hist = client.conversations_history(
                channel=dm_channel, limit=limit
            )
        except SlackApiError as exc:
            raise click.ClickException(str(exc)) from exc
        messages = list(reversed(hist.get("messages", [])))
        _print_messages(client, messages)


def _resolve_user_by_name(client: WebClient, name: str) -> str:
    """Walk the users list to find a user by display_name or name."""
    cursor = None
    while True:
        kwargs: dict = {"limit": 200}
        if cursor:
            kwargs["cursor"] = cursor
        resp = client.users_list(**kwargs)
        for member in resp["members"]:
            if member.get("name") == name:
                return member["id"]
            profile = member.get("profile", {})
            if profile.get("display_name") == name:
                return member["id"]
        cursor = resp.get("response_metadata", {}).get("next_cursor")
        if not cursor:
            break
    raise click.ClickException(f"User '{name}' not found.")


# -- search -------------------------------------------------------------------


@cli.command()
@click.argument("query")
@click.option("--count", default=20, help="Results per page.")
@click.option("--page", default=1, help="Page number.")
def search(query: str, count: int, page: int) -> None:
    """Search messages across the workspace."""
    client = get_client()

    try:
        # search.messages uses page-based pagination (not cursor)
        resp = client.search_messages(query=query, count=count, page=page)
    except SlackApiError as exc:
        raise click.ClickException(str(exc)) from exc

    matches = resp.get("messages", {})
    total = matches.get("total", 0)
    paging = matches.get("paging", {})

    console.print(
        f"[bold]Search results for '{query}'[/] "
        f"— page {paging.get('page', page)}/{paging.get('pages', 1)}, "
        f"{total} total matches"
    )

    for match in matches.get("matches", []):
        username = match.get("username", "unknown")
        text = match.get("text", "")
        channel_name = match.get("channel", {}).get("name", "?")
        ts = match.get("ts", "")
        ts_display = _format_ts(ts)

        line = Text()
        line.append(f"[{ts_display}] ", style="dim")
        line.append(f"#{channel_name} ", style="blue")
        line.append(f"{username}: ", style="bold")
        line.append(text)
        console.print(line)


# -- Output helpers -----------------------------------------------------------


def _format_ts(ts: str) -> str:
    """Convert a Slack timestamp to a human-readable datetime string."""
    try:
        from datetime import datetime, timezone  # noqa: PLC0415

        epoch = float(ts.split(".")[0])
        dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M")
    except (ValueError, IndexError):
        return ts


def _print_messages(client: WebClient, messages: list[dict]) -> None:
    """Render a list of Slack messages to the console."""
    for msg in messages:
        user_id = msg.get("user", "")
        username = resolve_user(client, user_id) if user_id else "bot"
        text = msg.get("text", "")
        ts = msg.get("ts", "")
        ts_display = _format_ts(ts)
        thread_ts = msg.get("thread_ts")
        reply_count = msg.get("reply_count", 0)

        line = Text()
        line.append(f"[{ts_display}] ", style="dim")
        line.append(f"{username}: ", style="bold")
        line.append(text)
        # Indicate threaded messages
        if thread_ts and reply_count:
            line.append(f" [{reply_count} replies]", style="yellow")
        console.print(line)


if __name__ == "__main__":
    cli()
