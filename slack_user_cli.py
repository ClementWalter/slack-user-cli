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
import subprocess
import time
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
    """Load config from disk, returning empty dict if missing.

    Migrates legacy single-workspace format to multi-workspace on read.
    """
    if not CONFIG_FILE.exists():
        return {}
    config = json.loads(CONFIG_FILE.read_text())
    # Migrate legacy format: {token, cookie, team, user} → multi-workspace
    if "token" in config and "workspaces" not in config:
        team = config.get("team", "default")
        config = {
            "cookie": config.get("cookie", ""),
            "default": team,
            "workspaces": {
                team: {
                    "token": config["token"],
                    "team": team,
                    "user": config.get("user", ""),
                }
            },
        }
        save_config(config)
    return config


def save_config(config: dict) -> None:
    """Persist config to disk, creating parent dirs as needed."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(config, indent=2))


def get_workspace_config(config: dict, workspace: str | None) -> dict:
    """Extract token + cookie for a specific workspace.

    Returns a dict with 'token' and 'cookie' keys ready for WebClient.
    """
    workspaces = config.get("workspaces", {})
    cookie = config.get("cookie", "")

    if not workspaces:
        raise click.ClickException(
            "Not logged in. Run 'login' first to set credentials."
        )

    if workspace is None:
        workspace = config.get("default", "")

    if workspace not in workspaces:
        available = ", ".join(workspaces.keys())
        raise click.ClickException(
            f"Workspace '{workspace}' not found. Available: {available}"
        )

    ws = workspaces[workspace]
    return {"token": ws["token"], "cookie": cookie}


def get_client(config: dict | None = None, workspace: str | None = None) -> WebClient:
    """Build an authenticated WebClient from stored credentials.

    The xoxc- token goes in the standard token param while the d cookie
    must be injected via a custom Cookie header — this mirrors how the
    Slack web client authenticates.
    """
    if config is None:
        config = load_config()
    ws = get_workspace_config(config, workspace)
    token = ws.get("token")
    cookie = ws.get("cookie")
    if not token or not cookie:
        raise click.ClickException(
            "Not logged in. Run 'login' first to set credentials."
        )
    return WebClient(token=token, headers={"cookie": f"d={cookie}"})


# -- Disk-backed cache --------------------------------------------------------

# Cache TTL: 1 hour — channels and users rarely change
CACHE_TTL_SECONDS = 3600

# In-memory user display name cache (populated from disk + API)
_user_cache: dict[str, str] = {}


def _cache_path(workspace: str, kind: str) -> Path:
    """Return the cache file path for a workspace and cache kind.

    Derived from CONFIG_DIR at call time so monkeypatching works in tests.
    """
    return CONFIG_DIR / "cache" / workspace / f"{kind}.json"


def _load_cache(workspace: str, kind: str) -> dict | None:
    """Load a cache file if it exists and hasn't expired."""
    path = _cache_path(workspace, kind)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None
    # Check TTL
    if time.time() - data.get("ts", 0) > CACHE_TTL_SECONDS:
        logger.debug("Cache expired for %s/%s", workspace, kind)
        return None
    return data.get("data")


def _save_cache(workspace: str, kind: str, data: dict) -> None:
    """Save data to a cache file with a timestamp."""
    path = _cache_path(workspace, kind)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"ts": time.time(), "data": data}))


def _get_active_workspace(config: dict | None = None, workspace: str | None = None) -> str:
    """Resolve the active workspace name for cache keying."""
    if config is None:
        config = load_config()
    if workspace is None:
        workspace = config.get("default", "")
    return workspace


def build_channel_cache(client: WebClient, workspace: str) -> dict[str, str]:
    """Fetch all channels and build a name→id mapping, saving to disk."""
    name_to_id: dict[str, str] = {}
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
            name = ch.get("name", "")
            if name:
                name_to_id[name] = ch["id"]
        cursor = resp.get("response_metadata", {}).get("next_cursor")
        if not cursor:
            break
    _save_cache(workspace, "channels", name_to_id)
    logger.debug("Cached %d channels for %s", len(name_to_id), workspace)
    return name_to_id


def build_user_cache(client: WebClient, workspace: str) -> dict:
    """Fetch all users and build lookup maps, saving to disk.

    Returns dict with:
      - id_to_display: {user_id: display_name}
      - name_to_id: {username: user_id}
      - display_to_id: {display_name: user_id}
    """
    id_to_display: dict[str, str] = {}
    name_to_id: dict[str, str] = {}
    display_to_id: dict[str, str] = {}
    cursor = None
    while True:
        kwargs: dict = {"limit": 200}
        if cursor:
            kwargs["cursor"] = cursor
        resp = client.users_list(**kwargs)
        for member in resp["members"]:
            uid = member["id"]
            username = member.get("name", "")
            profile = member.get("profile", {})
            display = profile.get("display_name") or member.get("real_name") or username
            id_to_display[uid] = display
            if username:
                name_to_id[username] = uid
            if profile.get("display_name"):
                display_to_id[profile["display_name"]] = uid
        cursor = resp.get("response_metadata", {}).get("next_cursor")
        if not cursor:
            break
    data = {
        "id_to_display": id_to_display,
        "name_to_id": name_to_id,
        "display_to_id": display_to_id,
    }
    _save_cache(workspace, "users", data)
    logger.debug("Cached %d users for %s", len(id_to_display), workspace)
    return data


def _get_channel_cache(client: WebClient, workspace: str) -> dict[str, str]:
    """Get channel name→id map from cache or API."""
    cached = _load_cache(workspace, "channels")
    if cached is not None:
        return cached
    return build_channel_cache(client, workspace)


def _get_user_cache(client: WebClient, workspace: str) -> dict:
    """Get user lookup maps from cache or API."""
    cached = _load_cache(workspace, "users")
    if cached is not None:
        return cached
    return build_user_cache(client, workspace)


def resolve_user(client: WebClient, user_id: str, workspace: str = "") -> str:
    """Resolve a Slack user ID to a display name, using disk cache.

    Only reads the disk cache passively — never triggers a full users_list
    build. This keeps individual user lookups fast and avoids pagination
    storms when the cache hasn't been built yet.
    """
    if user_id in _user_cache:
        return _user_cache[user_id]

    # Passively check disk cache (no API call if missing)
    if workspace:
        cached = _load_cache(workspace, "users")
        if cached is not None:
            name = cached.get("id_to_display", {}).get(user_id)
            if name:
                _user_cache[user_id] = name
                return name

    # Fall back to single API call for unknown users
    try:
        resp = client.users_info(user=user_id)
        user = resp["user"]
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


def resolve_channel(client: WebClient, name_or_id: str, workspace: str = "") -> str:
    """Resolve a channel name (without #) to its ID, or pass through an ID."""
    # Already an ID — starts with C, D, or G
    if name_or_id[0] in ("C", "D", "G") and name_or_id[1:].isalnum():
        return name_or_id

    # Check disk cache first
    if workspace:
        channel_map = _get_channel_cache(client, workspace)
        if name_or_id in channel_map:
            return channel_map[name_or_id]

    # Cache miss — walk the API (and rebuild cache while we're at it)
    channel_map = build_channel_cache(client, workspace) if workspace else {}
    if name_or_id in channel_map:
        return channel_map[name_or_id]

    # Final fallback: paginate without caching (no workspace context)
    if not workspace:
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
@click.option(
    "-w",
    "--workspace",
    default=None,
    help="Workspace name to use (defaults to the default workspace).",
)
@click.pass_context
def cli(ctx: click.Context, debug: bool, workspace: str | None) -> None:
    """Slack User CLI — read and write Slack from your terminal."""
    level = logging.DEBUG if debug else logging.WARNING
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")
    # Resolve and store the active workspace name for cache keying
    ctx.ensure_object(dict)
    ctx.obj["workspace"] = workspace
    config = load_config()
    ctx.obj["workspace_name"] = _get_active_workspace(config, workspace)


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
    help="Paste credentials from browser DevTools (one workspace).",
)
@click.option(
    "--browser",
    "mode",
    flag_value="browser",
    help="Paste localStorage JSON from browser to import all workspaces.",
)
@click.option(
    "--workspace-name",
    default=None,
    help="Name for this workspace (manual mode only).",
)
def login(mode: str | None, workspace_name: str | None) -> None:
    """Authenticate with Slack using session credentials.

    Three modes:
      --auto     Extract from Slack desktop app (all workspaces).
      --browser  Paste browser localStorage JSON (all workspaces).
      --manual   Paste a single xoxc- token + d cookie.
    """
    if mode is None:
        mode = "auto"

    config = load_config()
    config.setdefault("workspaces", {})

    if mode == "auto":
        _login_auto(config)
    elif mode == "browser":
        _login_browser(config)
    else:
        _login_manual(config, workspace_name)

    save_config(config)

    # Show summary of all workspaces
    ws_count = len(config.get("workspaces", {}))
    default = config.get("default", "")
    if ws_count > 1:
        console.print(
            f"\n[bold]{ws_count} workspaces saved.[/] "
            f"Default: [cyan]{default}[/]"
        )
        console.print(
            "[dim]Use -w <name> to switch, or 'workspaces' to list all.[/]"
        )


def _login_auto(config: dict) -> None:
    """Extract credentials from Slack desktop app via slacktokens."""
    try:
        from slacktokens import get_tokens_and_cookie  # noqa: PLC0415
    except ImportError as exc:
        raise click.ClickException(
            "slacktokens not available. Use --manual or --browser instead."
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
    config["cookie"] = cookie

    # slacktokens returns {cookie: str, tokens: {workspace: token, ...}}
    tokens = result.get("tokens", {})
    if not tokens:
        raise click.ClickException(
            "No tokens found. Is Slack desktop installed and logged in?"
        )

    _validate_and_save_tokens(config, tokens, cookie)


def _login_browser(config: dict) -> None:
    """Import all workspaces from browser localStorage JSON.

    The user pastes the output of:
        JSON.stringify(JSON.parse(localStorage.localConfig_v2))
    from browser DevTools. We extract every team's token from it.
    """
    # JS snippet that copies the result to clipboard automatically
    js_snippet = (
        "copy(JSON.stringify(JSON.parse(localStorage.localConfig_v2)))"
    )
    console.print(
        "[yellow]Run this in your browser DevTools console:[/]"
    )
    console.print(f"[bold]{js_snippet}[/]")
    click.prompt("Press Enter when copied", default="", show_default=False)

    # Read directly from macOS clipboard to avoid terminal paste truncation
    try:
        result = subprocess.run(
            ["pbpaste"], capture_output=True, text=True, check=True
        )
        raw = result.stdout
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        raise click.ClickException(
            "Failed to read clipboard. Paste the JSON manually with "
            "'pbpaste | slack_user_cli login --browser-stdin'"
        ) from exc

    if not raw.strip():
        raise click.ClickException("Clipboard is empty.")

    try:
        local_config = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise click.ClickException(f"Invalid JSON: {exc}") from exc

    teams = local_config.get("teams", {})
    if not teams:
        raise click.ClickException("No teams found in the pasted JSON.")

    # Extract tokens keyed by team name
    tokens: dict[str, str] = {}
    for _team_id, team_data in teams.items():
        name = team_data.get("name", team_data.get("team_name", _team_id))
        token = team_data.get("token", "")
        if token:
            tokens[name] = token

    if not tokens:
        raise click.ClickException("No tokens found in the pasted JSON.")

    # Also need the d cookie — prompt if not already stored
    cookie = config.get("cookie", "")
    if not cookie:
        cookie = click.prompt("Paste d cookie value (xoxd-…)")
    config["cookie"] = cookie

    _validate_and_save_tokens(config, tokens, cookie)


def _login_manual(config: dict, workspace_name: str | None) -> None:
    """Login with a single manually-pasted token + cookie."""
    token = click.prompt("Paste xoxc- token")
    cookie = click.prompt("Paste d cookie value (xoxd-…)")
    config["cookie"] = cookie

    client = WebClient(token=token, headers={"cookie": f"d={cookie}"})
    try:
        resp = client.auth_test()
    except SlackApiError as exc:
        raise click.ClickException(
            f"Auth validation failed: {exc.response['error']}"
        ) from exc

    team = workspace_name or resp.get("team", "default")
    user = resp.get("user", "")
    config["workspaces"][team] = {
        "token": token,
        "team": team,
        "user": user,
    }
    if len(config["workspaces"]) == 1:
        config["default"] = team

    console.print(
        f"[green]Logged in as [bold]{user}[/bold] "
        f"in [bold]{team}[/bold][/]"
    )


def _validate_and_save_tokens(
    config: dict, tokens: dict[str, str], cookie: str
) -> None:
    """Validate each token with auth.test and save to config."""
    first_team = None
    for ws_name, token in tokens.items():
        client = WebClient(
            token=token, headers={"cookie": f"d={cookie}"}
        )
        try:
            resp = client.auth_test()
        except SlackApiError:
            console.print(
                f"[red]Skipping {ws_name}: auth validation failed[/]"
            )
            continue

        team = resp.get("team", ws_name)
        user = resp.get("user", "")
        config["workspaces"][team] = {
            "token": token,
            "team": team,
            "user": user,
        }
        if first_team is None:
            first_team = team
        console.print(
            f"[green]Logged in as [bold]{user}[/bold] "
            f"in [bold]{team}[/bold][/]"
        )

    if not config.get("workspaces"):
        raise click.ClickException("No workspaces could be validated.")

    # Set default to first workspace if not already set
    if "default" not in config and first_team:
        config["default"] = first_team


# -- workspaces ---------------------------------------------------------------


@cli.command()
def workspaces() -> None:
    """List all saved workspaces."""
    config = load_config()
    ws_map = config.get("workspaces", {})
    default = config.get("default", "")

    if not ws_map:
        raise click.ClickException("No workspaces saved. Run 'login' first.")

    table = Table(title="Workspaces")
    table.add_column("Name", style="cyan")
    table.add_column("User")
    table.add_column("Default")

    for name, ws in ws_map.items():
        is_default = "yes" if name == default else ""
        table.add_row(name, ws.get("user", ""), is_default)

    console.print(table)
    console.print("[dim]Use -w <name> to switch workspace for a command.[/]")


@cli.command()
@click.argument("name")
def default(name: str) -> None:
    """Set the default workspace."""
    config = load_config()
    ws_map = config.get("workspaces", {})
    if name not in ws_map:
        available = ", ".join(ws_map.keys())
        raise click.ClickException(
            f"Workspace '{name}' not found. Available: {available}"
        )
    config["default"] = name
    save_config(config)
    console.print(f"[green]Default workspace set to [bold]{name}[/bold][/]")


@cli.command()
@click.pass_context
def refresh(ctx: click.Context) -> None:
    """Force-refresh the channel and user cache for the active workspace."""
    client = get_client(workspace=ctx.obj["workspace"])
    ws = ctx.obj["workspace_name"]

    console.print(f"[yellow]Refreshing cache for {ws}…[/]")
    ch_map = build_channel_cache(client, ws)
    console.print(f"  Cached [bold]{len(ch_map)}[/] channels")
    user_data = build_user_cache(client, ws)
    user_count = len(user_data.get("id_to_display", {}))
    console.print(f"  Cached [bold]{user_count}[/] users")
    console.print("[green]Cache refreshed.[/]")


# -- channels -----------------------------------------------------------------


@cli.command()
@click.option(
    "--type",
    "channel_types",
    default="public_channel,private_channel",
    help="Comma-separated channel types to list.",
)
@click.option(
    "--all",
    "show_all",
    is_flag=True,
    default=False,
    help="Show all visible channels, not just joined ones.",
)
@click.pass_context
def channels(ctx: click.Context, channel_types: str, show_all: bool) -> None:
    """List joined channels (use --all to include unjoined)."""
    client = get_client(workspace=ctx.obj["workspace"])
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
            # Skip channels the user hasn't joined unless --all
            if not show_all and not ch.get("is_member"):
                continue
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
@click.pass_context
def read(ctx: click.Context, channel: str, limit: int) -> None:
    """Read recent messages from a channel."""
    client = get_client(workspace=ctx.obj["workspace"])
    ws = ctx.obj["workspace_name"]
    channel_id = resolve_channel(client, channel, workspace=ws)

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
    _print_messages(client, messages, workspace=ws)


# -- thread -------------------------------------------------------------------


@cli.command()
@click.argument("channel")
@click.argument("ts")
@click.option("--limit", default=50, help="Number of replies to show.")
@click.option("--dm", "is_dm", is_flag=True, default=False, help="Treat CHANNEL as a user name and resolve to DM channel.")
@click.pass_context
def thread(ctx: click.Context, channel: str, ts: str, limit: int, is_dm: bool) -> None:
    """Read thread replies for a given message timestamp."""
    client = get_client(workspace=ctx.obj["workspace"])
    ws = ctx.obj["workspace_name"]

    if is_dm:
        # Resolve user name to DM channel
        user_id = channel
        if not (channel.startswith("U") and channel[1:].isalnum()):
            user_id = _resolve_user_by_name(client, channel, workspace=ws)
        try:
            resp = client.conversations_open(users=[user_id])
        except SlackApiError as exc:
            raise click.ClickException(str(exc)) from exc
        channel_id = resp["channel"]["id"]
    else:
        channel_id = resolve_channel(client, channel, workspace=ws)

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
    _print_messages(client, replies, workspace=ws)


# -- users --------------------------------------------------------------------


@cli.command()
@click.pass_context
def users(ctx: click.Context) -> None:
    """List workspace members."""
    client = get_client(workspace=ctx.obj["workspace"])
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
@click.option("--thread", "thread_ts", default=None, help="Reply in thread (message timestamp).")
@click.pass_context
def send(ctx: click.Context, channel: str, message: str, thread_ts: str | None) -> None:
    """Send a message to a channel. Use --thread to reply in a thread."""
    client = get_client(workspace=ctx.obj["workspace"])
    ws = ctx.obj["workspace_name"]
    channel_id = resolve_channel(client, channel, workspace=ws)

    kwargs: dict = {"channel": channel_id, "text": message}
    if thread_ts:
        kwargs["thread_ts"] = thread_ts

    try:
        resp = client.chat_postMessage(**kwargs)
    except SlackApiError as exc:
        raise click.ClickException(str(exc)) from exc

    ts = resp.get("ts", "")
    console.print(f"[green]Message sent[/] (ts={ts})")


# -- dm -----------------------------------------------------------------------


@cli.command()
@click.argument("user")
@click.argument("message", required=False, default=None)
@click.option("--limit", default=20, help="Messages to show when reading.")
@click.option("--thread", "thread_ts", default=None, help="Reply in thread (message timestamp).")
@click.pass_context
def dm(ctx: click.Context, user: str, message: str | None, limit: int, thread_ts: str | None) -> None:
    """Open a DM with a user. Send a message or read recent history."""
    client = get_client(workspace=ctx.obj["workspace"])
    ws = ctx.obj["workspace_name"]

    # Resolve user name to ID if needed (simple heuristic: IDs start with U)
    user_id = user
    if not (user.startswith("U") and user[1:].isalnum()):
        user_id = _resolve_user_by_name(client, user, workspace=ws)

    # Open (or retrieve) the DM channel
    try:
        resp = client.conversations_open(users=[user_id])
    except SlackApiError as exc:
        raise click.ClickException(str(exc)) from exc

    dm_channel = resp["channel"]["id"]

    if message:
        kwargs: dict = {"channel": dm_channel, "text": message}
        if thread_ts:
            kwargs["thread_ts"] = thread_ts
        try:
            send_resp = client.chat_postMessage(**kwargs)
        except SlackApiError as exc:
            raise click.ClickException(str(exc)) from exc
        label = "DM thread reply sent" if thread_ts else "DM sent"
        console.print(
            f"[green]{label}[/] (ts={send_resp.get('ts', '')})"
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
        _print_messages(client, messages, workspace=ws)


def _resolve_user_by_name(
    client: WebClient, name: str, workspace: str = ""
) -> str:
    """Resolve a user by username or display_name, using disk cache."""
    if workspace:
        user_data = _get_user_cache(client, workspace)
        # Check username first, then display name
        uid = user_data.get("name_to_id", {}).get(name)
        if uid:
            return uid
        uid = user_data.get("display_to_id", {}).get(name)
        if uid:
            return uid

    # Cache miss — fall back to paginating the API
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
@click.pass_context
def search(ctx: click.Context, query: str, count: int, page: int) -> None:
    """Search messages across the workspace."""
    client = get_client(workspace=ctx.obj["workspace"])

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


def _print_messages(
    client: WebClient, messages: list[dict], workspace: str = ""
) -> None:
    """Render a list of Slack messages to the console."""
    for msg in messages:
        user_id = msg.get("user", "")
        username = resolve_user(client, user_id, workspace=workspace) if user_id else "bot"
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
