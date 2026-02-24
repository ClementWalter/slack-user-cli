---
name: slack-user-cli
description:
  "Read and write Slack channels, DMs, threads, and search from the terminal
  using slack_user_cli. Use when the user asks to interact with Slack
  workspaces, read messages, send messages, or search Slack. Every command
  supports `--json`; every read defaults to raw IDs (users, channels) and
  accepts `--names` to resolve to display names. For programmatic consumers
  (scripts, smithers workflows, pipelines) prefer `--json` to get structured
  output rather than parsing rendered text."
allowed-tools:
  - Bash
  - Read
---

# Slack User CLI

Terminal access to Slack using browser session credentials (`xoxc-` token + `d`
cookie). Located at `~/.claude/skills/slack-user-cli/slack_user_cli.py`.

## Running

All commands use `uv run`:

```bash
uv run ~/.claude/skills/slack-user-cli/slack_user_cli.py <command> [options]
```

## Authentication

Must be logged in before using any command. Credentials are stored in
`~/.config/slack-user-cli/config.json`.

```bash
# Auto-extract from Slack desktop app (close Slack first)
slack_user_cli login --auto

# Import all workspaces from browser — copies to clipboard, reads via pbpaste
slack_user_cli login --browser

# Add a single workspace manually
slack_user_cli login --manual
```

## Global Options

| Option                            | Description                                 |
| --------------------------------- | ------------------------------------------- |
| `-w <name>`, `--workspace <name>` | Use a specific workspace instead of default |
| `--debug`                         | Enable debug logging                        |

## Output Conventions

- **IDs by default.** Every read command emits raw Slack IDs (`U…` users,
  `C…`/`D…`/`G…` channels) so output is stable for scripts. Do **not** add
  `--names` unless the user explicitly asks for human-readable names — raw IDs
  are the right answer for chaining further commands.
- **`--names` is opt-in.** Only when the user specifically wants display names
  (e.g. "show me who said what", "summarize this thread"), pass `--names` to
  resolve user/channel IDs and rewrite `<@UXXX>` mentions.
- **`--json` everywhere.** Every command supports `--json` for structured
  output. Use it whenever a programmatic consumer would otherwise parse rendered
  text. `--json` and `--names` are independent.

## Commands Reference

### Workspace Management

```bash
# List all saved workspaces
slack_user_cli workspaces

# Set default workspace
slack_user_cli default "Workspace Name"

# Force-refresh the channel and user cache
slack_user_cli refresh
```

### Reading

```bash
# List joined channels (output: channel IDs)
slack_user_cli channels
slack_user_cli channels --all
slack_user_cli channels --type "public_channel,private_channel,mpim,im"
slack_user_cli channels --json   # {channels: [{id, name, type, num_members, topic, is_member}, ...]}

# Read recent messages from a channel (by name or ID; output: user IDs)
slack_user_cli read <channel_name_or_id> --limit 20

# Emit structured JSON instead of human-readable text (for programmatic
# consumers — smithers workflows, scripts, pipelines). Shape:
#   {"channel": "...", "messages": [{"ts", "user", "text", "threadCount"?, "replies"?}, ...]}
# Use this whenever you would otherwise have to parse the pretty output back
# into fields — the parse step is the #1 source of bugs and timeouts.
slack_user_cli read <channel_name_or_id> --limit 20 --json

# Add --expand-thread to inline every thread's replies under `replies: [...]`
# on the parent. Only meaningful with --json. Most decisions live in replies
# rather than parent posts, so expansion is almost always what you want for
# analysis; skip it only when you need cheap channel-level metadata.
slack_user_cli read <channel_name_or_id> --limit 20 --json --expand-thread

# Read thread replies (use --dm when CHANNEL is a user name, not a channel)
slack_user_cli thread <channel_name_or_id> <message_ts>
slack_user_cli thread <channel_name_or_id> <message_ts> --json
slack_user_cli thread --dm <user_name_or_id> <message_ts>

# Read a thread directly from a Slack permalink URL
slack_user_cli url "https://workspace.slack.com/archives/C.../p..."
slack_user_cli url "https://workspace.slack.com/archives/C.../p..." --json

# List workspace members (output: user IDs)
slack_user_cli users
slack_user_cli users --json   # {users: [{id, name, display_name, real_name, status_emoji, status_text}, ...]}

# List channels a user is a member of (by username or user ID; output: channel IDs)
slack_user_cli user-channels <user_name_or_id>
slack_user_cli user-channels <user_name_or_id> --json
slack_user_cli user-channels <user_name_or_id> --type "public_channel,private_channel,mpim"
```

### Writing

**CRITICAL: When drafting messages for the user, read and follow the tone guide
in `~/.claude/skills/slack-user-cli/TONE.md`.** Match the user's natural voice:
casual, humble, concrete, no marketing-speak. If file does not exist, create it.

**CRITICAL: Before sending any message to a main channel (i.e. a `send`
command), you MUST use `AskUserQuestion` to get explicit approval.** Posting to
a main channel is visible to everyone and cannot be undone. Always confirm with
the user first.

**Permalink timestamp parsing:** When replying to a thread from a Slack
permalink URL (e.g. `https://...slack.com/archives/C.../p1012345678907689`),
extract the thread_ts by inserting a dot before the last 6 digits of the `p`
value: `p1012345678907689` → `1012345678.907689`. Double-check this conversion
before sending.

```bash
# Send a message to a channel (use --thread to reply in a thread)
slack_user_cli send <channel_name_or_id> "message text"
slack_user_cli send <channel_name_or_id> "reply text" --thread <message_ts>

# DM a user (by display name or user ID; use --thread for thread replies)
slack_user_cli dm <user_name_or_id> "message text"
slack_user_cli dm <user_name_or_id> "reply text" --thread <message_ts>
slack_user_cli dm <user_name_or_id> "message" --json

# Read DM history (omit message; output: user IDs). Same --json shape as `read`.
slack_user_cli dm <user_name_or_id>
slack_user_cli dm <user_name_or_id> --json
```

### File Uploads

**Same approval rules as Writing above** — uploading to a main channel (without
`--thread`) requires `AskUserQuestion` confirmation first.

```bash
# Upload a file to a channel
slack_user_cli upload <channel_name_or_id> /path/to/file.png

# Upload with a message and title
slack_user_cli upload <channel_name_or_id> /path/to/file.png --message "Here's the report" --title "Q1 Report"

# Upload in a thread
slack_user_cli upload <channel_name_or_id> /path/to/file.png --thread <message_ts>

# Upload a file via DM
slack_user_cli dm-upload <user_name_or_id> /path/to/file.png

# DM upload with message and in a thread
slack_user_cli dm-upload <user_name_or_id> /path/to/file.png --message "See attached" --thread <message_ts>
```

### Important: DM User Name Resolution

When using `dm`, the USER argument must match the Slack **username** (e.g.
`first.last`), not the display name with spaces (e.g. `First Last`). Use
`search "from:<username>"` to discover the correct username format.

### Search

```bash
# Search messages (output: raw user/channel IDs in user/channel fields)
slack_user_cli search "query" --count 20 --page 1
slack_user_cli search "query" --json
```

### Canvases

```bash
# Read a canvas by URL (outputs plain text by default)
slack_user_cli canvas "https://workspace.slack.com/docs/TEAM_ID/FILE_ID"

# Read a canvas by file ID
slack_user_cli canvas DEADBEEFUUV

# Get raw HTML output
slack_user_cli canvas "https://workspace.slack.com/docs/TEAM_ID/FILE_ID" --html

# JSON: {file_id, title, text} (or html with --html)
slack_user_cli canvas DEADBEEFUUV --json

# Append markdown to a canvas (default: insert_at_end)
slack_user_cli canvas-edit DEADBEEFUUV "## New Section\nSome text"

# Replace entire canvas content
slack_user_cli canvas-edit DEADBEEFUUV "## Fresh Start" --operation replace

# Prepend content
slack_user_cli canvas-edit DEADBEEFUUV "## Header" --operation insert_at_start

# Pipe content from a file or heredoc
cat summary.md | slack_user_cli canvas-edit DEADBEEFUUV --operation replace
```

### Cross-workspace Usage

```bash
# Read from a specific workspace
slack_user_cli -w "Other Workspace" channels
slack_user_cli -w "Other Workspace" read general --limit 5
```

## Cache

Channel and user data is cached to disk for fast resolution:

- **Location**: `~/.config/slack-user-cli/cache/<workspace>/`
- **Files**: `channels.json` (name→id map), `users.json` (id→display, name→id,
  display→id maps)
- **TTL**: 1 hour — cache auto-expires and is rebuilt on next use
- **Refresh**: run `slack_user_cli refresh` to force-rebuild both caches
- **Behavior**: `resolve_user()` passively reads disk cache, falling back to a
  single `users_info` API call — never triggers a full `users_list` build.
  `resolve_channel()` and `_resolve_user_by_name()` will auto-build the cache on
  first use if it doesn't exist.

Run `refresh` after joining new channels or when user lookups return IDs instead
of names.

## Key Details

- **Auth model**: `xoxc-` token (per-workspace) + `d` cookie (shared across
  workspaces), extracted from browser or Slack desktop app
- **Config location**: `~/.config/slack-user-cli/config.json`
- **Cache location**: `~/.config/slack-user-cli/cache/<workspace>/`
- **Multi-workspace**: stores all workspaces; use `-w` to switch or `default` to
  set the default
- **Channel resolution**: accepts channel names (without `#`) or IDs (starting
  with C/D/G); uses disk cache for fast lookup
- **User resolution**: accepts display names, usernames, or user IDs (starting
  with U); uses disk cache + single API fallback
- **Pagination**: handled automatically for channels, users, messages, and
  threads
- **Search**: uses page-based pagination (`--page`, `--count`)
- **Output**: formatted with Rich tables and colored text
- **Timestamps**: message timestamps (`ts`) are displayed as `YYYY-MM-DD HH:MM`
  UTC

## Channel Summary Workflow

When the user asks to summarize a Slack channel (e.g., "summarize #general since
Feb 27"), follow this procedure:

### 1. Resolve channel ID and start date

- If the user gives a channel name, resolve the ID:
  ```bash
  slack_user_cli channels --all 2>&1 | grep -i "<channel_name>"
  ```
- If the channel name isn't found (e.g., cross-workspace channel), ask the user
  for a sample message link from that channel to extract the channel ID (`C...`
  from the URL).
- If no start date is provided, **ask the user** for one before proceeding.

### 2. Read channel messages from the start date

```bash
slack_user_cli read <channel_id> --limit 100
```

- Filter the output to messages on or after the start date.
- Identify every top-level message that has `[N replies]` — these are threads.
- Also note standalone messages (no replies) that contain decisions or actions.

### 3. Read each thread

For each threaded message, use the `url` command with a constructed permalink.
The permalink format is:

```
https://<workspace>.slack.com/archives/<channel_id>/p<ts_without_dot>
```

To convert a displayed timestamp like `1772191041.209019` to a permalink `p`
value, remove the dot: `p1772191041209019`.

**However**, the `read` command output doesn't show raw timestamps. Instead, use
`search` to find the thread starter message and get its context, then use the
`url` command:

```bash
# Find thread by searching for unique keywords from the message
slack_user_cli search "<unique phrase from message> in:<channel_name>" --count 3

# Read the full thread via permalink
slack_user_cli url "https://<workspace>.slack.com/archives/<channel_id>/p<ts>"
```

**If `url` fails** with `thread_not_found`, fall back to `search` with targeted
keywords to retrieve thread replies:

```bash
slack_user_cli search "<topic keywords> in:<channel_name>" --count 15
```

### 4. Summarize each thread

For each thread, produce a structured summary:

- **Topic**: One-line description
- **Decisions taken**: What was agreed upon
- **Pending / Open questions**: Unresolved items
- **Next steps / Action items**: Who does what
- **Codebase relevance**: How it relates to the current project (backend,
  frontend, SDK, infrastructure, etc.) — only include if applicable

### 5. Cross-cutting summary

After all threads, add a cross-cutting table of **technical issues** that span
multiple threads, with columns: Issue | Impact | Status.

### Tips

- The `read` command returns messages newest-first by default. Increase
  `--limit` if the start date is far back.
- Search is more reliable than `read` for finding specific messages and their
  thread replies. Use `in:<channel_name>` to scope searches.
- Watch for Slack API rate limits. If you hit `ratelimited`, wait a few seconds
  and retry.
- For large channels, process threads in batches of 3-5 to avoid rate limits.

## Troubleshooting

- **"Not logged in"**: run `slack_user_cli login --browser` or `--manual`
- **"Workspace not found"**: check available names with
  `slack_user_cli workspaces`
- **Token expired**: tokens expire on Slack logout; re-run `login`
- **Too many channels**: `channels` shows only joined by default; this is
  correct
- **macOS Keychain prompt**: expected when using `--auto` (cookie decryption)
- **User shows as ID instead of name**: run `slack_user_cli refresh` to rebuild
  the user cache
- **Channel not found after joining**: run `slack_user_cli refresh` to rebuild
  the channel cache
