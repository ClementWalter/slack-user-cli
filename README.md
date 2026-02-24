# slack-user-cli

Terminal access to Slack using browser session credentials (`xoxc-` token + `d`
cookie). No Slack app registration, no OAuth flow — it reuses the credentials
already on your machine from the Slack desktop app or browser session.

The tool is exposed both as a standalone CLI and as a
[Claude Code](https://claude.com/claude-code) skill (see
[`SKILL.md`](SKILL.md)).

![help command](help_screen.png)

## Prerequisites

Both install paths require [`uv`](https://docs.astral.sh/uv/) — it's what runs
the script and resolves its Python dependencies on demand. Install it with:

```bash
# macOS / Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# or via Homebrew
brew install uv
```

The `npx skills` install path additionally requires Node.js (for `npx`).

## Install as a Claude Code skill

Recommended path. Uses [`npx skills`](https://github.com/vercel-labs/skills) to
drop the skill into `~/.claude/skills/slack-user-cli/`:

```bash
npx skills add ClementWalter/slack-user-cli
```

After install, Claude Code picks it up automatically — see
[`SKILL.md`](SKILL.md) for what the skill exposes.

## Install as a standalone CLI

The CLI is a single-file Python script with
[PEP 723](https://peps.python.org/pep-0723/) inline metadata, so
[`uv`](https://docs.astral.sh/uv/) handles dependencies on the fly:

```bash
uv run slack_user_cli.py --help
```

For convenience, alias it:

```bash
alias slack_user_cli='uv run /path/to/slack-user-cli/slack_user_cli.py'
```

## Authentication

Credentials are stored in `~/.config/slack-user-cli/config.json`.

```bash
# Auto-extract from the Slack desktop app (close Slack first; macOS Keychain prompt)
slack_user_cli login --auto

# Import all workspaces from the browser via clipboard
slack_user_cli login --browser

# Add a single workspace manually
slack_user_cli login --manual
```

## Usage

```bash
# Workspaces
slack_user_cli workspaces
slack_user_cli default "Workspace Name"

# Read
slack_user_cli channels
slack_user_cli read <channel> --limit 20
slack_user_cli read <channel> --limit 20 --json --expand-thread
slack_user_cli thread <channel> <message_ts>
slack_user_cli url "https://workspace.slack.com/archives/C.../p..."
slack_user_cli search "query in:#channel" --count 20

# Write
slack_user_cli send <channel> "message text"
slack_user_cli send <channel> "reply" --thread <message_ts>
slack_user_cli dm <user> "message text"
slack_user_cli upload <channel> /path/to/file.png --message "caption"

# Cross-workspace
slack_user_cli -w "Other Workspace" channels
```

Every read command emits raw Slack IDs by default (stable for scripting); pass
`--names` to resolve to display names. Every command supports `--json` for
structured output.

See [`SKILL.md`](SKILL.md) for the full command reference, output schemas, and
the channel-summary workflow.

## Cache

Channel and user data is cached at `~/.config/slack-user-cli/cache/<workspace>/`
with a 1-hour TTL. Run `slack_user_cli refresh` to force-rebuild after joining
new channels or when lookups return IDs instead of names.
