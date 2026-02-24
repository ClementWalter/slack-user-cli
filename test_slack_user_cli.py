#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "pytest>=8.0",
#     "slack-sdk>=3.33",
#     "slacktokens>=0.2.6",
#     "click>=8.0",
#     "rich>=13.0",
# ]
# ///
"""Unit tests for slack_user_cli.py.

Each test covers a single assertion. WebClient is mocked throughout
to avoid real API calls.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner
from slack_sdk.errors import SlackApiError

from slack_user_cli import (
    _channel_type_label,
    _format_ts,
    cli,
    get_client,
    get_workspace_config,
    load_config,
    resolve_channel,
    resolve_user,
    save_config,
)


# -- Fixtures -----------------------------------------------------------------


@pytest.fixture()
def runner():
    """Click CLI test runner."""
    return CliRunner()


@pytest.fixture()
def tmp_config(tmp_path, monkeypatch):
    """Redirect config to a temp directory so tests don't touch real config."""
    config_dir = tmp_path / ".config" / "slack-user-cli"
    config_file = config_dir / "config.json"
    monkeypatch.setattr("slack_user_cli.CONFIG_DIR", config_dir)
    monkeypatch.setattr("slack_user_cli.CONFIG_FILE", config_file)
    return config_file


@pytest.fixture()
def saved_config(tmp_config):
    """Write a valid multi-workspace config and return its path."""
    tmp_config.parent.mkdir(parents=True, exist_ok=True)
    tmp_config.write_text(
        json.dumps({
            "cookie": "xoxd-test",
            "default": "testteam",
            "workspaces": {
                "testteam": {
                    "token": "xoxc-test",
                    "team": "testteam",
                    "user": "testuser",
                }
            },
        })
    )
    return tmp_config


@pytest.fixture()
def legacy_config(tmp_config):
    """Write a legacy single-workspace config for migration tests."""
    tmp_config.parent.mkdir(parents=True, exist_ok=True)
    tmp_config.write_text(
        json.dumps({"token": "xoxc-test", "cookie": "xoxd-test", "team": "legacyteam", "user": "legacyuser"})
    )
    return tmp_config


@pytest.fixture()
def mock_client():
    """A mocked WebClient instance."""
    return MagicMock()


@pytest.fixture(autouse=True)
def _clear_user_cache():
    """Reset the module-level user cache between tests."""
    from slack_user_cli import _user_cache

    _user_cache.clear()


# -- Config tests -------------------------------------------------------------


class TestLoadConfig:
    def test_returns_empty_dict_when_missing(self, tmp_config):
        assert load_config() == {}

    def test_returns_workspaces(self, saved_config):
        config = load_config()
        assert "testteam" in config["workspaces"]

    def test_returns_cookie(self, saved_config):
        config = load_config()
        assert config["cookie"] == "xoxd-test"

    def test_migrates_legacy_format(self, legacy_config):
        """Legacy {token, cookie} config is auto-migrated to multi-workspace."""
        config = load_config()
        assert "workspaces" in config

    def test_legacy_migration_preserves_token(self, legacy_config):
        config = load_config()
        assert config["workspaces"]["legacyteam"]["token"] == "xoxc-test"

    def test_legacy_migration_sets_default(self, legacy_config):
        config = load_config()
        assert config["default"] == "legacyteam"


class TestSaveConfig:
    def test_creates_file(self, tmp_config):
        save_config({"cookie": "c", "workspaces": {}})
        assert tmp_config.exists()

    def test_persists_data(self, tmp_config):
        save_config({"cookie": "xoxd-new", "workspaces": {"ws": {"token": "t"}}})
        data = json.loads(tmp_config.read_text())
        assert data["cookie"] == "xoxd-new"

    def test_creates_parent_dirs(self, tmp_config):
        # Ensure parent doesn't exist yet
        assert not tmp_config.parent.exists()
        save_config({"cookie": "c", "workspaces": {}})
        assert tmp_config.parent.exists()


# -- get_workspace_config tests -----------------------------------------------


class TestGetWorkspaceConfig:
    def test_raises_when_no_workspaces(self):
        with pytest.raises(Exception, match="Not logged in"):
            get_workspace_config({}, None)

    def test_raises_when_workspace_not_found(self):
        config = {"workspaces": {"team1": {"token": "t"}}, "cookie": "c"}
        with pytest.raises(Exception, match="not found"):
            get_workspace_config(config, "nonexistent")

    def test_returns_token_and_cookie(self):
        config = {
            "workspaces": {"myteam": {"token": "xoxc-t"}},
            "cookie": "xoxd-c",
            "default": "myteam",
        }
        ws = get_workspace_config(config, None)
        assert ws["token"] == "xoxc-t"

    def test_uses_default_workspace(self):
        config = {
            "workspaces": {"a": {"token": "ta"}, "b": {"token": "tb"}},
            "cookie": "c",
            "default": "b",
        }
        ws = get_workspace_config(config, None)
        assert ws["token"] == "tb"

    def test_explicit_workspace_overrides_default(self):
        config = {
            "workspaces": {"a": {"token": "ta"}, "b": {"token": "tb"}},
            "cookie": "c",
            "default": "a",
        }
        ws = get_workspace_config(config, "b")
        assert ws["token"] == "tb"


# -- get_client tests ---------------------------------------------------------


class TestGetClient:
    def test_raises_when_empty_config(self, tmp_config):
        with pytest.raises(Exception, match="Not logged in"):
            get_client({})

    def test_returns_client_with_valid_config(self, saved_config):
        client = get_client()
        assert client is not None


# -- resolve_user tests -------------------------------------------------------


class TestResolveUser:
    def test_returns_display_name(self, mock_client):
        mock_client.users_info.return_value = {
            "user": {
                "profile": {"display_name": "alice"},
                "real_name": "Alice Smith",
            }
        }
        assert resolve_user(mock_client, "U123") == "alice"

    def test_falls_back_to_real_name(self, mock_client):
        mock_client.users_info.return_value = {
            "user": {"profile": {"display_name": ""}, "real_name": "Bob Jones"}
        }
        assert resolve_user(mock_client, "U456") == "Bob Jones"

    def test_falls_back_to_user_id(self, mock_client):
        mock_client.users_info.return_value = {
            "user": {"profile": {"display_name": ""}, "real_name": ""}
        }
        # Empty strings are falsy, should fall back to user_id
        assert resolve_user(mock_client, "U789") == "U789"

    def test_caches_result(self, mock_client):
        mock_client.users_info.return_value = {
            "user": {"profile": {"display_name": "cached"}}
        }
        resolve_user(mock_client, "UCACHE")
        resolve_user(mock_client, "UCACHE")
        # Should only call API once due to caching
        assert mock_client.users_info.call_count == 1

    def test_returns_user_id_on_api_error(self, mock_client):
        mock_client.users_info.side_effect = SlackApiError(
            message="error",
            response=MagicMock(status_code=200, data={"ok": False, "error": "user_not_found"}),
        )
        assert resolve_user(mock_client, "UFAIL") == "UFAIL"


# -- resolve_channel tests ----------------------------------------------------


class TestResolveChannel:
    def test_passes_through_channel_id(self, mock_client):
        assert resolve_channel(mock_client, "C12345ABC") == "C12345ABC"

    def test_passes_through_dm_id(self, mock_client):
        assert resolve_channel(mock_client, "D12345ABC") == "D12345ABC"

    def test_passes_through_group_id(self, mock_client):
        assert resolve_channel(mock_client, "G12345ABC") == "G12345ABC"

    def test_resolves_name_to_id(self, mock_client):
        mock_client.conversations_list.return_value = {
            "channels": [{"id": "C999", "name": "general"}],
            "response_metadata": {"next_cursor": ""},
        }
        assert resolve_channel(mock_client, "general") == "C999"

    def test_raises_when_not_found(self, mock_client):
        mock_client.conversations_list.return_value = {
            "channels": [],
            "response_metadata": {"next_cursor": ""},
        }
        with pytest.raises(Exception, match="not found"):
            resolve_channel(mock_client, "nonexistent")


# -- _channel_type_label tests -----------------------------------------------


class TestChannelTypeLabel:
    def test_im(self):
        assert _channel_type_label({"is_im": True}) == "DM"

    def test_mpim(self):
        assert _channel_type_label({"is_mpim": True}) == "Group DM"

    def test_private(self):
        assert _channel_type_label({"is_private": True}) == "Private"

    def test_public(self):
        assert _channel_type_label({}) == "Public"


# -- _format_ts tests ---------------------------------------------------------


class TestFormatTs:
    def test_valid_timestamp(self):
        # 1700000000 = 2023-11-14 22:13 UTC
        assert _format_ts("1700000000.000000") == "2023-11-14 22:13"

    def test_invalid_timestamp_returns_original(self):
        assert _format_ts("not-a-ts") == "not-a-ts"

    def test_empty_string_returns_original(self):
        assert _format_ts("") == ""


# -- CLI command tests --------------------------------------------------------


class TestLoginManual:
    @patch("slack_user_cli.WebClient")
    def test_successful_manual_login(self, mock_wc_cls, runner, tmp_config):
        mock_instance = MagicMock()
        mock_instance.auth_test.return_value = {
            "user": "testuser",
            "team": "testteam",
        }
        mock_wc_cls.return_value = mock_instance

        result = runner.invoke(
            cli,
            ["login", "--manual"],
            input="xoxc-token\nxoxd-cookie\n",
        )
        assert "Logged in as" in result.output

    @patch("slack_user_cli.WebClient")
    def test_saves_config_on_login(self, mock_wc_cls, runner, tmp_config):
        mock_instance = MagicMock()
        mock_instance.auth_test.return_value = {
            "user": "u",
            "team": "t",
        }
        mock_wc_cls.return_value = mock_instance

        runner.invoke(
            cli,
            ["login", "--manual"],
            input="xoxc-tok\nxoxd-cook\n",
        )
        config = json.loads(tmp_config.read_text())
        # Multi-workspace format: token stored under workspaces
        assert config["workspaces"]["t"]["token"] == "xoxc-tok"

    @patch("slack_user_cli.WebClient")
    def test_login_fails_on_auth_error(self, mock_wc_cls, runner, tmp_config):
        mock_instance = MagicMock()
        mock_instance.auth_test.side_effect = SlackApiError(
            message="invalid_auth",
            response=MagicMock(
                status_code=200, data={"ok": False, "error": "invalid_auth"}
            ),
        )
        mock_wc_cls.return_value = mock_instance

        result = runner.invoke(
            cli,
            ["login", "--manual"],
            input="bad-token\nbad-cookie\n",
        )
        assert result.exit_code != 0


class TestLoginBrowser:
    @patch("slack_user_cli.subprocess")
    @patch("slack_user_cli.WebClient")
    def test_imports_all_workspaces(
        self, mock_wc_cls, mock_subprocess, runner, tmp_config
    ):
        mock_instance = MagicMock()
        mock_instance.auth_test.side_effect = [
            {"user": "alice", "team": "Team Alpha"},
            {"user": "alice", "team": "Team Beta"},
        ]
        mock_wc_cls.return_value = mock_instance

        # Mock pbpaste returning clipboard content
        mock_subprocess.run.return_value = MagicMock(
            stdout=json.dumps({
                "teams": {
                    "T001": {"name": "Alpha", "token": "xoxc-alpha"},
                    "T002": {"name": "Beta", "token": "xoxc-beta"},
                }
            })
        )

        # Press Enter to confirm copy, then provide d cookie
        result = runner.invoke(
            cli,
            ["login", "--browser"],
            input="\nxoxd-cookie\n",
        )
        assert "Team Alpha" in result.output

    @patch("slack_user_cli.subprocess")
    @patch("slack_user_cli.WebClient")
    def test_saves_both_workspaces(
        self, mock_wc_cls, mock_subprocess, runner, tmp_config
    ):
        mock_instance = MagicMock()
        mock_instance.auth_test.side_effect = [
            {"user": "u1", "team": "WS1"},
            {"user": "u2", "team": "WS2"},
        ]
        mock_wc_cls.return_value = mock_instance

        mock_subprocess.run.return_value = MagicMock(
            stdout=json.dumps({
                "teams": {
                    "T1": {"name": "ws1", "token": "xoxc-1"},
                    "T2": {"name": "ws2", "token": "xoxc-2"},
                }
            })
        )

        runner.invoke(
            cli,
            ["login", "--browser"],
            input="\nxoxd-c\n",
        )
        config = json.loads(tmp_config.read_text())
        assert len(config["workspaces"]) == 2

    @patch("slack_user_cli.subprocess")
    @patch("slack_user_cli.WebClient")
    def test_rejects_invalid_json(
        self, mock_wc_cls, mock_subprocess, runner, tmp_config
    ):
        mock_subprocess.run.return_value = MagicMock(stdout="not-json")

        result = runner.invoke(
            cli,
            ["login", "--browser"],
            input="\n",
        )
        assert result.exit_code != 0

    @patch("slack_user_cli.subprocess")
    @patch("slack_user_cli.WebClient")
    def test_rejects_empty_clipboard(
        self, mock_wc_cls, mock_subprocess, runner, tmp_config
    ):
        mock_subprocess.run.return_value = MagicMock(stdout="")

        result = runner.invoke(
            cli,
            ["login", "--browser"],
            input="\n",
        )
        assert result.exit_code != 0

    @patch("slack_user_cli.subprocess")
    @patch("slack_user_cli.WebClient")
    def test_skips_cookie_prompt_when_already_stored(
        self, mock_wc_cls, mock_subprocess, runner, saved_config
    ):
        """When a cookie is already in config, don't prompt for it again."""
        mock_instance = MagicMock()
        mock_instance.auth_test.return_value = {
            "user": "u", "team": "New Team"
        }
        mock_wc_cls.return_value = mock_instance

        mock_subprocess.run.return_value = MagicMock(
            stdout=json.dumps({
                "teams": {"T1": {"name": "new", "token": "xoxc-new"}}
            })
        )

        # Only press Enter, no cookie prompt expected
        result = runner.invoke(
            cli,
            ["login", "--browser"],
            input="\n",
        )
        assert "New Team" in result.output


class TestChannelsCommand:
    @patch("slack_user_cli.get_client")
    def test_lists_channels(self, mock_get_client, runner, saved_config):
        mock_client = MagicMock()
        mock_client.conversations_list.return_value = {
            "channels": [
                {
                    "id": "C1",
                    "name": "general",
                    "num_members": 42,
                    "topic": {"value": "General discussion"},
                }
            ],
            "response_metadata": {"next_cursor": ""},
        }
        mock_get_client.return_value = mock_client

        result = runner.invoke(cli, ["channels"])
        assert "general" in result.output

    @patch("slack_user_cli.get_client")
    def test_shows_member_count(self, mock_get_client, runner, saved_config):
        mock_client = MagicMock()
        mock_client.conversations_list.return_value = {
            "channels": [
                {
                    "id": "C1",
                    "name": "dev",
                    "num_members": 15,
                    "topic": {"value": ""},
                }
            ],
            "response_metadata": {"next_cursor": ""},
        }
        mock_get_client.return_value = mock_client

        result = runner.invoke(cli, ["channels"])
        assert "15" in result.output


class TestReadCommand:
    @patch("slack_user_cli.get_client")
    def test_read_displays_messages(self, mock_get_client, runner, saved_config):
        mock_client = MagicMock()
        # resolve_channel: pass through ID
        mock_client.conversations_list.return_value = {
            "channels": [{"id": "C1", "name": "general"}],
            "response_metadata": {"next_cursor": ""},
        }
        mock_client.conversations_history.return_value = {
            "messages": [
                {"user": "U1", "text": "hello world", "ts": "1700000000.000"},
            ],
            "response_metadata": {"next_cursor": ""},
        }
        mock_client.users_info.return_value = {
            "user": {"profile": {"display_name": "alice"}}
        }
        mock_get_client.return_value = mock_client

        result = runner.invoke(cli, ["read", "general", "--limit", "5"])
        assert "hello world" in result.output

    @patch("slack_user_cli.get_client")
    def test_read_resolves_usernames(
        self, mock_get_client, runner, saved_config
    ):
        mock_client = MagicMock()
        mock_client.conversations_list.return_value = {
            "channels": [{"id": "C1", "name": "general"}],
            "response_metadata": {"next_cursor": ""},
        }
        mock_client.conversations_history.return_value = {
            "messages": [
                {"user": "U1", "text": "hi", "ts": "1700000000.000"},
            ],
            "response_metadata": {"next_cursor": ""},
        }
        mock_client.users_info.return_value = {
            "user": {"profile": {"display_name": "bob"}}
        }
        mock_get_client.return_value = mock_client

        result = runner.invoke(cli, ["read", "general"])
        assert "bob" in result.output


class TestThreadCommand:
    @patch("slack_user_cli.get_client")
    def test_thread_displays_replies(
        self, mock_get_client, runner, saved_config
    ):
        mock_client = MagicMock()
        mock_client.conversations_replies.return_value = {
            "messages": [
                {
                    "user": "U1",
                    "text": "parent message",
                    "ts": "1700000000.000",
                },
                {
                    "user": "U2",
                    "text": "reply here",
                    "ts": "1700000001.000",
                },
            ],
            "response_metadata": {"next_cursor": ""},
        }
        mock_client.users_info.return_value = {
            "user": {"profile": {"display_name": "charlie"}}
        }
        mock_get_client.return_value = mock_client

        result = runner.invoke(
            cli, ["thread", "C12345ABC", "1700000000.000"]
        )
        assert "reply here" in result.output


class TestUsersCommand:
    @patch("slack_user_cli.get_client")
    def test_lists_users(self, mock_get_client, runner, saved_config):
        mock_client = MagicMock()
        mock_client.users_list.return_value = {
            "members": [
                {
                    "id": "U1",
                    "name": "alice",
                    "profile": {
                        "display_name": "Alice",
                        "real_name": "Alice Smith",
                        "status_emoji": "",
                        "status_text": "",
                    },
                }
            ],
            "response_metadata": {"next_cursor": ""},
        }
        mock_get_client.return_value = mock_client

        result = runner.invoke(cli, ["users"])
        assert "Alice" in result.output

    @patch("slack_user_cli.get_client")
    def test_skips_bots(self, mock_get_client, runner, saved_config):
        mock_client = MagicMock()
        mock_client.users_list.return_value = {
            "members": [
                {
                    "id": "U1",
                    "name": "slackbot",
                    "is_bot": True,
                    "profile": {
                        "display_name": "Slackbot",
                        "real_name": "Slackbot",
                        "status_emoji": "",
                        "status_text": "",
                    },
                },
                {
                    "id": "U2",
                    "name": "human",
                    "profile": {
                        "display_name": "Human",
                        "real_name": "Human User",
                        "status_emoji": "",
                        "status_text": "",
                    },
                },
            ],
            "response_metadata": {"next_cursor": ""},
        }
        mock_get_client.return_value = mock_client

        result = runner.invoke(cli, ["users"])
        assert "Slackbot" not in result.output


class TestSendCommand:
    @patch("slack_user_cli.get_client")
    def test_send_message(self, mock_get_client, runner, saved_config):
        mock_client = MagicMock()
        mock_client.conversations_list.return_value = {
            "channels": [{"id": "C1", "name": "general"}],
            "response_metadata": {"next_cursor": ""},
        }
        mock_client.chat_postMessage.return_value = {"ts": "123.456"}
        mock_get_client.return_value = mock_client

        result = runner.invoke(cli, ["send", "general", "hello"])
        assert "Message sent" in result.output

    @patch("slack_user_cli.get_client")
    def test_send_calls_api_with_text(
        self, mock_get_client, runner, saved_config
    ):
        mock_client = MagicMock()
        mock_client.conversations_list.return_value = {
            "channels": [{"id": "C1", "name": "general"}],
            "response_metadata": {"next_cursor": ""},
        }
        mock_client.chat_postMessage.return_value = {"ts": "1.0"}
        mock_get_client.return_value = mock_client

        runner.invoke(cli, ["send", "general", "test msg"])
        mock_client.chat_postMessage.assert_called_once_with(
            channel="C1", text="test msg"
        )


class TestDmCommand:
    @patch("slack_user_cli.get_client")
    def test_dm_send(self, mock_get_client, runner, saved_config):
        mock_client = MagicMock()
        mock_client.conversations_open.return_value = {
            "channel": {"id": "D99"}
        }
        mock_client.chat_postMessage.return_value = {"ts": "1.0"}
        mock_get_client.return_value = mock_client

        result = runner.invoke(cli, ["dm", "U12345ABC", "hi there"])
        assert "DM sent" in result.output

    @patch("slack_user_cli.get_client")
    def test_dm_read_when_no_message(
        self, mock_get_client, runner, saved_config
    ):
        mock_client = MagicMock()
        mock_client.conversations_open.return_value = {
            "channel": {"id": "D99"}
        }
        mock_client.conversations_history.return_value = {
            "messages": [
                {"user": "U1", "text": "old msg", "ts": "1700000000.000"}
            ]
        }
        mock_client.users_info.return_value = {
            "user": {"profile": {"display_name": "peer"}}
        }
        mock_get_client.return_value = mock_client

        result = runner.invoke(cli, ["dm", "U12345ABC"])
        assert "old msg" in result.output


class TestSearchCommand:
    @patch("slack_user_cli.get_client")
    def test_search_displays_results(
        self, mock_get_client, runner, saved_config
    ):
        mock_client = MagicMock()
        mock_client.search_messages.return_value = {
            "messages": {
                "total": 1,
                "paging": {"page": 1, "pages": 1},
                "matches": [
                    {
                        "username": "alice",
                        "text": "found it",
                        "channel": {"name": "general"},
                        "ts": "1700000000.000",
                    }
                ],
            }
        }
        mock_get_client.return_value = mock_client

        result = runner.invoke(cli, ["search", "keyword"])
        assert "found it" in result.output

    @patch("slack_user_cli.get_client")
    def test_search_shows_total(self, mock_get_client, runner, saved_config):
        mock_client = MagicMock()
        mock_client.search_messages.return_value = {
            "messages": {
                "total": 42,
                "paging": {"page": 1, "pages": 3},
                "matches": [],
            }
        }
        mock_get_client.return_value = mock_client

        result = runner.invoke(cli, ["search", "query"])
        assert "42 total matches" in result.output


# -- Pagination tests ---------------------------------------------------------


class TestPagination:
    @patch("slack_user_cli.get_client")
    def test_channels_follows_cursor(
        self, mock_get_client, runner, saved_config
    ):
        mock_client = MagicMock()
        # First page returns a cursor, second page is empty
        mock_client.conversations_list.side_effect = [
            {
                "channels": [
                    {
                        "id": "C1",
                        "name": "page1",
                        "num_members": 1,
                        "topic": {"value": ""},
                    }
                ],
                "response_metadata": {"next_cursor": "abc123"},
            },
            {
                "channels": [
                    {
                        "id": "C2",
                        "name": "page2",
                        "num_members": 2,
                        "topic": {"value": ""},
                    }
                ],
                "response_metadata": {"next_cursor": ""},
            },
        ]
        mock_get_client.return_value = mock_client

        result = runner.invoke(cli, ["channels"])
        assert "page1" in result.output

    @patch("slack_user_cli.get_client")
    def test_channels_shows_second_page(
        self, mock_get_client, runner, saved_config
    ):
        mock_client = MagicMock()
        mock_client.conversations_list.side_effect = [
            {
                "channels": [
                    {
                        "id": "C1",
                        "name": "first",
                        "num_members": 1,
                        "topic": {"value": ""},
                    }
                ],
                "response_metadata": {"next_cursor": "next"},
            },
            {
                "channels": [
                    {
                        "id": "C2",
                        "name": "second",
                        "num_members": 2,
                        "topic": {"value": ""},
                    }
                ],
                "response_metadata": {"next_cursor": ""},
            },
        ]
        mock_get_client.return_value = mock_client

        result = runner.invoke(cli, ["channels"])
        assert "second" in result.output


# -- Workspace management tests -----------------------------------------------


class TestWorkspacesCommand:
    def test_lists_workspaces(self, runner, saved_config):
        result = runner.invoke(cli, ["workspaces"])
        assert "testteam" in result.output

    def test_shows_default_marker(self, runner, saved_config):
        result = runner.invoke(cli, ["workspaces"])
        assert "yes" in result.output

    def test_errors_when_no_workspaces(self, runner, tmp_config):
        result = runner.invoke(cli, ["workspaces"])
        assert result.exit_code != 0


class TestDefaultCommand:
    def test_sets_default(self, runner, saved_config):
        result = runner.invoke(cli, ["default", "testteam"])
        assert "Default workspace set to" in result.output

    def test_errors_on_unknown_workspace(self, runner, saved_config):
        result = runner.invoke(cli, ["default", "nonexistent"])
        assert result.exit_code != 0


class TestWorkspaceSwitch:
    @patch("slack_user_cli.get_client")
    def test_workspace_flag_passed_to_get_client(
        self, mock_get_client, runner, saved_config
    ):
        mock_client = MagicMock()
        mock_client.conversations_list.return_value = {
            "channels": [],
            "response_metadata": {"next_cursor": ""},
        }
        mock_get_client.return_value = mock_client

        runner.invoke(cli, ["-w", "testteam", "channels"])
        mock_get_client.assert_called_once_with(workspace="testteam")
