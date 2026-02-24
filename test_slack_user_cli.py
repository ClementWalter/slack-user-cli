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
    """Write a valid config and return its path."""
    tmp_config.parent.mkdir(parents=True, exist_ok=True)
    tmp_config.write_text(
        json.dumps({"token": "xoxc-test", "cookie": "xoxd-test"})
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

    def test_returns_saved_data(self, saved_config):
        config = load_config()
        assert config["token"] == "xoxc-test"

    def test_returns_cookie(self, saved_config):
        config = load_config()
        assert config["cookie"] == "xoxd-test"


class TestSaveConfig:
    def test_creates_file(self, tmp_config):
        save_config({"token": "t", "cookie": "c"})
        assert tmp_config.exists()

    def test_persists_token(self, tmp_config):
        save_config({"token": "xoxc-new", "cookie": "xoxd-new"})
        data = json.loads(tmp_config.read_text())
        assert data["token"] == "xoxc-new"

    def test_creates_parent_dirs(self, tmp_config):
        # Ensure parent doesn't exist yet
        assert not tmp_config.parent.exists()
        save_config({"token": "t", "cookie": "c"})
        assert tmp_config.parent.exists()


# -- get_client tests ---------------------------------------------------------


class TestGetClient:
    def test_raises_when_no_config(self, tmp_config):
        with pytest.raises(Exception, match="Not logged in"):
            get_client({})

    def test_raises_when_missing_token(self, tmp_config):
        with pytest.raises(Exception, match="Not logged in"):
            get_client({"cookie": "c"})

    def test_raises_when_missing_cookie(self, tmp_config):
        with pytest.raises(Exception, match="Not logged in"):
            get_client({"token": "t"})

    def test_returns_client_with_valid_config(self, saved_config):
        client = get_client({"token": "xoxc-t", "cookie": "xoxd-c"})
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
        assert config["token"] == "xoxc-tok"

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
