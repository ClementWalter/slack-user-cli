#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11,<3.12"  # leveldb 0.201 (via slacktokens) uses PyUnicode_AS_UNICODE, removed in 3.12
# dependencies = [
#     "pytest==9.1.1",
#     "slack-sdk==3.41.0",
#     "slacktokens==0.2.6",
#     "click==8.3.2",
#     "rich==14.3.3",
#     "requests==2.33.1",
# ]
#
# [tool.uv]
# exclude-newer = "2026-10-27T00:00:00Z"
# ///
"""Unit tests for `_fetch_canvas_content` on files that are not canvases.

A message's file id can be a video or an image; `canvas` must refuse it with a
pointer to `download` instead of rendering binary bytes. No network.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock

import click
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from slack_user_cli import _fetch_canvas_content  # noqa: E402


@pytest.fixture
def video_client():
    client = MagicMock()
    client.api_call.return_value = {"file": {"title": "rec.mov", "filetype": "mov",
                                             "pretty_type": "QuickTime Movie", "url_private": "https://x"}}
    return client


def test_non_canvas_file_is_refused(video_client):
    with pytest.raises(click.ClickException, match="QuickTime Movie file, not a canvas"):
        _fetch_canvas_content(video_client, "F0VIDEO")
