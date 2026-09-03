"""Config fallback to the 1Password vault through the claudine-secret helper."""

import json
import subprocess

import slack_user_cli as cli


def completed(stdout: str, code: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=code, stdout=stdout, stderr="")


def test_vault_config_parses_helper_output(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: completed(json.dumps({"cookie": "d", "workspaces": {}})))
    assert cli.vault_config()["cookie"] == "d"


def test_vault_config_asks_for_the_slack_document(monkeypatch):
    seen = {}
    monkeypatch.setattr(subprocess, "run", lambda cmd, **k: seen.setdefault("cmd", cmd) and completed("{}"))
    cli.vault_config()
    assert seen["cmd"][1:] == ["document", "slack-user-cli config.json"]


def test_vault_config_empty_when_helper_fails(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: completed("", 3))
    assert cli.vault_config() == {}


def test_vault_config_empty_when_helper_missing(monkeypatch):
    def boom(*a, **k):
        raise FileNotFoundError("claudine-secret")
    monkeypatch.setattr(subprocess, "run", boom)
    assert cli.vault_config() == {}


def test_load_config_uses_vault_without_local_file(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "CONFIG_FILE", tmp_path / "missing.json")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: completed(json.dumps({"default": "zama", "workspaces": {}})))
    assert cli.load_config()["default"] == "zama"
