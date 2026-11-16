"""CLI smoke test for the parts that need no hidden prompt."""
import json
import os

import pytest

from gatehouse import cli
from gatehouse.store import Store
from gatehouse.vault import Vault, new_credential


def test_cli_setup_agent_grant_and_revoke(tmp_path, monkeypatch, capsys):
    home = tmp_path / "home"
    pf = tmp_path / "pass"
    pf.write_text("a long test passphrase\n")
    os.chmod(pf, 0o600)
    monkeypatch.setenv("GATEHOUSE_HOME", str(home))
    monkeypatch.setattr("gatehouse.vault.SCRYPT_N", 2 ** 12)
    monkeypatch.setattr(Vault.create, "__defaults__", (2 ** 12,))
    run = lambda *a: cli.main(["--passphrase-file", str(pf), *a])
    run("init")
    assert (home / "vault.json").stat().st_mode & 0o077 == 0 and home.stat().st_mode & 0o077 == 0

    v = Vault(home / "vault.json")
    key = v.unlock("a long test passphrase")
    with v.edit(key) as creds:
        creds.append(new_credential("Books", "u", "p", origins=["https://books.example.test"],
                                    login_url="https://books.example.test/login"))
    cfg = tmp_path / "agent.json"
    run("agent", "add", "codex", "--write-config", str(cfg))
    assert cfg.stat().st_mode & 0o077 == 0 and set(json.loads(cfg.read_text())) == {"url", "agent_id", "sign_key"}
    run("grant", "add", "--agent", "codex", "--account", "Books", "--for", "forever")
    store = Store(home / "state.db")
    (grant,) = store.grants(active_only=True)
    with pytest.raises(SystemExit):                       # cannot grant a website that is not approved on the account
        run("grant", "add", "--agent", "codex", "--account", "Books", "--origin", "https://evil.example", "--for", "once")
    with pytest.raises(SystemExit):                       # session grants need a running broker
        run("grant", "add", "--agent", "codex", "--account", "Books", "--for", "session")
    run("grant", "revoke", grant["id"])
    assert store.grants(active_only=True) == []
    run("logins", "disable")
    assert store.logins_disabled()
    run("account", "list"); run("audit"); run("status")
    out = capsys.readouterr().out
    assert "DISABLED" in out and "Books" in out


def test_passphrase_file_must_be_private(tmp_path, monkeypatch):
    pf = tmp_path / "pass"
    pf.write_text("x" * 12)
    os.chmod(pf, 0o644)
    monkeypatch.setenv("GATEHOUSE_HOME", str(tmp_path / "home"))
    with pytest.raises(SystemExit):
        cli.main(["--passphrase-file", str(pf), "init"])
