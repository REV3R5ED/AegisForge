"""Tests for the scan/baseline CLI surface (network fully mocked)."""

import json

import pytest

from aegisforge.cli.main import main
from aegisforge.core.results import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK
from aegisforge.network import scanner as scanner_mod
from aegisforge.network.scanner import PortResult, ScanResult


@pytest.fixture(autouse=True)
def _isolated(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGISFORGE_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("AEGISFORGE_AUDIT_LOG", str(tmp_path / "audit.log"))


def _fake_scan(target="localhost"):
    return ScanResult(
        target=target,
        resolved_ip="127.0.0.1",
        ports=[
            PortResult(port=22, state="open", service="ssh", banner="SSH-2.0-x"),
            PortResult(port=80, state="closed"),
        ],
        duration_ms=42.0,
    )


def _patch_scan(monkeypatch, scan=None):
    scan = scan or _fake_scan()
    monkeypatch.setattr(scanner_mod, "scan_host", lambda *a, **k: scan)
    return scan


def test_scan_human_output(monkeypatch, capsys):
    _patch_scan(monkeypatch)
    code = main(["network", "scan", "localhost", "--ports", "22,80"])
    assert code == EXIT_OK
    out = capsys.readouterr().out
    assert "1/2 ports open" in out
    assert "22" in out and "open" in out and "ssh" in out


def test_scan_json_output(monkeypatch, capsys):
    _patch_scan(monkeypatch)
    code = main(["network", "scan", "localhost", "--json"])
    assert code == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    assert data["command"] == "network scan"
    assert data["data"]["ports_open"] == 1
    assert data["data"]["ports"][0]["service"] == "ssh"


def test_scan_csv_output(monkeypatch, capsys):
    _patch_scan(monkeypatch)
    code = main(["network", "scan", "localhost", "--csv"])
    assert code == EXIT_OK
    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == "target,port,state,service,rtt_ms,banner"
    assert any(",22,open,ssh," in line for line in lines[1:])


def test_scan_authorization_refused(monkeypatch, capsys):
    from aegisforge.network.scanner import ScanAuthorizationError

    def _refused(*a, **k):
        raise ScanAuthorizationError("refusing without --allow-remote")

    monkeypatch.setattr(scanner_mod, "scan_host", _refused)
    code = main(["network", "scan", "93.184.216.34"])
    assert code == EXIT_ERROR
    assert "--allow-remote" in capsys.readouterr().err


def test_scan_bad_port_spec_is_exit_2(capsys):
    code = main(["network", "scan", "localhost", "--ports", "abc"])
    assert code == EXIT_ERROR


def test_scan_tls_expiry_finding(monkeypatch, capsys):
    scan = _fake_scan()
    scan.ports[0].tls = {
        "not_after": "2020-01-01T00:00:00Z",
        "days_until_expiry": -100,
        "subject": {"CN": "localhost"},
    }
    _patch_scan(monkeypatch, scan)
    code = main(["network", "scan", "localhost", "--json"])
    assert code == EXIT_FINDINGS
    data = json.loads(capsys.readouterr().out)
    assert data["status"] == "warning"
    assert any("expired" in f["title"] for f in data["findings"])


def test_baseline_save_and_list(monkeypatch, capsys):
    _patch_scan(monkeypatch)
    code = main(["network", "baseline", "save", "lab", "localhost"])
    assert code == EXIT_OK
    assert "saved" in capsys.readouterr().out
    code = main(["network", "baseline", "list", "--json"])
    assert code == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    assert [b["name"] for b in data["data"]["baselines"]] == ["lab"]


def test_baseline_diff_detects_new_port(monkeypatch, capsys):
    _patch_scan(monkeypatch)
    assert main(["network", "baseline", "save", "lab", "localhost"]) == EXIT_OK
    capsys.readouterr()
    new_scan = _fake_scan()
    new_scan.ports.append(PortResult(port=8080, state="open", service="http"))
    _patch_scan(monkeypatch, new_scan)
    code = main(["network", "baseline", "diff", "lab", "localhost", "--json"])
    assert code == EXIT_FINDINGS
    data = json.loads(capsys.readouterr().out)
    changes = data["data"]["changes"]
    assert len(changes) == 1
    assert changes[0]["change"] == "new" and changes[0]["port"] == 8080
    assert any("new open port" in f["title"] for f in data["findings"])


def test_baseline_diff_human_output(monkeypatch, capsys):
    _patch_scan(monkeypatch)
    main(["network", "baseline", "save", "lab", "localhost"])
    capsys.readouterr()
    new_scan = _fake_scan()
    new_scan.ports.append(PortResult(port=8080, state="open", service="http"))
    _patch_scan(monkeypatch, new_scan)
    code = main(["network", "baseline", "diff", "lab", "localhost"])
    assert code == EXIT_FINDINGS
    out = capsys.readouterr().out
    assert "NEW:" in out and "8080" in out


def test_baseline_diff_csv(monkeypatch, capsys):
    _patch_scan(monkeypatch)
    main(["network", "baseline", "save", "lab", "localhost"])
    capsys.readouterr()
    new_scan = _fake_scan()
    new_scan.ports.append(PortResult(port=8080, state="open", service="http"))
    _patch_scan(monkeypatch, new_scan)
    code = main(["network", "baseline", "diff", "lab", "localhost", "--csv"])
    assert code == EXIT_FINDINGS
    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == "port,change,detail"


def test_baseline_diff_missing_is_exit_2(capsys):
    code = main(["network", "baseline", "diff", "ghost", "localhost"])
    assert code == EXIT_ERROR


def test_baseline_show_and_delete(monkeypatch, capsys):
    _patch_scan(monkeypatch)
    main(["network", "baseline", "save", "lab", "localhost"])
    capsys.readouterr()
    code = main(["network", "baseline", "show", "lab", "--json"])
    assert code == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    assert data["data"]["name"] == "lab"
    code = main(["network", "baseline", "delete", "lab"])
    assert code == EXIT_OK
    assert "deleted" in capsys.readouterr().out


def test_baseline_bad_name_is_exit_2(capsys):
    code = main(["network", "baseline", "save", "../evil", "localhost"])
    assert code == EXIT_ERROR


def test_scan_registers_in_plugin_registry():
    # Importing the network package registers it (already imported via CLI).
    import aegisforge.network  # noqa: F401
    from aegisforge.core.plugins import get_registry

    info = get_registry().get("network")
    assert info.version == "0.2.0"
    assert "network scan" in info.commands
    assert "network baseline" in info.commands
