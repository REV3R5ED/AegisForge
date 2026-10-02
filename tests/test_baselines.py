"""Tests for scan baselines (state dir is isolated per test)."""

import json

import pytest

from aegisforge.network import baselines as baselines_mod
from aegisforge.network.baselines import (
    BaselineError,
    delete_baseline,
    diff_baseline,
    list_baselines,
    load_baseline,
    save_baseline,
)
from aegisforge.network.scanner import PortResult, ScanResult
from aegisforge.network.validation import ValidationError


@pytest.fixture()
def state_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGISFORGE_STATE_DIR", str(tmp_path))
    return tmp_path


def _scan(target="localhost", ports=()):
    return ScanResult(
        target=target,
        resolved_ip="127.0.0.1",
        ports=list(ports),
        duration_ms=12.5,
    )


def _port(port, state, service=None, banner=None):
    return PortResult(port=port, state=state, service=service, banner=banner)


def test_save_load_roundtrip(state_dir):
    scan = _scan(ports=[_port(22, "open", "ssh", "SSH-2.0-x"), _port(80, "closed")])
    path = save_baseline("web-01", scan)
    assert path.exists()
    payload = load_baseline("web-01")
    assert payload["name"] == "web-01"
    assert payload["target"] == "localhost"
    assert payload["schema_version"] == 1
    by_port = {p["port"]: p for p in payload["ports"]}
    assert by_port[22]["service"] == "ssh"
    assert by_port[80]["state"] == "closed"


def test_save_overwrites(state_dir):
    save_baseline("dup", _scan(ports=[_port(22, "open")]))
    save_baseline("dup", _scan(ports=[_port(80, "open")]))
    payload = load_baseline("dup")
    assert {p["port"] for p in payload["ports"]} == {80}


def test_load_missing_raises(state_dir):
    with pytest.raises(BaselineError, match="no baseline"):
        load_baseline("ghost")


def test_load_corrupt_raises(state_dir):
    directory = baselines_mod.baseline_dir()
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "bad.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(BaselineError, match="corrupt"):
        load_baseline("bad")


def test_save_rejects_bad_name(state_dir):
    with pytest.raises(ValidationError):
        save_baseline("../evil", _scan())


def test_list_baselines(state_dir):
    assert list_baselines() == []
    save_baseline("a", _scan(ports=[_port(22, "open"), _port(80, "closed")]))
    save_baseline("b", _scan(ports=[_port(443, "open")]))
    entries = list_baselines()
    assert [e["name"] for e in entries] == ["a", "b"]
    assert entries[0]["ports_open"] == 1
    assert entries[0]["ports_scanned"] == 2


def test_list_skips_corrupt_files(state_dir):
    directory = baselines_mod.baseline_dir()
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "bad.json").write_text("nope", encoding="utf-8")
    save_baseline("good", _scan())
    assert [e["name"] for e in list_baselines()] == ["good"]


def test_delete_baseline(state_dir):
    save_baseline("temp", _scan())
    assert delete_baseline("temp") is True
    assert delete_baseline("temp") is False


def test_diff_new_closed_changed(state_dir):
    old = _scan(
        ports=[
            _port(22, "open", "ssh", "SSH-2.0-a"),
            _port(23, "open", "telnet"),
            _port(25, "closed"),
        ]
    )
    save_baseline("base", old)
    new = _scan(
        ports=[
            _port(22, "open", "ssh", "SSH-2.0-b"),  # banner changed
            _port(23, "closed"),  # closed
            _port(25, "closed"),
            _port(8080, "open", "http"),  # new
        ]
    )
    diff = diff_baseline(load_baseline("base"), new)
    by_port = {e.port: e for e in diff.entries}
    assert by_port[8080].change == "new"
    assert "now open" in by_port[8080].detail
    assert by_port[23].change == "closed"
    assert by_port[22].change == "changed"
    assert "banner changed" in by_port[22].detail
    assert "new" in diff.summary and "closed" in diff.summary


def test_diff_no_changes(state_dir):
    ports = [_port(22, "open", "ssh", "SSH-2.0-a")]
    save_baseline("same", _scan(ports=ports))
    diff = diff_baseline(load_baseline("same"), _scan(ports=ports))
    assert diff.entries == []
    assert diff.summary == "no changes since baseline"


def test_diff_service_change_detected(state_dir):
    save_baseline("svc", _scan(ports=[_port(80, "open", "http")]))
    new = _scan(ports=[_port(80, "open", "https")])
    diff = diff_baseline(load_baseline("svc"), new)
    assert len(diff.entries) == 1
    assert diff.entries[0].change == "changed"
    assert "service: http -> https" in diff.entries[0].detail


def test_diff_serializes():
    diff = diff_baseline(
        {"name": "n", "created": "t", "ports": []},
        _scan(ports=[_port(22, "open")]),
    )
    d = diff.to_dict()
    assert d["name"] == "n"
    assert d["entries"][0]["change"] == "new"
    assert json.dumps(d)  # JSON-serializable
