"""Tests for the core models and infrastructure."""

import json
import logging

import pytest

from aegisforge.core.config import ConfigError, example_config, load_config
from aegisforge.core.events import Event
from aegisforge.core.evidence import Evidence
from aegisforge.core.findings import Finding
from aegisforge.core.logging import audit_log, configure_logging, get_logger
from aegisforge.core.plugins import ModuleInfo, ModuleRegistry, get_registry
from aegisforge.core.results import Result, exit_code_for


def test_event_defaults_and_validation():
    event = Event(event_type="network.ping.completed", source="aegisforge")
    assert event.event_id
    assert event.timestamp.endswith("Z")
    assert event.severity == "info"
    d = event.to_dict()
    assert d["event_type"] == "network.ping.completed"
    with pytest.raises(ValueError):
        Event(event_type="x", source="y", severity="bogus")
    with pytest.raises(ValueError):
        Event(event_type="", source="y")


def test_finding_validation():
    finding = Finding(title="host unreachable", severity="low", confidence=90)
    assert finding.to_dict()["confidence"] == 90
    with pytest.raises(ValueError):
        Finding(title="x", confidence=101)
    with pytest.raises(ValueError):
        Finding(title="")


def test_evidence_custody_and_hashing():
    evidence = Evidence(
        kind="network-scan", source="aegisforge", description="ping sweep"
    )
    assert evidence.sha256 is None
    evidence.add_custody("analyst", "collected")
    assert len(evidence.custody) == 1
    assert Evidence.hash_text("abc") == Evidence.hash_bytes(b"abc")
    assert len(Evidence.hash_text("abc")) == 64
    with pytest.raises(ValueError):
        Evidence(kind="", source="x")


def test_config_defaults_and_file(tmp_path, monkeypatch):
    monkeypatch.delenv("AEGISFORGE_CONFIG", raising=False)
    cfg = load_config(path=tmp_path / "does-not-exist.json")
    assert cfg["ping_count"] == 3
    assert cfg.source == "defaults"

    path = tmp_path / "config.json"
    path.write_text(
        json.dumps({"profiles": {"quick": {"ping_count": 1}}}), encoding="utf-8"
    )
    cfg = load_config(path=path, profile="quick")
    assert cfg["ping_count"] == 1
    assert cfg.profile == "quick"


def test_config_top_level_object_is_default_profile(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"ping_count": 7}), encoding="utf-8")
    cfg = load_config(path=path)
    assert cfg["ping_count"] == 7


def test_config_rejects_unknown_settings_and_profiles(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps({"profiles": {"default": {"nope": 1}}}), encoding="utf-8"
    )
    with pytest.raises(ConfigError, match="unknown setting"):
        load_config(path=path)
    with pytest.raises(ConfigError, match="not defined"):
        load_config(path=path, profile="missing")


def test_config_rejects_bad_json(tmp_path):
    path = tmp_path / "config.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ConfigError, match="cannot read"):
        load_config(path=path)


def test_config_overrides_win(tmp_path):
    cfg = load_config(overrides={"ping_count": 9})
    assert cfg["ping_count"] == 9
    with pytest.raises(ConfigError):
        load_config(overrides={"bogus": 1})


def test_example_config_parses():
    data = json.loads(example_config())
    assert "profiles" in data and "default" in data["profiles"]


def test_result_envelope_and_exit_codes():
    result = Result(command="network ping", target="example.com")
    assert exit_code_for(result) == 0
    result.add_finding(Finding(title="loss", severity="low"))
    assert result.status == "warning"
    assert exit_code_for(result) == 1
    result.fail("boom")
    assert exit_code_for(result) == 2
    d = result.to_dict()
    assert d["tool"] == "aegisforge"
    assert d["version"]


def test_result_high_finding_escalates_status():
    result = Result(command="x")
    result.status = "error"
    result.add_finding(Finding(title="crit", severity="critical"))
    assert result.status == "error"  # error is sticky


def test_plugin_registry():
    registry = ModuleRegistry()
    registry.register(ModuleInfo(name="network", description="net"))
    assert registry.names() == ["network"]
    assert registry.get("network").description == "net"
    with pytest.raises(ValueError):
        registry.register(ModuleInfo(name="network", description="dup"))
    with pytest.raises(KeyError):
        registry.get("nope")


def test_network_module_is_registered():
    import aegisforge.network  # noqa: F401  (registration side effect)

    assert "network" in get_registry().names()


def test_logging_and_audit(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGISFORGE_AUDIT_LOG", str(tmp_path / "audit.log"))
    configure_logging(verbose=False)
    assert isinstance(get_logger(), logging.Logger)
    audit_log({"command": "test", "exit_code": 0})
    lines = (tmp_path / "audit.log").read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["command"] == "test"
    assert record["timestamp"].endswith("Z")


def test_audit_log_never_raises(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGISFORGE_AUDIT_LOG", "/nonexistent-dir-xyz/audit.log")
    # Should not raise even though the directory cannot be created... actually it
    # can attempt mkdir; use a file path that is a directory to force failure.
    monkeypatch.setenv("AEGISFORGE_AUDIT_LOG", str(tmp_path))
    audit_log({"command": "test"})  # path is a directory -> OSError swallowed
