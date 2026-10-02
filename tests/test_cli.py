"""Tests for the CLI: dispatch, rendering, exit codes (network mocked)."""

import json

import pytest

from aegisforge.cli.main import build_parser, main
from aegisforge.core.results import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK
from aegisforge.network.dns import DNSResult
from aegisforge.network.ping import PingResult
from aegisforge.network.trace import TraceHop, TraceResult


@pytest.fixture(autouse=True)
def _no_trial_check(monkeypatch):
    monkeypatch.setenv("AEGISFORGE_NO_TRIAL_CHECK", "1")
    monkeypatch.setenv("AEGISFORGE_STATE_DIR", "/tmp/aegisforge-test-state")


def _ok_ping(*a, **k):
    return [
        PingResult(
            target="example.com",
            reachable=True,
            transmitted=3,
            received=3,
            loss_percent=0.0,
            rtt_avg_ms=1.2,
        )
    ]


def test_subnet_human_output(capsys):
    code = main(["network", "subnet", "192.168.1.0/24"])
    assert code == EXIT_OK
    out = capsys.readouterr().out
    assert "192.168.1.0/24" in out
    assert "256 addresses" in out


def test_subnet_json_output(capsys):
    code = main(["network", "subnet", "10.0.0.0/8", "--json"])
    assert code == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    assert data["tool"] == "aegisforge"
    assert data["command"] == "network subnet"
    assert data["data"]["calculator"]["num_addresses"] == 2**24
    assert data["status"] == "ok"


def test_subnet_expand_csv(capsys):
    code = main(["network", "subnet", "192.168.1.0/30", "--expand", "--csv"])
    assert code == EXIT_OK
    out = capsys.readouterr().out
    assert out.splitlines()[0] == "host"
    assert "192.168.1.1" in out


def test_subnet_invalid_cidr_is_exit_2(capsys):
    code = main(["network", "subnet", "bogus"])
    assert code == EXIT_ERROR
    assert "error" in capsys.readouterr().err


def test_subnet_expand_too_big_is_exit_2(capsys):
    code = main(["network", "subnet", "10.0.0.0/8", "--expand"])
    assert code == EXIT_ERROR


def test_ping_all_reachable_exit_0(monkeypatch, capsys):
    monkeypatch.setattr("aegisforge.cli.main.ping_mod.ping_many", _ok_ping)
    code = main(["network", "ping", "example.com"])
    assert code == EXIT_OK
    assert "1/1 hosts reachable" in capsys.readouterr().out


def test_ping_unreachable_exit_1(monkeypatch, capsys):
    def _down(*a, **k):
        return [
            PingResult(
                target="down.example",
                reachable=False,
                transmitted=3,
                received=0,
                loss_percent=100.0,
                error="timeout",
            )
        ]

    monkeypatch.setattr("aegisforge.cli.main.ping_mod.ping_many", _down)
    code = main(["network", "ping", "down.example", "--json"])
    assert code == EXIT_FINDINGS
    data = json.loads(capsys.readouterr().out)
    assert data["status"] == "warning"
    assert data["findings"][0]["title"] == "host unreachable: down.example"


def test_ping_packet_loss_exit_1(monkeypatch, capsys):
    def _lossy(*a, **k):
        return [
            PingResult(
                target="h.example",
                reachable=True,
                transmitted=4,
                received=2,
                loss_percent=50.0,
                rtt_avg_ms=3.0,
            )
        ]

    monkeypatch.setattr("aegisforge.cli.main.ping_mod.ping_many", _lossy)
    assert main(["network", "ping", "h.example"]) == EXIT_FINDINGS


def test_ping_rejects_unsafe_target():
    assert main(["network", "ping", "a;b"]) == EXIT_ERROR


def test_dns_json(monkeypatch, capsys):
    monkeypatch.setattr(
        "aegisforge.cli.main.dns_mod.lookup",
        lambda t, timeout=5.0: DNSResult(
            query=t, addresses=[{"ip": "93.184.216.34", "family": "IPv4"}]
        ),
    )
    code = main(["network", "dns", "example.com", "--json"])
    assert code == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    assert data["data"]["addresses"][0]["ip"] == "93.184.216.34"


def test_dns_failure_exit_2(monkeypatch):
    from aegisforge.network.dns import DNSError

    def _fail(t, timeout=5.0):
        raise DNSError("cannot resolve 'nope.invalid'")

    monkeypatch.setattr("aegisforge.cli.main.dns_mod.lookup", _fail)
    assert main(["network", "dns", "nope.invalid"]) == EXIT_ERROR


def test_trace_reached_exit_0(monkeypatch, capsys):
    monkeypatch.setattr(
        "aegisforge.cli.main.trace_mod.traceroute",
        lambda t, max_hops=30, timeout=2.0: TraceResult(
            target=t,
            reached=True,
            hops=[
                TraceHop(hop=1, ip="192.168.1.1", rtt_ms=1.0),
                TraceHop(hop=2, ip=t, rtt_ms=2.0),
            ],
            max_hops=30,
        ),
    )
    assert main(["network", "trace", "example.com"]) == EXIT_OK


def test_trace_not_reached_exit_1(monkeypatch):
    monkeypatch.setattr(
        "aegisforge.cli.main.trace_mod.traceroute",
        lambda t, max_hops=30, timeout=2.0: TraceResult(
            target=t, reached=False, hops=[TraceHop(hop=1, ip=None)], max_hops=30
        ),
    )
    assert main(["network", "trace", "10.9.9.9"]) == EXIT_FINDINGS


def test_interfaces_human(monkeypatch, capsys):
    monkeypatch.setattr(
        "aegisforge.cli.main.interfaces_mod.list_interfaces",
        lambda: {
            "interfaces": [
                {
                    "name": "eth0",
                    "mac": "aa:bb:cc:dd:ee:ff",
                    "mtu": 1500,
                    "status": "up",
                    "ipv4": ["10.0.0.5"],
                    "ipv6": [],
                }
            ],
            "method": "ip addr",
            "notes": [],
        },
    )
    code = main(["network", "interfaces"])
    assert code == EXIT_OK
    assert "eth0" in capsys.readouterr().out


def test_inventory_json(monkeypatch, capsys):
    monkeypatch.setattr(
        "aegisforge.cli.main.inventory_mod.local_inventory",
        lambda: {
            "hostname": "lab",
            "fqdn": "lab.local",
            "platform": "Linux",
            "platform_release": "x",
            "python": "3.12",
            "interfaces": [],
            "default_gateways": ["10.0.0.1"],
            "dns_servers": [],
            "notes": [],
        },
    )
    code = main(["network", "inventory", "--json"])
    assert code == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    assert data["data"]["hostname"] == "lab"


def test_config_show(monkeypatch, capsys, tmp_path):
    cfg = tmp_path / "c.json"
    cfg.write_text(
        json.dumps({"profiles": {"default": {"ping_count": 5}}}), encoding="utf-8"
    )
    code = main(["--config", str(cfg), "config", "show", "--json"])
    assert code == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    assert data["data"]["ping_count"] == 5


def test_bad_config_is_exit_2(tmp_path):
    cfg = tmp_path / "c.json"
    cfg.write_text("{bad", encoding="utf-8")
    assert (
        main(["--config", str(cfg), "network", "subnet", "10.0.0.0/24"]) == EXIT_ERROR
    )


def test_audit_log_written(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGISFORGE_AUDIT_LOG", str(tmp_path / "audit.log"))
    main(["network", "subnet", "10.0.0.0/24"])
    content = (tmp_path / "audit.log").read_text(encoding="utf-8")
    assert "network subnet" in content


def test_trial_notice_printed_on_startup(monkeypatch, capsys, tmp_path):
    monkeypatch.delenv("AEGISFORGE_NO_TRIAL_CHECK", raising=False)
    monkeypatch.setenv("AEGISFORGE_STATE_DIR", str(tmp_path / "state"))
    main(["network", "subnet", "10.0.0.0/24"])
    err = capsys.readouterr().err
    assert "Trial:" in err


def test_parser_has_help_for_all_commands():
    parser = build_parser()
    # --help on each subcommand must not raise.
    for argv in (
        ["network", "subnet", "--help"],
        ["network", "ping", "--help"],
        ["network", "dns", "--help"],
        ["network", "trace", "--help"],
        ["network", "interfaces", "--help"],
        ["network", "inventory", "--help"],
        ["config", "show", "--help"],
    ):
        with pytest.raises(SystemExit) as exc:
            parser.parse_args(argv)
        assert exc.value.code == 0
