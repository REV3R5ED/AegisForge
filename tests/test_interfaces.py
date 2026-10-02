"""Tests for interface/route/neighbour discovery (mocked subprocess)."""

import json
import subprocess

from aegisforge.network.interfaces import list_interfaces, list_neighbours, list_routes

IP_ADDR_JSON = json.dumps(
    [
        {
            "ifname": "lo",
            "address": "00:00:00:00:00:00",
            "mtu": 65536,
            "operstate": "UNKNOWN",
            "addr_info": [
                {"family": "inet", "local": "127.0.0.1"},
                {"family": "inet6", "local": "::1"},
            ],
        },
        {
            "ifname": "eth0",
            "address": "02:42:ac:11:00:02",
            "mtu": 1500,
            "operstate": "UP",
            "addr_info": [{"family": "inet", "local": "172.17.0.2"}],
        },
    ]
)

IP_ROUTE_JSON = json.dumps(
    [
        {"dst": "default", "gateway": "172.17.0.1", "dev": "eth0"},
        {"dst": "172.17.0.0/16", "dev": "eth0", "metric": 100},
    ]
)

IP_NEIGH_JSON = json.dumps(
    [
        {
            "dst": "172.17.0.1",
            "lladdr": "02:42:ac:11:00:01",
            "dev": "eth0",
            "state": "REACHABLE",
        },
    ]
)


def _completed(stdout: str) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=["ip"], returncode=0, stdout=stdout, stderr=""
    )


def _fake_run_factory(mapping: dict[str, str]):
    def _fake(argv, **kwargs):
        key = " ".join(argv)
        if key in mapping:
            return _completed(mapping[key])
        return subprocess.CompletedProcess(
            args=argv, returncode=1, stdout="", stderr=""
        )

    return _fake


def test_list_interfaces_ip_json(monkeypatch):
    monkeypatch.setattr(
        "aegisforge.network.interfaces.subprocess.run",
        _fake_run_factory({"ip -j addr": IP_ADDR_JSON}),
    )
    result = list_interfaces()
    assert result["method"] == "ip addr"
    assert result["notes"] == []
    names = [i["name"] for i in result["interfaces"]]
    assert names == ["lo", "eth0"]
    eth0 = result["interfaces"][1]
    assert eth0["ipv4"] == ["172.17.0.2"]
    assert eth0["mac"] == "02:42:ac:11:00:02"
    assert eth0["status"] == "up"


def test_list_interfaces_falls_back_to_ifconfig(monkeypatch):
    def _fake(argv, **kwargs):
        raise FileNotFoundError("no ip")

    monkeypatch.setattr("aegisforge.network.interfaces.subprocess.run", _fake)
    result = list_interfaces()
    # ifconfig also missing in this sandbox -> graceful empty result
    assert result["interfaces"] == []
    assert result["notes"]


def test_list_routes(monkeypatch):
    monkeypatch.setattr(
        "aegisforge.network.interfaces.subprocess.run",
        _fake_run_factory({"ip -j route": IP_ROUTE_JSON}),
    )
    result = list_routes()
    assert len(result["routes"]) == 2
    assert result["routes"][0]["gateway"] == "172.17.0.1"


def test_list_neighbours(monkeypatch):
    monkeypatch.setattr(
        "aegisforge.network.interfaces.subprocess.run",
        _fake_run_factory({"ip -j neigh": IP_NEIGH_JSON}),
    )
    result = list_neighbours()
    assert result["neighbours"][0]["mac"] == "02:42:ac:11:00:01"


def test_list_neighbours_graceful_without_ip(monkeypatch):
    def _fake(argv, **kwargs):
        raise FileNotFoundError("no ip")

    monkeypatch.setattr("aegisforge.network.interfaces.subprocess.run", _fake)
    result = list_neighbours()
    assert result["neighbours"] == []
    assert result["notes"]
