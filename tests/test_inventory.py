"""Tests for local asset inventory (mocked)."""

from aegisforge.network import inventory as inventory_mod


def test_local_inventory_composes_primitives(monkeypatch):
    monkeypatch.setattr(
        inventory_mod,
        "list_interfaces",
        lambda: {
            "interfaces": [{"name": "eth0", "ipv4": ["10.0.0.5"]}],
            "method": "ip addr",
            "notes": [],
        },
    )
    monkeypatch.setattr(
        inventory_mod,
        "list_routes",
        lambda: {
            "routes": [
                {
                    "destination": "default",
                    "gateway": "10.0.0.1",
                    "interface": "eth0",
                    "metric": None,
                }
            ],
            "method": "ip route",
            "notes": [],
        },
    )
    monkeypatch.setattr(inventory_mod.platform, "system", lambda: "Linux")
    data = inventory_mod.local_inventory()
    assert data["default_gateways"] == ["10.0.0.1"]
    assert data["hostname"]
    assert data["platform"] == "Linux"
