"""Tests for input validation."""

import pytest

from aegisforge.network.validation import (
    ValidationError,
    validate_cidr,
    validate_port,
    validate_positive_int,
    validate_target,
    validate_targets,
    validate_timeout,
)


def test_validate_target_ok():
    assert validate_target("  example.com ") == "example.com"
    assert validate_target("192.168.1.1") == "192.168.1.1"
    assert validate_target("2001:db8::1") == "2001:db8::1"


def test_validate_target_rejects_bad_input():
    for bad in ["", "   ", "a;b", "a|b", "a$b", "a`b", "a b", "a\nb", "a/b"]:
        with pytest.raises(ValidationError):
            validate_target(bad)


def test_validate_target_rejects_cidr_by_default():
    with pytest.raises(ValidationError):
        validate_target("10.0.0.0/8")


def test_validate_targets_dedupes_and_caps():
    assert validate_targets(["a.com", "a.com", "b.com"], max_targets=10) == [
        "a.com",
        "b.com",
    ]
    with pytest.raises(ValidationError, match="too many"):
        validate_targets([f"h{i}.example" for i in range(11)], max_targets=10)
    with pytest.raises(ValidationError):
        validate_targets([], max_targets=10)


def test_validate_cidr():
    net = validate_cidr("10.0.0.0/8")
    assert net.prefixlen == 8
    with pytest.raises(ValidationError):
        validate_cidr("999.1.1.1/24")


def test_validate_port():
    assert validate_port(443) == 443
    with pytest.raises(ValidationError):
        validate_port(0)
    with pytest.raises(ValidationError):
        validate_port(70000)


def test_validate_positive_int():
    assert validate_positive_int("n", 5, maximum=10) == 5
    with pytest.raises(ValidationError):
        validate_positive_int("n", 0)
    with pytest.raises(ValidationError):
        validate_positive_int("n", 11, maximum=10)
    with pytest.raises(ValidationError):
        validate_positive_int("n", True)


def test_validate_timeout():
    assert validate_timeout(2.5) == 2.5
    with pytest.raises(ValidationError):
        validate_timeout(0.01)
    with pytest.raises(ValidationError):
        validate_timeout(500)


def test_is_public_ip():
    from aegisforge.network.validation import is_public_ip

    assert is_public_ip("8.8.8.8") is True
    assert is_public_ip("1.1.1.1") is True
    assert is_public_ip("2001:4860:4860::8888") is True
    for local in [
        "192.168.1.1",
        "10.0.0.5",
        "172.16.0.1",
        "127.0.0.1",
        "169.254.10.20",
        "224.0.0.1",
        "0.0.0.0",
        "::1",
        "fe80::1",
        "fc00::1",
        "192.0.2.1",
    ]:
        assert is_public_ip(local) is False, local
    with pytest.raises(ValidationError):
        is_public_ip("not-an-ip")


def test_parse_port_spec():
    from aegisforge.network.validation import parse_port_spec

    assert parse_port_spec("22,80,443", None, max_ports=1024, default=[80]) == [
        22,
        80,
        443,
    ]
    assert parse_port_spec(None, "1-3", max_ports=1024, default=[80]) == [1, 2, 3]
    assert parse_port_spec("22", "80-81", max_ports=1024, default=[]) == [22, 80, 81]
    assert parse_port_spec("22,22", None, max_ports=1024, default=[]) == [22]
    assert parse_port_spec(None, None, max_ports=1024, default=[80]) == [80]
    assert parse_port_spec(None, "8080-8080", max_ports=1024, default=[]) == [8080]
    for bad_ports, bad_range in [
        ("22,abc", None),
        ("0", None),
        ("70000", None),
        ("22,,80", None),
        (None, "100-1"),
        (None, "1-"),
        (None, "abc"),
        (None, "1-70000"),
    ]:
        with pytest.raises(ValidationError):
            parse_port_spec(bad_ports, bad_range, max_ports=1024, default=[])
    with pytest.raises(ValidationError, match="too large"):
        parse_port_spec(None, "1-2000", max_ports=1024, default=[])


def test_validate_baseline_name():
    from aegisforge.network.validation import validate_baseline_name

    assert validate_baseline_name("web-01_prod") == "web-01_prod"
    for bad in ["", "../evil", "a/b", "has space", "x" * 65, "-"]:
        with pytest.raises(ValidationError):
            validate_baseline_name(bad)
