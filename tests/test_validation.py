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
