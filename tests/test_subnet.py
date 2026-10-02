"""Tests for subnet calculator and CIDR expansion."""

import pytest

from aegisforge.network.subnet import describe_subnet, expand_cidr
from aegisforge.network.validation import ValidationError


def test_describe_ipv4_subnet():
    info = describe_subnet("192.168.1.0/24")
    assert info["network_address"] == "192.168.1.0"
    assert info["broadcast_address"] == "192.168.1.255"
    assert info["netmask"] == "255.255.255.0"
    assert info["prefixlen"] == 24
    assert info["num_addresses"] == 256
    assert info["num_usable_hosts"] == 254
    assert info["first_usable"] == "192.168.1.1"
    assert info["last_usable"] == "192.168.1.254"
    assert info["is_private"] is True
    assert info["version"] == 4


def test_describe_ipv6_subnet():
    info = describe_subnet("2001:db8::/32")
    assert info["version"] == 6
    assert info["prefixlen"] == 32
    assert info["num_addresses"] == 2**96


def test_describe_slash31_and_32():
    info = describe_subnet("10.0.0.0/31")
    assert info["num_usable_hosts"] == 2
    info32 = describe_subnet("10.0.0.5/32")
    assert info32["num_usable_hosts"] == 1
    assert info32["first_usable"] == "10.0.0.5"


def test_expand_small_block():
    hosts = expand_cidr("192.168.1.0/30")
    assert hosts == ["192.168.1.1", "192.168.1.2"]


def test_expand_refuses_oversized_block():
    with pytest.raises(ValidationError, match="more than the limit"):
        expand_cidr("10.0.0.0/8", max_hosts=1024)


def test_expand_hard_cap():
    with pytest.raises(ValidationError, match="must be <="):
        expand_cidr("10.0.0.0/30", max_hosts=10**9)


def test_invalid_cidr():
    with pytest.raises(ValidationError):
        describe_subnet("not-a-cidr")
    with pytest.raises(ValidationError):
        describe_subnet("192.168.1.0/33")
    with pytest.raises(ValidationError):
        describe_subnet("")


def test_cidr_with_unsafe_characters_rejected():
    with pytest.raises(ValidationError):
        describe_subnet("10.0.0.0/24; rm -rf /")
