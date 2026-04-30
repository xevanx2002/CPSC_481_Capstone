from core.actions import Action, DISCOVER_HOST
from core.state import State
from executors import HybridExecutor, MockExecutor, RealExecutor
from executors.base import ExecutionResult
from executors.real import parse_nmap_services

SAMPLE_NMAP_SV = """\
Starting Nmap 7.94 ( https://nmap.org ) at 2026-04-29 16:00 PDT
Nmap scan report for target.htb (10.10.10.75)
Host is up (0.045s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
"""


def test_parse_nmap_services_extracts_port_and_name():
    ports, services = parse_nmap_services(SAMPLE_NMAP_SV)
    assert ports == [22, 80]
    assert services == {22: "ssh", 80: "http"}


def test_parse_nmap_services_empty_output():
    assert parse_nmap_services("") == ([], {})


def test_hybrid_falls_through_on_not_implemented():
    primary = RealExecutor()
    fallback = MockExecutor()
    hybrid = HybridExecutor(primary, fallback)

    scenario = {"hosts": [{"id": "h1", "ip": "1.2.3.4", "exposure": "external"}]}
    # enumerate_http isn't implemented in RealExecutor yet → should fall to mock,
    # which fails because the host has no http service. Either way we should
    # see the fallback's error, not "not_implemented".
    result = hybrid.execute(Action("enumerate_http", "h1", 80), State(), scenario)
    assert result.error != "not_implemented"


def test_hybrid_does_not_fall_through_on_other_failures():
    class AlwaysFails:
        def execute(self, action, state, scenario):
            return ExecutionResult(action, False, error="real_failure")

    class ShouldNotBeCalled:
        def execute(self, action, state, scenario):
            raise AssertionError("fallback called when it shouldn't be")

    hybrid = HybridExecutor(AlwaysFails(), ShouldNotBeCalled())
    result = hybrid.execute(Action(DISCOVER_HOST, "h1"), State(), {})
    assert result.error == "real_failure"
