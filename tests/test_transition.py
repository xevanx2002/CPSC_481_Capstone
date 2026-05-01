from core.actions import (
    Action,
    DISCOVER_HOST,
    SCAN_HOST,
    ENUM_HTTP,
    IDENTIFY_VULN,
    EXPLOIT_UPLOAD,
    EXPLOIT_PRIVESC,
    READ_SENSITIVE_FILE,
    USE_CREDS_SSH,
    BRUTEFORCE_SSH,
)
from core.state import State
from agent.transition import apply_action


def test_discover_host_adds_to_state(simple_scenario):
    s = apply_action(
        State(reachable_hosts={"web01"}),
        Action(DISCOVER_HOST, "web01"),
        simple_scenario,
    )
    assert "web01" in s.discovered_hosts
    assert s.total_cost == 1


def test_discover_requires_reachability(simple_scenario):
    assert (
        apply_action(State(), Action(DISCOVER_HOST, "web01"), simple_scenario) is None
    )


def test_scan_requires_discovery(simple_scenario):
    assert (
        apply_action(
            State(reachable_hosts={"web01"}),
            Action(SCAN_HOST, "web01"),
            simple_scenario,
        )
        is None
    )


def test_enum_http_requires_scan(simple_scenario):
    s = apply_action(
        State(reachable_hosts={"web01"}),
        Action(DISCOVER_HOST, "web01"),
        simple_scenario,
    )
    assert apply_action(s, Action(ENUM_HTTP, "web01"), simple_scenario) is None


def test_exploit_requires_identified_vuln(simple_scenario):
    s = State(reachable_hosts={"web01"})
    for action in [
        Action(DISCOVER_HOST, "web01"),
        Action(SCAN_HOST, "web01"),
        Action(ENUM_HTTP, "web01"),
    ]:
        s = apply_action(s, action, simple_scenario)
    assert apply_action(s, Action(EXPLOIT_UPLOAD, "web01"), simple_scenario) is None


def test_use_creds_requires_credentials(simple_scenario):
    s = State(reachable_hosts={"web01"})
    s.discovered_hosts.add("web01")
    s.scanned_hosts.add("web01")
    s.discovered_services["web01"] = {22: "ssh", 80: "http"}
    assert apply_action(s, Action(USE_CREDS_SSH, "web01"), simple_scenario) is None


def test_exploit_upload_records_foothold(simple_scenario):
    s = State(reachable_hosts={"web01"})
    sequence = [
        Action(DISCOVER_HOST, "web01"),
        Action(SCAN_HOST, "web01"),
        Action(ENUM_HTTP, "web01"),
        Action(IDENTIFY_VULN, "web01"),
        Action(EXPLOIT_UPLOAD, "web01"),
    ]
    for action in sequence:
        s = apply_action(s, action, simple_scenario)
        assert s is not None, f"action {action} returned None"

    assert "web01" in s.footholds
    # foothold alone shouldn't count as full compromise yet
    assert "web01" not in s.compromised_hosts
    assert s.get_access_level("web01") == "web_shell"


def test_privesc_promotes_web_shell_to_root(simple_scenario):
    s = State(reachable_hosts={"web01"})
    sequence = [
        Action(DISCOVER_HOST, "web01"),
        Action(SCAN_HOST, "web01"),
        Action(ENUM_HTTP, "web01"),
        Action(IDENTIFY_VULN, "web01"),
        Action(EXPLOIT_UPLOAD, "web01"),
        Action(IDENTIFY_VULN, "web01"),
        Action(EXPLOIT_PRIVESC, "web01"),
    ]
    for action in sequence:
        s = apply_action(s, action, simple_scenario)
        assert s is not None, f"action {action} returned None"

    assert s.get_access_level("web01") == "root"
    assert "web01" in s.compromised_hosts


def test_privesc_requires_web_shell(simple_scenario):
    s = State(reachable_hosts={"web01"})
    s.discovered_hosts.add("web01")
    s.scanned_hosts.add("web01")
    s.discovered_vulns["web01"] = {"VF-PRIVESC-001"}
    assert apply_action(s, Action(EXPLOIT_PRIVESC, "web01"), simple_scenario) is None


def test_full_web_path_compromises_host(simple_scenario):
    s = State(reachable_hosts={"web01"})
    sequence = [
        Action(DISCOVER_HOST, "web01"),
        Action(SCAN_HOST, "web01"),
        Action(ENUM_HTTP, "web01"),
        Action(IDENTIFY_VULN, "web01"),
        Action(EXPLOIT_UPLOAD, "web01"),
        Action(READ_SENSITIVE_FILE, "web01"),
        Action(USE_CREDS_SSH, "web01"),
    ]
    for action in sequence:
        s = apply_action(s, action, simple_scenario)
        assert s is not None, f"action {action} returned None"

    assert "web01" in s.compromised_hosts
    assert s.get_access_level("web01") == "ssh_user"
    assert any(c.username == "webadmin" for c in s.creds_found)
    assert s.total_cost == 11


def test_bruteforce_compromises_without_creds(simple_scenario):
    s = State(reachable_hosts={"web01"})
    s = apply_action(s, Action(DISCOVER_HOST, "web01"), simple_scenario)
    s = apply_action(s, Action(SCAN_HOST, "web01"), simple_scenario)
    s = apply_action(s, Action(BRUTEFORCE_SSH, "web01"), simple_scenario)
    assert "web01" in s.compromised_hosts
    assert s.total_cost == 1 + 1 + 15