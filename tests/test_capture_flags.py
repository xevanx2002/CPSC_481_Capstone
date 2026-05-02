from core.actions import Action, CAPTURE_FLAGS
from core.state import State
from agent.transition import apply_action
from agent.action_generator import legal_actions
from executors.mock import MockExecutor
from executors.runner import _merge_observed


def _scenario_with_loot_vuln():
    return {
        "hosts": [
            {
                "id": "host01",
                "ip": "10.0.0.1",
                "exposure": "external",
                "services": [{"port": 80, "name": "http", "paths": ["/admin"]}],
                "vulnerabilities": [
                    {
                        "id": "VF-TEST-LOOT",
                        "severity": "high",
                        "cost": 3,
                        "requires": [],
                        "gives": ["web_shell"],
                        "loot_files": ["/home/user/user.txt", "/root/root.txt"],
                    }
                ],
            }
        ]
    }


def test_capture_requires_shell_access():
    scenario = _scenario_with_loot_vuln()
    state = State(
        reachable_hosts={"host01"},
        discovered_hosts={"host01"},
        scanned_hosts={"host01"},
        discovered_vulns={"host01": {"VF-TEST-LOOT"}},
        access_levels={"host01": "none"},
    )
    result = apply_action(state, Action(CAPTURE_FLAGS, "host01"), scenario)
    assert result is None


def test_capture_records_loot_paths():
    scenario = _scenario_with_loot_vuln()
    state = State(
        reachable_hosts={"host01"},
        discovered_hosts={"host01"},
        scanned_hosts={"host01"},
        discovered_vulns={"host01": {"VF-TEST-LOOT"}},
        access_levels={"host01": "web_shell"},
        footholds={"host01"},
    )
    result = apply_action(state, Action(CAPTURE_FLAGS, "host01"), scenario)
    assert result is not None
    assert "host01" in result.loot
    assert "/home/user/user.txt" in result.loot["host01"]
    assert "/root/root.txt" in result.loot["host01"]


def test_capture_skipped_when_already_collected():
    scenario = _scenario_with_loot_vuln()
    state = State(
        reachable_hosts={"host01"},
        discovered_hosts={"host01"},
        scanned_hosts={"host01"},
        discovered_vulns={"host01": {"VF-TEST-LOOT"}},
        access_levels={"host01": "web_shell"},
        loot={
            "host01": {
                "/home/user/user.txt": "abc",
                "/root/root.txt": "def",
            }
        },
    )
    result = apply_action(state, Action(CAPTURE_FLAGS, "host01"), scenario)
    assert result is None


def test_action_generator_emits_capture_when_shell_and_loot():
    scenario = _scenario_with_loot_vuln()
    state = State(
        reachable_hosts={"host01"},
        discovered_hosts={"host01"},
        scanned_hosts={"host01"},
        discovered_services={"host01": {80: "http"}},
        discovered_paths={"host01": {"/admin"}},
        discovered_vulns={"host01": {"VF-TEST-LOOT"}},
        access_levels={"host01": "web_shell"},
    )
    actions = legal_actions(state, scenario)
    capture = [a for a in actions if a.name == CAPTURE_FLAGS]
    assert len(capture) == 1
    assert capture[0].target_host == "host01"


def test_action_generator_skips_capture_without_shell():
    scenario = _scenario_with_loot_vuln()
    state = State(
        reachable_hosts={"host01"},
        discovered_hosts={"host01"},
        scanned_hosts={"host01"},
        discovered_services={"host01": {80: "http"}},
        discovered_paths={"host01": {"/admin"}},
        discovered_vulns={"host01": {"VF-TEST-LOOT"}},
        access_levels={"host01": "none"},
    )
    actions = legal_actions(state, scenario)
    assert not any(a.name == CAPTURE_FLAGS for a in actions)


def test_mock_executor_returns_loot_captured():
    scenario = _scenario_with_loot_vuln()
    state = State(
        access_levels={"host01": "web_shell"},
        discovered_vulns={"host01": {"VF-TEST-LOOT"}},
    )
    result = MockExecutor().execute(Action(CAPTURE_FLAGS, "host01"), state, scenario)
    assert result.success
    captured = result.observed["loot_captured"]
    assert "/home/user/user.txt" in captured
    assert "/root/root.txt" in captured
    assert captured["/home/user/user.txt"].startswith("<mock-loot:")


def test_mock_executor_fails_without_shell():
    scenario = _scenario_with_loot_vuln()
    state = State(
        access_levels={"host01": "none"},
        discovered_vulns={"host01": {"VF-TEST-LOOT"}},
    )
    result = MockExecutor().execute(Action(CAPTURE_FLAGS, "host01"), state, scenario)
    assert not result.success
    assert result.error == "no_shell_for_capture"


def test_merge_observed_writes_loot():
    state = State()
    action = Action(CAPTURE_FLAGS, "host01")
    fake = type(
        "R",
        (),
        {
            "observed": {"loot_captured": {"/root/root.txt": "abc123"}},
        },
    )()
    _merge_observed(state, action, fake)
    assert state.loot["host01"]["/root/root.txt"] == "abc123"
