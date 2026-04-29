import copy

from agent.planner import plan, is_goal
from core.actions import (
    Action,
    BRUTEFORCE_SSH,
    DISCOVER_HOST,
    ENUM_HTTP,
    EXPLOIT_UPLOAD,
    IDENTIFY_VULNERABILITY,
    READ_SENSITIVE_FILE,
    SCAN_HOST,
    USE_CREDS_SSH,
)


def test_plan_finds_optimal_web_path(simple_scenario):
    result = plan(simple_scenario)
    assert result is not None
    assert is_goal(result, simple_scenario)
    assert result.total_cost == 11
    assert result.actions_taken == [
        Action(DISCOVER_HOST, "web01"),
        Action(SCAN_HOST, "web01"),
        Action(ENUM_HTTP, "web01", 80),
        Action(IDENTIFY_VULNERABILITY, "web01"),
        Action(EXPLOIT_UPLOAD, "web01"),
        Action(READ_SENSITIVE_FILE, "web01"),
        Action(USE_CREDS_SSH, "web01", 22),
    ]


def test_plan_falls_back_to_bruteforce_without_web_vuln(simple_scenario):
    scenario = copy.deepcopy(simple_scenario)
    scenario["hosts"][0]["vulnerabilities"] = []

    result = plan(scenario)
    assert result is not None
    assert "web01" in result.compromised_hosts
    assert Action(BRUTEFORCE_SSH, "web01", 22) in result.actions_taken


def test_plan_prefers_cheaper_web_path_over_bruteforce(simple_scenario):
    result = plan(simple_scenario)
    assert Action(BRUTEFORCE_SSH, "web01", 22) not in result.actions_taken
