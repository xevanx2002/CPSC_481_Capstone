import copy
import json
from pathlib import Path

import pytest

from agent.planner import plan, is_goal
from core.actions import (
    Action,
    BRUTEFORCE_RDP,
    BRUTEFORCE_SSH,
    EXPLOIT_JENKINS,
    PIVOT_TO_HOST,
    USE_CREDS_SSH,
)


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def medium_scenario():
    return json.loads((ROOT / "scenarios" / "medium_network.json").read_text())


def test_medium_plan_compromises_both_hosts(medium_scenario):
    result = plan(medium_scenario)
    assert result is not None
    assert is_goal(result, medium_scenario)
    assert "web01" in result.compromised_hosts
    assert "file02" in result.compromised_hosts


def test_medium_plan_pivots_to_internal_host(medium_scenario):
    result = plan(medium_scenario)
    assert Action(PIVOT_TO_HOST, "file02") in result.actions_taken


def test_medium_plan_prefers_credential_reuse_over_jenkins(medium_scenario):
    """Reusing webadmin's SSH creds (cost 1) is cheaper than exploiting Jenkins (cost ~3)."""
    result = plan(medium_scenario)
    assert Action(USE_CREDS_SSH, "file02", 22) in result.actions_taken
    assert Action(EXPLOIT_JENKINS, "file02") not in result.actions_taken


def test_medium_plan_rejects_rdp_bruteforce(medium_scenario):
    result = plan(medium_scenario)
    assert Action(BRUTEFORCE_RDP, "file02", 3389) not in result.actions_taken


def test_medium_plan_rejects_ssh_bruteforce_when_creds_available(medium_scenario):
    result = plan(medium_scenario)
    assert Action(BRUTEFORCE_SSH, "file02", 22) not in result.actions_taken
    assert Action(BRUTEFORCE_SSH, "web01", 22) not in result.actions_taken


def test_medium_falls_back_to_jenkins_without_web_creds(medium_scenario):
    """If VM1 has no exploitable vuln, VM1 can't be compromised cheaply.
    The cheapest remaining path to file02 should still pivot via web01 bruteforce
    OR exploit Jenkins after pivoting. Either way, file02 must end up compromised."""
    scenario = copy.deepcopy(medium_scenario)
    scenario["hosts"][0]["vulnerabilities"] = []
    scenario["hosts"][0]["loot"] = []

    result = plan(scenario)
    assert result is not None
    assert "file02" in result.compromised_hosts


def test_medium_plan_unreached_host_requires_pivot(medium_scenario):
    """file02 starts unreachable. Without a pivot it must never get discovered."""
    scenario = copy.deepcopy(medium_scenario)
    scenario["hosts"][0]["reaches"] = []

    result = plan(scenario)
    assert result is None or "file02" not in result.compromised_hosts
