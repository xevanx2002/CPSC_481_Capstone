import copy

from agent.planner import plan


def test_low_severity_vuln_increases_exploit_cost(simple_scenario):
    scenario = copy.deepcopy(simple_scenario)
    scenario["hosts"][0]["vulnerabilities"][0]["severity"] = "low"

    result = plan(scenario)
    assert result is not None
    assert result.total_cost > 11


def test_critical_severity_vuln_decreases_exploit_cost(simple_scenario):
    scenario = copy.deepcopy(simple_scenario)
    scenario["hosts"][0]["vulnerabilities"][0]["severity"] = "critical"

    result = plan(scenario)
    assert result is not None
    assert result.total_cost <= 11
