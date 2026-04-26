import copy

from agent.planner import plan, is_goal


def test_plan_finds_optimal_web_path(simple_scenario):
    result = plan(simple_scenario)
    assert result is not None
    assert is_goal(result, simple_scenario)
    assert result.total_cost == 11
    assert result.actions_taken == [
        "discover_host(web01)",
        "scan_host(web01)",
        "enumerate_http(web01:80)",
        "identify_vulnerability(web01)",
        "exploit_upload(web01)",
        "read_sensitive_file(web01)",
        "use_credentials_ssh(web01:22)",
    ]


def test_plan_falls_back_to_bruteforce_without_web_vuln(simple_scenario):
    scenario = copy.deepcopy(simple_scenario)
    scenario["hosts"][0]["vulnerabilities"] = []

    result = plan(scenario)
    assert result is not None
    assert "web01" in result.compromised_hosts
    assert "bruteforce_ssh(web01:22)" in result.actions_taken


def test_plan_prefers_cheaper_web_path_over_bruteforce(simple_scenario):
    result = plan(simple_scenario)
    assert "bruteforce_ssh(web01:22)" not in result.actions_taken
