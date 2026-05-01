SEVERITY_POINTS = {"low": 10, "medium": 25, "high": 50, "critical": 80}


def score_vuln(vuln: dict, host: dict, discovery_cost: int) -> int:
    severity_score = SEVERITY_POINTS.get(vuln.get("severity", "medium"), 25)
    host_value = host.get("value", 0)
    exposure_bonus = 20 if host.get("role") == "public_web_server" else 5

    return max(0, severity_score + host_value + exposure_bonus - discovery_cost)


def score_result(result, scenario: dict) -> int:
    if result is None:
        return 0

    total = 0

    for host in scenario.get("hosts", []):
        host_id = host["id"]
        discovered = result.discovered_vulns.get(host_id, set())

        for vuln in host.get("vulnerabilities", []):
            if vuln["id"] in discovered:
                total += score_vuln(vuln, host, result.total_cost)

    compromised_bonus = 25 * len(result.compromised_hosts)
    # web_shell footholds without ssh/rdp escalation still represent
    # verified RCE: give partial credit so the report reflects the win
    foothold_bonus = 10 * len(
        getattr(result, "footholds", set()) - result.compromised_hosts
    )

    return total + compromised_bonus + foothold_bonus
