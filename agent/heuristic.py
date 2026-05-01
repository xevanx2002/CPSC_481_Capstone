from core.state import State

SUBGOAL_COSTS = {
    "reachable": 2,
    "discovered": 1,
    "scanned": 1,
    "http_enumerated": 2,
    "vuln_identified": 2,
    "web_shell": 3,
    "creds_found": 1,
    "compromised": 2,
}

"""
This is is the "what if" engine

This runs when the planner is exploring possible futures
It doesn't actually scan anything
It just simulates what would happen by reading the scenario JSONs 
pre declared services list and pretending the agent learned them.
"""

def heuristic(state: State, scenario: dict) -> int:
    remaining = 0

    for host in scenario.get("hosts", []):
        host_id = host["id"]

        if host_id in state.compromised_hosts:
            continue

        if host_id not in state.reachable_hosts:
            remaining += SUBGOAL_COSTS["reachable"]
        if host_id not in state.discovered_hosts:
            remaining += SUBGOAL_COSTS["discovered"]
        if host_id not in state.scanned_hosts:
            remaining += SUBGOAL_COSTS["scanned"]

        has_http = any(
            s["port"] == 80 and s["name"] == "http" for s in host.get("services", [])
        )
        has_ssh = any(
            s["port"] == 22 and s["name"] == "ssh" for s in host.get("services", [])
        )
        host_vuln_ids = {v["id"] for v in host.get("vulnerabilities", [])}
        known_vulns = state.discovered_vulns.get(host_id, set())

        if has_http and host_id not in state.discovered_paths:
            remaining += SUBGOAL_COSTS["http_enumerated"]

        if host_vuln_ids and not host_vuln_ids.issubset(known_vulns):
            remaining += SUBGOAL_COSTS["vuln_identified"]

        if state.get_access_level(host_id) not in ("web_shell", "ssh_user"):
            remaining += SUBGOAL_COSTS["web_shell"]

        needs_creds = has_ssh and not state.has_creds_for_access("ssh")
        if needs_creds:
            remaining += SUBGOAL_COSTS["creds_found"]

        if has_ssh:
            remaining += SUBGOAL_COSTS["compromised"]

    return remaining
