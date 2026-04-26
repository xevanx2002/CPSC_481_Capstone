from core.actions import (
    Action,
    DISCOVER_HOST,
    SCAN_HOST,
    ENUM_HTTP,
    IDENTIFY_VULNERABILITY,
    EXPLOIT_UPLOAD,
    READ_SENSITIVE_FILE,
    USE_CREDS_SSH,
    BRUTEFORCE_SSH,
)
from core.state import State


def legal_actions(state: State, scenario: dict) -> list[Action]:
    actions: list[Action] = []

    for host in scenario.get("hosts", []):
        host_id = host["id"]

        if host_id not in state.discovered_hosts:
            actions.append(Action(DISCOVER_HOST, host_id))
            continue

        if host_id not in state.scanned_hosts:
            actions.append(Action(SCAN_HOST, host_id))
            continue

        services = state.discovered_services.get(host_id, {})

        if services.get(80) == "http" and host_id not in state.discovered_paths:
            actions.append(Action(ENUM_HTTP, host_id, 80))

        paths = state.discovered_paths.get(host_id, set())
        known_vulns = state.discovered_vulns.get(host_id, set())
        host_vuln_ids = {v["id"] for v in host.get("vulnerabilities", [])}

        if "/admin" in paths and not host_vuln_ids.issubset(known_vulns):
            actions.append(Action(IDENTIFY_VULNERABILITY, host_id))

        if (
            "VF-UPLOAD-001" in known_vulns
            and state.get_access_level(host_id) != "web_shell"
            and host_id not in state.compromised_hosts
        ):
            actions.append(Action(EXPLOIT_UPLOAD, host_id))

        if state.get_access_level(host_id) == "web_shell" and any(
            loot.get("type") == "credential" for loot in host.get("loot", [])
        ) and not _all_loot_collected(state, host):
            actions.append(Action(READ_SENSITIVE_FILE, host_id))

        if (
            state.has_creds_for_access("ssh")
            and services.get(22) == "ssh"
            and host_id not in state.compromised_hosts
        ):
            actions.append(Action(USE_CREDS_SSH, host_id, 22))

        if services.get(22) == "ssh" and host_id not in state.compromised_hosts:
            actions.append(Action(BRUTEFORCE_SSH, host_id, 22))

    return actions


def _all_loot_collected(state: State, host: dict) -> bool:
    for loot in host.get("loot", []):
        if loot.get("type") != "credential":
            continue
        match = any(
            c.username == loot["username"]
            and c.password == loot["password"]
            and c.access == loot["access"]
            for c in state.creds_found
        )
        if not match:
            return False
    return True
