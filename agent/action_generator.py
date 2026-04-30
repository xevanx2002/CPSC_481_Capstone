from core.actions import (
    Action,
    DISCOVER_HOST,
    SCAN_HOST,
    ENUM_HTTP,
    IDENTIFY_VULN,
    EXPLOIT_UPLOAD,
    READ_SENSITIVE_FILE,
    USE_CREDS_SSH,
    BRUTEFORCE_SSH,
    PIVOT_TO_HOST,
    ENUM_SMB,
    READ_SMB_SHARE,
    EXPLOIT_JENKINS,
    BRUTEFORCE_RDP,
    TRY_DEFAULT_CREDS,
)

ADMIN_PATH_HINTS = ("/admin", "/login", "/manage", "/wp-admin", "/console")
from core.state import State
from knowledge import vuln_reqs_met, vulns_for


def legal_actions(state: State, scenario: dict) -> list[Action]:
    actions: list[Action] = []

    for host in scenario.get("hosts", []):
        host_id = host["id"]

        if host_id not in state.reachable_hosts:
            continue

        if host_id not in state.discovered_hosts:
            actions.append(Action(DISCOVER_HOST, host_id))
            continue

        if host_id not in state.scanned_hosts:
            actions.append(Action(SCAN_HOST, host_id))
            continue

        services = state.discovered_services.get(host_id, {})
        paths = state.discovered_paths.get(host_id, set())
        known_vulns = state.discovered_vulns.get(host_id, set())
        candidate_vulns = vulns_for(host, state)
        host_vuln_ids = {v["id"] for v in candidate_vulns}

        for port, name in services.items():
            if name == "http" and not _http_port_enumerated(host, port, paths):
                actions.append(Action(ENUM_HTTP, host_id, port))

            if (
                name == "http"
                and any(hint in path for hint in ADMIN_PATH_HINTS for path in paths)
                and not state.has_creds_for_access("http")
            ):
                actions.append(Action(TRY_DEFAULT_CREDS, host_id, port))

        if services.get(445) == "smb" and "smb://shares" not in paths:
            actions.append(Action(ENUM_SMB, host_id, 445))

        if "smb://shares" in paths and not _all_loot_collected(
            state, host, source_prefix="smb://"
        ):
            actions.append(Action(READ_SMB_SHARE, host_id, 445))

        if (
            host_vuln_ids
            and not host_vuln_ids.issubset(known_vulns)
            and _any_vuln_reqs_met(candidate_vulns, paths, state)
        ):
            actions.append(Action(IDENTIFY_VULN, host_id))

        if (
            "VF-UPLOAD-001" in known_vulns
            and state.get_access_level(host_id) not in ("web_shell", "ssh_user")
            and host_id not in state.compromised_hosts
        ):
            actions.append(Action(EXPLOIT_UPLOAD, host_id))

        if (
            "VF-JENKINS-001" in known_vulns
            and state.get_access_level(host_id) not in ("web_shell", "ssh_user")
            and host_id not in state.compromised_hosts
        ):
            actions.append(Action(EXPLOIT_JENKINS, host_id))

        if (
            state.get_access_level(host_id) == "web_shell"
            and any(
                loot.get("type") == "credential"
                and not loot.get("source", "").startswith("smb://")
                for loot in host.get("loot", [])
            )
            and not _all_loot_collected(
                state, host, source_prefix=None, exclude_smb=True
            )
        ):
            actions.append(Action(READ_SENSITIVE_FILE, host_id))

        if (
            state.has_creds_for_access("ssh")
            and services.get(22) == "ssh"
            and host_id not in state.compromised_hosts
        ):
            actions.append(Action(USE_CREDS_SSH, host_id, 22))

        if services.get(22) == "ssh" and host_id not in state.compromised_hosts:
            actions.append(Action(BRUTEFORCE_SSH, host_id, 22))

        if services.get(3389) == "rdp" and host_id not in state.compromised_hosts:
            actions.append(Action(BRUTEFORCE_RDP, host_id, 3389))

    for host in scenario.get("hosts", []):
        host_id = host["id"]
        if host_id in state.reachable_hosts:
            continue
        sources = [
            h
            for h in scenario.get("hosts", [])
            if h["id"] in state.compromised_hosts and host_id in h.get("reaches", [])
        ]
        if sources:
            actions.append(Action(PIVOT_TO_HOST, host_id))

    return actions


def _http_port_enumerated(host: dict, port: int, paths: set) -> bool:
    service = next((s for s in host.get("services", []) if s["port"] == port), None)
    if service is None:
        # discover mode — no scenario data. consider enumerated only once
        # we've actually populated paths via execution
        return bool(paths)
    expected = set(service.get("paths", []))
    return expected.issubset(paths) if expected else True


def _any_vuln_reqs_met(vulns: list[dict], paths: set, state: State) -> bool:
    return any(vuln_reqs_met(v, paths, state) for v in vulns)


def _all_loot_collected(
    state: State,
    host: dict,
    source_prefix: str | None = None,
    exclude_smb: bool = False,
) -> bool:
    for loot in host.get("loot", []):
        if loot.get("type") != "credential":
            continue
        source = loot.get("source", "")
        if source_prefix is not None and not source.startswith(source_prefix):
            continue
        if exclude_smb and source.startswith("smb://"):
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
