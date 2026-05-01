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
    EXPLOIT_PRIVESC,
)
from core.state import State, Credential
from knowledge import vuln_reqs_met, vulns_for

# kinda arbitrary point system
# no industry standard that I (mánu) could find
# feel free to argue if one needs
# a lower or higher value
ACTION_COSTS = {
    DISCOVER_HOST: 1,
    SCAN_HOST: 1,
    ENUM_HTTP: 2,
    IDENTIFY_VULN: 2,
    EXPLOIT_UPLOAD: 3,
    READ_SENSITIVE_FILE: 1,
    USE_CREDS_SSH: 2,
    BRUTEFORCE_SSH: 15, # last resort
    PIVOT_TO_HOST: 2,
    ENUM_SMB: 2,
    READ_SMB_SHARE: 1,
    EXPLOIT_JENKINS: 4,
    BRUTEFORCE_RDP: 12,
    TRY_DEFAULT_CREDS: 2,
    EXPLOIT_PRIVESC: 5,
}


def apply_action(state: State, action: Action, scenario: dict) -> State | None:
    new_state = state.clone()
    host_id = action.target_host
    host = _get_host_by_id(scenario, host_id)

    if host is None:
        return None

    if action.name == DISCOVER_HOST:
        if host_id in new_state.discovered_hosts:
            return None
        if host_id not in new_state.reachable_hosts:
            return None

        new_state.discovered_hosts.add(host_id)
        new_state.access_levels[host_id] = "none"

    elif action.name == SCAN_HOST:
        if host_id not in new_state.discovered_hosts:
            return None
        if host_id in new_state.scanned_hosts:
            return None

        new_state.scanned_hosts.add(host_id)

        # in declared scenarios services are pre known.
        # in discover mode they're empty here and get 
        # filled by the executor on replan
        services = host.get("services", [])
        new_state.open_ports[host_id] = [s["port"] for s in services]
        new_state.discovered_services[host_id] = {
            s["port"]: s["name"] for s in services
        }

    elif action.name == ENUM_HTTP:
        if host_id not in new_state.scanned_hosts:
            return None

        port = action.target_port if action.target_port is not None else 80
        services = new_state.discovered_services.get(host_id, {})
        if port not in services or services[port] != "http":
            return None

        if host_id not in new_state.discovered_paths:
            new_state.discovered_paths[host_id] = set()

        http_service = _get_service_by_port(host, port)
        if http_service is None:
            return None

        for path in http_service.get("paths", []):
            new_state.discovered_paths[host_id].add(path)

    elif action.name == IDENTIFY_VULN:
        paths = new_state.discovered_paths.get(host_id, set())

        if host_id not in new_state.discovered_vulns:
            new_state.discovered_vulns[host_id] = set()

        added = False
        for vuln in vulns_for(host, new_state):
            if not vuln_reqs_met(vuln, paths, new_state, host_id=host_id):
                continue
            if vuln["id"] not in new_state.discovered_vulns[host_id]:
                added = True
            new_state.discovered_vulns[host_id].add(vuln["id"])

        if not added:
            return None

    elif action.name == EXPLOIT_UPLOAD:
        if host_id not in new_state.discovered_vulns:
            return None
        if "VF-UPLOAD-001" not in new_state.discovered_vulns[host_id]:
            return None

        new_state.access_levels[host_id] = "web_shell"
        new_state.footholds.add(host_id)

    elif action.name == READ_SENSITIVE_FILE:
        if new_state.get_access_level(host_id) != "web_shell":
            return None

        for loot in host.get("loot", []):
            if loot.get("type") != "credential":
                continue
            if loot.get("source", "").startswith("smb://"):
                continue
            _add_credential(new_state, loot)

    elif action.name == BRUTEFORCE_SSH:
        services = new_state.discovered_services.get(host_id, {})
        if 22 not in services or services[22] != "ssh":
            return None
        if host_id in new_state.compromised_hosts:
            return None

        new_state.access_levels[host_id] = "ssh_user"
        new_state.compromised_hosts.add(host_id)

    elif action.name == USE_CREDS_SSH:
        if not new_state.has_creds_for_access("ssh"):
            return None

        services = new_state.discovered_services.get(host_id, {})
        if 22 not in services or services[22] != "ssh":
            return None

        new_state.access_levels[host_id] = "ssh_user"
        new_state.compromised_hosts.add(host_id)

    elif action.name == PIVOT_TO_HOST:
        sources = [
            h
            for h in scenario.get("hosts", [])
            if h["id"] in new_state.compromised_hosts
            and host_id in h.get("reaches", [])
        ]
        if not sources:
            return None
        if host_id in new_state.reachable_hosts:
            return None

        new_state.reachable_hosts.add(host_id)

    elif action.name == ENUM_SMB:
        if host_id not in new_state.scanned_hosts:
            return None
        services = new_state.discovered_services.get(host_id, {})
        if 445 not in services or services[445] != "smb":
            return None
        if (
            host_id in new_state.discovered_paths
            and "smb://shares" in new_state.discovered_paths[host_id]
        ):
            return None

        if host_id not in new_state.discovered_paths:
            new_state.discovered_paths[host_id] = set()
        new_state.discovered_paths[host_id].add("smb://shares")

    elif action.name == READ_SMB_SHARE:
        paths = new_state.discovered_paths.get(host_id, set())
        if "smb://shares" not in paths:
            return None

        for loot in host.get("loot", []):
            if loot.get("type") == "credential" and loot.get("source", "").startswith(
                "smb://"
            ):
                _add_credential(new_state, loot)

    elif action.name == EXPLOIT_JENKINS:
        if host_id not in new_state.discovered_vulns:
            return None
        if "VF-JENKINS-001" not in new_state.discovered_vulns[host_id]:
            return None
        if new_state.get_access_level(host_id) in ("web_shell", "ssh_user"):
            return None

        new_state.access_levels[host_id] = "web_shell"
        new_state.footholds.add(host_id)

    elif action.name == EXPLOIT_PRIVESC:
        # privesc bumps web_shell to root and counts as a real compromise
        # only fires when we already have a foothold cause we need shell access
        # to drop the payload and trigger the sudo
        if host_id not in new_state.discovered_vulns:
            return None
        if "VF-PRIVESC-001" not in new_state.discovered_vulns[host_id]:
            return None
        # so we don't try to privesc when we already have ssh_user / root
        if new_state.get_access_level(host_id) != "web_shell":
            return None

        new_state.access_levels[host_id] = "root"
        new_state.compromised_hosts.add(host_id)

    elif action.name == TRY_DEFAULT_CREDS:
        port = action.target_port
        services = new_state.discovered_services.get(host_id, {})
        if port not in services or services[port] != "http":
            return None
        if new_state.has_creds_for_access("http"):
            return None

        added = False
        for loot in host.get("loot", []):
            if loot.get("type") != "credential":
                continue
            if loot.get("access") != "http":
                continue
            before = len(new_state.creds_found)
            _add_credential(new_state, loot)
            if len(new_state.creds_found) > before:
                added = True

        if not added:
            return None

    elif action.name == BRUTEFORCE_RDP:
        services = new_state.discovered_services.get(host_id, {})
        if 3389 not in services or services[3389] != "rdp":
            return None
        if host_id in new_state.compromised_hosts:
            return None

        new_state.access_levels[host_id] = "rdp_user"
        new_state.compromised_hosts.add(host_id)

    else:
        return None

    new_state.actions_taken.append(action)
    new_state.total_cost += _action_cost(action, host)
    return new_state


SEVERITY_MULTIPLIER = {"low": 1.5, "medium": 1.0, "high": 0.7, "critical": 0.5}


def _action_cost(action: Action, host: dict) -> int:
    base = ACTION_COSTS.get(action.name, 0)

    if action.name == EXPLOIT_UPLOAD:
        vuln = next(
            (v for v in host.get("vulnerabilities", []) if v["id"] == "VF-UPLOAD-001"),
            None,
        )
        if vuln:
            mult = SEVERITY_MULTIPLIER.get(vuln.get("severity", "medium"), 1.0)
            return max(1, round(base * mult))

    return base


def _add_credential(state: State, loot: dict) -> None:
    credential = Credential(
        username=loot["username"],
        password=loot["password"],
        access=loot["access"],
        privilege=loot["privilege"],
        source=loot["source"],
        confidence=loot["confidence"],
    )
    already_known = any(
        c.username == credential.username
        and c.password == credential.password
        and c.access == credential.access
        for c in state.creds_found
    )
    if not already_known:
        state.creds_found.append(credential)


def _get_host_by_id(scenario: dict, host_id: str) -> dict | None:
    for host in scenario.get("hosts", []):
        if host["id"] == host_id:
            return host
    return None


def _get_service_by_port(host: dict, port: int) -> dict | None:
    for service in host.get("services", []):
        if service["port"] == port:
            return service
    return None