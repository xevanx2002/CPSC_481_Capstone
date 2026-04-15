from core.actions import (
    Action,
    DISCOVER_HOST,
    SCAN_HOST,
    ENUM_HTTP,
    IDENTIFY_VULNERABILITY,
    EXPLOIT_UPLOAD,
    READ_SENSITIVE_FILE,
    USE_CREDS_SSH,
)
from core.state import State, Credential


ACTION_COSTS = {
    DISCOVER_HOST: 1,
    SCAN_HOST: 1,
    ENUM_HTTP: 2,
    IDENTIFY_VULNERABILITY: 2,
    EXPLOIT_UPLOAD: 3,
    READ_SENSITIVE_FILE: 1,
    USE_CREDS_SSH: 2,
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

        new_state.discovered_hosts.add(host_id)
        new_state.access_levels[host_id] = "none"

    elif action.name == SCAN_HOST:
        if host_id not in new_state.discovered_hosts:
            return None
        if host_id in new_state.scanned_hosts:
            return None

        new_state.scanned_hosts.add(host_id)
        new_state.open_ports[host_id] = [service["port"] for service in host["services"]]
        new_state.discovered_services[host_id] = {
            service["port"]: service["name"] for service in host["services"]
        }

    elif action.name == ENUM_HTTP:
        if host_id not in new_state.scanned_hosts:
            return None

        services = new_state.discovered_services.get(host_id, {})
        if 80 not in services or services[80] != "http":
            return None

        if host_id not in new_state.discovered_paths:
            new_state.discovered_paths[host_id] = set()

        http_service = _get_service_by_port(host, 80)
        if http_service is None:
            return None

        for path in http_service.get("paths", []):
            new_state.discovered_paths[host_id].add(path)

    elif action.name == IDENTIFY_VULNERABILITY:
        if host_id not in new_state.discovered_paths:
            return None
        if "/admin" not in new_state.discovered_paths[host_id]:
            return None

        if host_id not in new_state.discovered_vulns:
            new_state.discovered_vulns[host_id] = set()

        for vuln in host.get("vulnerabilities", []):
            new_state.discovered_vulns[host_id].add(vuln["id"])

    elif action.name == EXPLOIT_UPLOAD:
        if host_id not in new_state.discovered_vulns:
            return None
        if "VF-UPLOAD-001" not in new_state.discovered_vulns[host_id]:
            return None

        new_state.access_levels[host_id] = "web_shell"

    elif action.name == READ_SENSITIVE_FILE:
        if new_state.get_access_level(host_id) != "web_shell":
            return None

        for loot in host.get("loot", []):
            if loot.get("type") == "credential":
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
                    for c in new_state.creds_found
                )

                if not already_known:
                    new_state.creds_found.append(credential)

    elif action.name == USE_CREDS_SSH:
        if not new_state.has_creds_for_access("ssh"):
            return None

        services = new_state.discovered_services.get(host_id, {})
        if 22 not in services or services[22] != "ssh":
            return None

        new_state.access_levels[host_id] = "ssh_user"
        new_state.compromised_hosts.add(host_id)

    else:
        return None

    new_state.actions_taken.append(str(action))
    new_state.total_cost += ACTION_COSTS.get(action.name, 0)
    return new_state


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