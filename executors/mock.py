from core.actions import Action
from core.state import State
from executors.base import ExecutionResult
from knowledge import loot_files_for_discovered, vuln_reqs_met, vulns_for


def _find_host(scenario: dict, host_id: str) -> dict | None:
    for h in scenario.get("hosts", []):
        if h["id"] == host_id:
            return h
    return None


def _loot_creds(host: dict) -> list[dict]:
    out = []
    for loot in host.get("loot", []):
        if loot.get("type") != "credential":
            continue
        out.append(
            {
                "username": loot["username"],
                "password": loot["password"],
                "access": loot.get("access", "ssh"),
                "privilege": loot.get("privilege", "user"),
                "source": loot.get("source", "unknown"),
                "confidence": loot.get("confidence", "high"),
            }
        )
    return out


class MockExecutor:
    """
    Returns canned observations from the scenario JSON. 
    No network input / output

    Mirrors the contract in docs/action_execution_mapping.md so the runner can
    be exercised end-to-end before any VMs we made exist
    """

    def execute(self, action: Action, state: State, scenario: dict) -> ExecutionResult:
        handler = getattr(self, f"_do_{action.name}", None)
        if handler is None:
            return ExecutionResult(
                action=action,
                success=False,
                error=f"no_mock_handler:{action.name}",
            )
        return handler(action, state, scenario)

    def _do_discover_host(self, action, state, scenario):
        if _find_host(scenario, action.target_host) is None:
            return ExecutionResult(action, False, error="host_unknown")
        return ExecutionResult(action, True, observed={"host_alive": True})

    def _do_scan_host(self, action, state, scenario):
        host = _find_host(scenario, action.target_host)
        if host is None:
            return ExecutionResult(action, False, error="host_unknown")
        ports = [s["port"] for s in host.get("services", [])]
        services = {s["port"]: s["name"] for s in host.get("services", [])}
        return ExecutionResult(
            action,
            True,
            observed={"open_ports": ports, "services": services},
        )

    def _do_enumerate_http(self, action, state, scenario):
        host = _find_host(scenario, action.target_host)
        if host is None:
            return ExecutionResult(action, False, error="host_unknown")
        for s in host.get("services", []):
            if s.get("name") == "http" and s["port"] == action.target_port:
                return ExecutionResult(
                    action, True, observed={"paths": s.get("paths", [])}
                )
        return ExecutionResult(action, False, error="http_enum_failed")

    def _do_enumerate_smb(self, action, state, scenario):
        host = _find_host(scenario, action.target_host)
        if host is None:
            return ExecutionResult(action, False, error="host_unknown")
        for s in host.get("services", []):
            if s.get("name") == "smb":
                return ExecutionResult(
                    action, True, observed={"paths": ["smb://shares"]}
                )
        return ExecutionResult(action, False, error="smb_enum_failed")

    def _do_identify_vuln(self, action, state, scenario):
        host = _find_host(scenario, action.target_host)
        if host is None:
            return ExecutionResult(action, False, error="host_unknown")
        host_paths = state.discovered_paths.get(action.target_host, set())
        matched = [
            v["id"]
            for v in vulns_for(host, state)
            if vuln_reqs_met(v, host_paths, state, host_id=action.target_host)
        ]
        if not matched:
            return ExecutionResult(action, False, error="no_vulns_identified")
        return ExecutionResult(action, True, observed={"vulns": matched})

    def _do_exploit_upload(self, action, state, scenario):
        if "VF-UPLOAD-001" not in state.discovered_vulns.get(action.target_host, set()):
            return ExecutionResult(action, False, error="vuln_not_identified")
        host = _find_host(scenario, action.target_host)
        ip = host.get("ip", "?") if host else "?"
        shell_url = f"http://{ip}/uploads/webshell.php"
        return ExecutionResult(
            action,
            True,
            observed={"access_level": "web_shell", "shell_url": shell_url},
            artifacts={"shell_url": shell_url},
        )

    def _do_exploit_jenkins(self, action, state, scenario):
        if "VF-JENKINS-001" not in state.discovered_vulns.get(
            action.target_host, set()
        ):
            return ExecutionResult(action, False, error="vuln_not_identified")
        host = _find_host(scenario, action.target_host)
        ip = host.get("ip", "?") if host else "?"
        shell_url = f"http://{ip}/jenkins/script-shell"
        return ExecutionResult(
            action,
            True,
            observed={"access_level": "web_shell", "shell_url": shell_url},
            artifacts={"shell_url": shell_url},
        )

    def _do_exploit_privesc(self, action, state, scenario):
        if "VF-PRIVESC-001" not in state.discovered_vulns.get(
            action.target_host, set()
        ):
            return ExecutionResult(action, False, error="vuln_not_identified")
        if state.access_levels.get(action.target_host) != "web_shell":
            return ExecutionResult(action, False, error="no_web_shell")
        return ExecutionResult(
            action, True, observed={"access_level": "root", "compromised": True}
        )

    def _do_read_sensitive_file(self, action, state, scenario):
        if state.access_levels.get(action.target_host) != "web_shell":
            return ExecutionResult(action, False, error="no_web_shell")
        host = _find_host(scenario, action.target_host)
        creds = _loot_creds(host) if host else []
        if not creds:
            return ExecutionResult(action, False, error="file_read_failed")
        return ExecutionResult(action, True, observed={"creds": creds})

    def _do_read_smb_share(self, action, state, scenario):
        if "smb://shares" not in state.discovered_paths.get(action.target_host, set()):
            return ExecutionResult(action, False, error="smb_not_enumerated")
        host = _find_host(scenario, action.target_host)
        creds = _loot_creds(host) if host else []
        if not creds:
            return ExecutionResult(action, False, error="smb_read_failed")
        return ExecutionResult(action, True, observed={"creds": creds})

    def _do_use_credentials_ssh(self, action, state, scenario):
        if not any(c.access == "ssh" for c in state.creds_found):
            return ExecutionResult(action, False, error="no_ssh_creds")
        return ExecutionResult(
            action,
            True,
            observed={"access_level": "ssh_user", "compromised": True},
        )

    def _do_bruteforce_ssh(self, action, state, scenario):
        return ExecutionResult(
            action,
            True,
            observed={
                "access_level": "ssh_user",
                "compromised": True,
                "creds": [
                    {
                        "username": "guest",
                        "password": "guest",
                        "access": "ssh",
                        "privilege": "user",
                        "source": "bruteforce",
                        "confidence": "low",
                    }
                ],
            },
        )

    def _do_bruteforce_rdp(self, action, state, scenario):
        return ExecutionResult(
            action,
            True,
            observed={"access_level": "rdp_user", "compromised": True},
        )

    def _do_try_default_creds(self, action, state, scenario):
        host = _find_host(scenario, action.target_host)
        if host is None:
            return ExecutionResult(action, False, error="host_unknown")
        creds = [
            {
                "username": loot["username"],
                "password": loot["password"],
                "access": loot.get("access", "http"),
                "privilege": loot.get("privilege", "user"),
                "source": loot.get("source", "default_credentials"),
                "confidence": loot.get("confidence", "medium"),
            }
            for loot in host.get("loot", [])
            if loot.get("type") == "credential" and loot.get("access") == "http"
        ]
        if not creds:
            return ExecutionResult(action, False, error="default_creds_failed")
        return ExecutionResult(action, True, observed={"creds": creds})

    def _do_capture_flags(self, action, state, scenario):
        host = _find_host(scenario, action.target_host)
        if host is None:
            return ExecutionResult(action, False, error="host_unknown")

        access = state.access_levels.get(action.target_host, "none")
        if access not in ("web_shell", "ssh_user", "rdp_user", "root"):
            return ExecutionResult(action, False, error="no_shell_for_capture")

        already = state.loot.get(action.target_host, {})
        loot_captured: dict[str, str] = {}
        for path in loot_files_for_discovered(host, state, action.target_host):
            if path in already:
                continue
            loot_captured[path] = f"<mock-loot:{path}>"

        if not loot_captured:
            return ExecutionResult(action, False, error="nothing_to_capture")

        return ExecutionResult(
            action,
            True,
            observed={"loot_captured": loot_captured},
        )

    def _do_pivot_to_host(self, action, state, scenario):
        target = action.target_host
        for h in scenario.get("hosts", []):
            if target in h.get("reaches", []) and h["id"] in state.compromised_hosts:
                return ExecutionResult(action, True, observed={"reachable": [target]})
        return ExecutionResult(action, False, error="pivot_failed")
