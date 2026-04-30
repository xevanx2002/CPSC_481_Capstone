"""Real subprocess-backed executors.

Each handler returns an `ExecutionResult` carrying `raw=<command output>`
so the eventual report can show *what was actually run*. Unimplemented
actions return error="not_implemented" so HybridExecutor can fall through
to the mock implementation while we incrementally fill these in.
"""

import re
import shutil
import subprocess

from core.actions import Action
from core.state import State
from executors.base import ExecutionResult


_NMAP_PORT_RE = re.compile(r"^(\d+)/tcp\s+open\s+(\S+)(?:\s+(.+))?$", re.MULTILINE)


def parse_nmap_services(output: str) -> tuple[list[int], dict[int, str]]:
    """Parse `nmap -sV` stdout into (ports, {port: service_name})."""
    ports: list[int] = []
    services: dict[int, str] = {}
    for match in _NMAP_PORT_RE.finditer(output):
        port = int(match.group(1))
        name = match.group(2)
        ports.append(port)
        services[port] = name
    return ports, services


class RealExecutor:
    def __init__(
        self,
        nmap_extra_args: list[str] | None = None,
        scan_timeout: int = 300,
    ):
        self.nmap_extra = nmap_extra_args or []
        self.scan_timeout = scan_timeout

    def execute(
        self, action: Action, state: State, scenario: dict
    ) -> ExecutionResult:
        handler = getattr(self, f"_do_{action.name}", None)
        if handler is None:
            return ExecutionResult(action, False, error="not_implemented")
        return handler(action, state, scenario)

    def _ip_for(self, scenario: dict, host_id: str) -> str | None:
        for h in scenario.get("hosts", []):
            if h["id"] == host_id:
                return h.get("ip")
        return None

    def _do_discover_host(self, action, state, scenario):
        ip = self._ip_for(scenario, action.target_host)
        if not ip:
            return ExecutionResult(action, False, error="host_unknown")
        if not shutil.which("nmap"):
            return ExecutionResult(
                action, False, error="not_implemented", raw="nmap not installed"
            )
        try:
            proc = subprocess.run(
                ["nmap", "-sn", "-PE", ip, *self.nmap_extra],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except subprocess.TimeoutExpired:
            return ExecutionResult(action, False, error="discover_timeout")

        if "Host is up" not in proc.stdout:
            return ExecutionResult(
                action, False, error="host_unreachable", raw=proc.stdout
            )
        return ExecutionResult(
            action, True, observed={"host_alive": True}, raw=proc.stdout
        )

    def _do_scan_host(self, action, state, scenario):
        ip = self._ip_for(scenario, action.target_host)
        if not ip:
            return ExecutionResult(action, False, error="host_unknown")
        if not shutil.which("nmap"):
            return ExecutionResult(
                action, False, error="not_implemented", raw="nmap not installed"
            )
        try:
            proc = subprocess.run(
                [
                    "nmap",
                    "-sV",
                    "--top-ports",
                    "1000",
                    ip,
                    *self.nmap_extra,
                ],
                capture_output=True,
                text=True,
                timeout=self.scan_timeout,
            )
        except subprocess.TimeoutExpired:
            return ExecutionResult(action, False, error="scan_timeout")

        ports, services = parse_nmap_services(proc.stdout)
        if not ports:
            return ExecutionResult(
                action, False, error="scan_failed", raw=proc.stdout
            )
        return ExecutionResult(
            action,
            True,
            observed={"open_ports": ports, "services": services},
            raw=proc.stdout,
        )
