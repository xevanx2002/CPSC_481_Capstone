from dataclasses import dataclass, field
from typing import Dict, List, Set


@dataclass
class Credential:
    username: str
    password: str
    access: str
    privilege: str
    source: str
    confidence: str


@dataclass
class State:
    discovered_hosts: Set[str] = field(default_factory=set)
    scanned_hosts: Set[str] = field(default_factory=set)

    open_ports: Dict[str, List[int]] = field(default_factory=dict)
    discovered_services: Dict[str, Dict[int, str]] = field(default_factory=dict)

    discovered_paths: Dict[str, Set[str]] = field(default_factory=dict)
    discovered_vulns: Dict[str, Set[str]] = field(default_factory=dict)

    access_levels: Dict[str, str] = field(default_factory=dict)
    compromised_hosts: Set[str] = field(default_factory=set)

    creds_found: List[Credential] = field(default_factory=list)

    actions_taken: List[str] = field(default_factory=list)
    total_cost: int = 0

    def clone(self) -> "State":
        return State(
            discovered_hosts=set(self.discovered_hosts),
            scanned_hosts=set(self.scanned_hosts),
            open_ports={host: ports[:] for host, ports in self.open_ports.items()},
            discovered_services={
                host: services.copy() for host, services in self.discovered_services.items()
            },
            discovered_paths={
                host: set(paths) for host, paths in self.discovered_paths.items()
            },
            discovered_vulns={
                host: set(vulns) for host, vulns in self.discovered_vulns.items()
            },
            access_levels=self.access_levels.copy(),
            compromised_hosts=set(self.compromised_hosts),
            creds_found=self.creds_found[:],
            actions_taken=self.actions_taken[:],
            total_cost=self.total_cost,
        )

    def has_creds_for_access(self, access_type: str) -> bool:
        return any(cred.access == access_type for cred in self.creds_found)

    def get_access_level(self, host_id: str) -> str:
        return self.access_levels.get(host_id, "none")