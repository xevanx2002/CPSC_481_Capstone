from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Dict, List, Set

if TYPE_CHECKING:
    from core.actions import Action
"""
**use Set when uniqueness matters**
**use List when order/repetition matters** 
**use Dict when you're keying off something**
"""

# simple login
@dataclass
class Credential:
    username: str
    password: str
    access: str
    privilege: str
    source: str
    confidence: str


# essentially a "notebook" that starts empty and gets
# filled as the agent gathers info.
# the agent acts, observations come back and
# the objects fields get filled in.
# the notebook becomes the runtime_state variable in main
@dataclass
class State:
                                                           # hosts the agent ...
    reachable_hosts: Set[str] = field(default_factory=set) # - can talk to network wise
    discovered_hosts: Set[str] = field(default_factory=set)# - knows exist
    scanned_hosts: Set[str] = field(default_factory=set)   # - has fully port scanned

    open_ports: Dict[str, List[int]] = field(default_factory=dict)
    discovered_services: Dict[str, Dict[int, str]] = field(default_factory=dict)

    discovered_paths: Dict[str, Set[str]] = field(default_factory=dict)
    discovered_vulns: Dict[str, Set[str]] = field(default_factory=dict)

    access_levels: Dict[str, str] = field(default_factory=dict) # string ladder
    compromised_hosts: Set[str] = field(default_factory=set) # strict win condition

    # hosts where we got a verified web_shell foothold but haven't escalated
    # to ssh/rdp yet. partial credit signal so the report doesn't show 0
    # when a real RCE was achieved v
    footholds: Set[str] = field(default_factory=set)

    # shell URLs for hosts where we landed a web shell
    # privesc and post-exploit actions reach back through these to run commands
    shell_urls: Dict[str, str] = field(default_factory=dict)

    creds_found: List[Credential] = field(default_factory=list)

    actions_taken: List["Action"] = field(default_factory=list)
    total_cost: int = 0

# returns deep copy of current state. Important for the planner
# A* explores many possible futures without polluting current state
# by making clones
# clones -> applies action to clone -> reasons about it
# creates containers of clones wrapped in set() or dict()
    def clone(self) -> "State":
        return State(
            reachable_hosts=set(self.reachable_hosts),
            discovered_hosts=set(self.discovered_hosts),
            scanned_hosts=set(self.scanned_hosts),
            open_ports={host: ports[:] for host, ports in self.open_ports.items()},
            discovered_services={
                host: services.copy()
                for host, services in self.discovered_services.items()
            },
            discovered_paths={
                host: set(paths) for host, paths in self.discovered_paths.items()
            },
            discovered_vulns={
                host: set(vulns) for host, vulns in self.discovered_vulns.items()
            },
            access_levels=self.access_levels.copy(),
            compromised_hosts=set(self.compromised_hosts),
            footholds=set(self.footholds),
            shell_urls=dict(self.shell_urls),
            creds_found=self.creds_found[:],
            actions_taken=self.actions_taken[:],
            total_cost=self.total_cost,
        )

    def has_creds_for_access(self, access_type: str) -> bool:
        return any(cred.access == access_type for cred in self.creds_found)

    def get_access_level(self, host_id: str) -> str:
        return self.access_levels.get(host_id, "none")

# returns tuple of every important fact in the state
# A* needs to know "have i seen this already?" to avoid re exploring
# signature() flatten whole state into a hashable fingerprint in a set called 
# visited to skip redundant work
    def signature(self) -> tuple:
        return (
            frozenset(self.reachable_hosts),
            frozenset(self.discovered_hosts),
            frozenset(self.scanned_hosts),
            frozenset(
                (host, port)
                for host, ports in self.open_ports.items()
                for port in ports
            ),
            frozenset(
                (host, port, name)
                for host, services in self.discovered_services.items()
                for port, name in services.items()
            ),
            frozenset(
                (host, path)
                for host, paths in self.discovered_paths.items()
                for path in paths
            ),
            frozenset(
                (host, vuln)
                for host, vulns in self.discovered_vulns.items()
                for vuln in vulns
            ),
            frozenset(self.access_levels.items()),
            frozenset(self.compromised_hosts),
            frozenset(self.footholds),
            frozenset(self.shell_urls.items()),
            frozenset((c.username, c.password, c.access) for c in self.creds_found),
        )