"""
KB = Knowledge Based

Generic vulnerability knowledge base.

We currently have per-scenario JSONs which declares the world (hosts, services, paths, loot)
but it does not declare which vulns exist. That knowledge will be living here.
It'll be applied at run time against the observed state. This is what lets the planner reason about
unknown infrastructure (HackTheBox) where we can't spoil the answer in
the scenario file.

A KB rule produces a vuln dict in the same shape `transition.py` and
`action_generator.py` already consume from declared scenarios, so existing
gating logic (e.g. `VF-UPLOAD-001` triggers EXPLOIT_UPLOAD) keeps working.
"""

from typing import Callable

from core.state import State

# Each rule: (id, name, severity, cost, requires, gives, predicate)
# `predicate(host, state) -> bool` decides if the rule fires given current observations.
RULES: list[dict] = [
    {
        "id": "VF-UPLOAD-001",
        "name": "Nibbleblog 4.0.3 authenticated arbitrary file upload (CVE-2015-6967)",
        "service": "http",
        "severity": "high",
        "cost": 3,
        "requires": ["/admin", "credential:admin"],
        "gives": ["web_shell", "file_access"],
        "predicate": lambda host, state: (
            _path_contains(state, host["id"], "nibbleblog")
            and state.has_creds_for_access("http")
        ),
    },
    {
        "id": "VF-JENKINS-001",
        "name": "Jenkins Script Console RCE (default credentials)",
        "service": "http",
        "severity": "high",
        "cost": 4,
        "requires": ["/script"],
        "gives": ["web_shell", "file_access"],
        "predicate": lambda host, state: (
            _path_contains(state, host["id"], "/script")
            and _service_banner_contains(state, host["id"], "jenkins")
        ),
    },
]


def _path_contains(state: State, host_id: str, fragment: str) -> bool:
    return any(fragment in p for p in state.discovered_paths.get(host_id, set()))


def _service_banner_contains(state: State, host_id: str, fragment: str) -> bool:
    services = state.discovered_services.get(host_id, {})
    return any(fragment.lower() in str(name).lower() for name in services.values())


def _strip_predicate(rule: dict) -> dict:
    return {k: v for k, v in rule.items() if k != "predicate"}


def match_kb(host: dict, state: State) -> list[dict]:
    """Return KB rules whose predicates fire against current observations."""
    return [_strip_predicate(rule) for rule in RULES if rule["predicate"](host, state)]


def vuln_requirements_met(vuln: dict, paths: set, state: State) -> bool:
    """Check vuln 'requires' list against observed paths and creds.

    Path requirements use substring matching so a generic hint like "/admin"
    matches deeper real paths like "/nibbleblog/admin.php".
    """
    for req in vuln.get("requires", []):
        if req.startswith("credential:"):
            user = req.split(":", 1)[1]
            if not any(c.username == user for c in state.creds_found):
                return False
        else:
            if not any(req in path for path in paths):
                return False
    return True


def vulns_for(host: dict, state: State) -> list[dict]:
    """Union of scenario-declared vulns and KB-matched vulns, deduped by id.

    Declared vulns win on conflict — scenarios can override KB defaults if
    they want to pin a specific cost or requirement set.
    """
    declared = list(host.get("vulnerabilities", []))
    declared_ids = {v["id"] for v in declared}
    matched = [v for v in match_kb(host, state) if v["id"] not in declared_ids]
    return declared + matched