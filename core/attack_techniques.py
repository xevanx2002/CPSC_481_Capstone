"""

maps each VectorForge action to its closest MITRE ATT&CK technique.
used by the live runner to narrate "what attacker move is this"
during a run, and by reports to tag actions with the framework
language reviewers expect to see.

reference: https://attack.mitre.org/

"""

from core.actions import (
    DISCOVER_HOST,
    SCAN_HOST,
    ENUM_HTTP,
    ENUM_SMB,
    TRY_DEFAULT_CREDS,
    IDENTIFY_VULN,
    EXPLOIT_UPLOAD,
    EXPLOIT_JENKINS,
    EXPLOIT_PRIVESC,
    CAPTURE_FLAGS,
    READ_SENSITIVE_FILE,
    READ_SMB_SHARE,
    USE_CREDS_SSH,
    BRUTEFORCE_SSH,
    BRUTEFORCE_RDP,
    PIVOT_TO_HOST,
)


# action_name -> {tactic_id, tactic_name, technique_id, technique_name}
# some actions touch multiple techniques. we pick the most representative one
# and put alternates in `also` for the report
TECHNIQUES: dict[str, dict] = {
    DISCOVER_HOST: {
        "tactic_id": "TA0007",
        "tactic_name": "Discovery",
        "technique_id": "T1018",
        "technique_name": "Remote System Discovery",
    },
    SCAN_HOST: {
        "tactic_id": "TA0007",
        "tactic_name": "Discovery",
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
    },
    ENUM_HTTP: {
        "tactic_id": "TA0043",
        "tactic_name": "Reconnaissance",
        "technique_id": "T1595.003",
        "technique_name": "Wordlist Scanning",
    },
    ENUM_SMB: {
        "tactic_id": "TA0007",
        "tactic_name": "Discovery",
        "technique_id": "T1135",
        "technique_name": "Network Share Discovery",
    },
    TRY_DEFAULT_CREDS: {
        "tactic_id": "TA0006",
        "tactic_name": "Credential Access",
        "technique_id": "T1078.001",
        "technique_name": "Default Accounts",
    },
    IDENTIFY_VULN: {
        "tactic_id": "TA0043",
        "tactic_name": "Reconnaissance",
        "technique_id": "T1595.002",
        "technique_name": "Vulnerability Scanning",
    },
    EXPLOIT_UPLOAD: {
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "also": ["T1505.003 Web Shell"],
    },
    EXPLOIT_JENKINS: {
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
    },
    EXPLOIT_PRIVESC: {
        "tactic_id": "TA0004",
        "tactic_name": "Privilege Escalation",
        "technique_id": "T1548.003",
        "technique_name": "Sudo and Sudo Caching",
    },
    READ_SENSITIVE_FILE: {
        "tactic_id": "TA0006",
        "tactic_name": "Credential Access",
        "technique_id": "T1552.001",
        "technique_name": "Credentials In Files",
    },
    CAPTURE_FLAGS: {
        "tactic_id": "TA0009",
        "tactic_name": "Collection",
        "technique_id": "T1005",
        "technique_name": "Data from Local System",
    },
    READ_SMB_SHARE: {
        "tactic_id": "TA0009",
        "tactic_name": "Collection",
        "technique_id": "T1039",
        "technique_name": "Data from Network Shared Drive",
    },
    USE_CREDS_SSH: {
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
    },
    BRUTEFORCE_SSH: {
        "tactic_id": "TA0006",
        "tactic_name": "Credential Access",
        "technique_id": "T1110.001",
        "technique_name": "Password Guessing",
    },
    BRUTEFORCE_RDP: {
        "tactic_id": "TA0006",
        "tactic_name": "Credential Access",
        "technique_id": "T1110.001",
        "technique_name": "Password Guessing",
    },
    PIVOT_TO_HOST: {
        "tactic_id": "TA0008",
        "tactic_name": "Lateral Movement",
        "technique_id": "T1090",
        "technique_name": "Proxy",
        "also": ["T1572 Protocol Tunneling"],
    },
}


def technique_for(action_name: str) -> dict | None:
    return TECHNIQUES.get(action_name)
