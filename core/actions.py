from dataclasses import dataclass

# string constant for every action name
# they double as JSON serialization identifiers for later
DISCOVER_HOST = "discover_host"
SCAN_HOST = "scan_host"
ENUM_HTTP = "enumerate_http"
IDENTIFY_VULN = "identify_vuln"
EXPLOIT_UPLOAD = "exploit_upload"
READ_SENSITIVE_FILE = "read_sensitive_file"
USE_CREDS_SSH = "use_credentials_ssh"
BRUTEFORCE_SSH = "bruteforce_ssh"
PIVOT_TO_HOST = "pivot_to_host"
ENUM_SMB = "enumerate_smb"
READ_SMB_SHARE = "read_smb_share"
EXPLOIT_JENKINS = "exploit_jenkins"
BRUTEFORCE_RDP = "bruteforce_rdp"
TRY_DEFAULT_CREDS = "try_default_creds"

# frozen so it's hashable later
@dataclass(frozen=True)
class Action:
    name: str
    target_host: str
    target_port: int | None = None

    def __str__(self) -> str:
        if self.target_port is not None:
            return f"{self.name}({self.target_host}:{self.target_port})"
        return f"{self.name}({self.target_host})"