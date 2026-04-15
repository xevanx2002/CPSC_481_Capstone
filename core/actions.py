from dataclasses import dataclass


DISCOVER_HOST = "discover_host"
SCAN_HOST = "scan_host"
ENUM_HTTP = "enumerate_http"
IDENTIFY_VULNERABILITY = "identify_vulnerability"
EXPLOIT_UPLOAD = "exploit_upload"
READ_SENSITIVE_FILE = "read_sensitive_file"
USE_CREDS_SSH = "use_credentials_ssh"


@dataclass(frozen=True)
class Action:
    name: str
    target_host: str
    target_port: int | None = None

    def __str__(self) -> str:
        if self.target_port is not None:
            return f"{self.name}({self.target_host}:{self.target_port})"
        return f"{self.name}({self.target_host})"