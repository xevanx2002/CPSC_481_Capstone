from dataclasses import dataclass, field

@dataclass
class Service:
    port: int
    name: str
    version: str = ""
    application: str = ""
    paths: list[str] = field(default_factory = list)

@dataclass
class Host:
    id: str
    hostname: str
    ip: str
    role: str
    value: int
    services: list[Service] = field(default_factory = list)
    vulnerabilities: list[dict] = field(default_factory = list)
    loot: list[dict] = field(default_factory = list)