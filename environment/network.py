from environment.host import Host, Service

class Network:
    def __init__(self, scenario: dict):
        self.scenario = scenario
        self.hosts = self._load_hosts(scenario)

    def _load_hosts(self, scenario: dict) -> dict[str, Host]:
        hosts = {}

        for host_data in scenario.get("hosts", []):
            services = [
                Service(
                    port = s["port"],
                    name = s["name"],
                    version = s.get("version", ""),
                    application = s.get("application", ""),
                    path = s.get("paths", [])
                )
                
                for s in host_data.get("services", [])
            ]

            host = Host(
                id = host_data["id"],
                hostname = host_data["hostname"],
                ip = host_data["ip"],
                role = host_data["role"],
                value = host_data.get("value", 0),
                services = services,
                vulnerabilities = host_data.get("vulnerabilities", []),
                loot = host_data.get("loot", [])
            )

            hosts[host.id] = host

        return hosts
    
    def get_host(self, host_id: str) -> Host | None:
        return self.hosts.get(host_id)
    
    def all_hosts(self) -> list[Host]:
        return list(self.hosts.values())