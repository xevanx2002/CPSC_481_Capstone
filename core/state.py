class State:
    def __init__(self):
        self.discovered_hosts = []
        self.open_ports = {}
        self.vulnerabilities = {}
        self.credentials = []