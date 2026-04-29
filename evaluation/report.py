def print_report(scenario: dict, result, score: int):
    print("VectorForge Evaluation Report")
    print()

    if result is None:
        print("No plan found.")
        print(f"Final Score: {score}")
        return
    
    print(f"Compromised Hosts: {sorted(result.compromised_hosts)}")
    print(f"Total cost: {result.total_cost}")
    print(f"Credentials Found: {len(result.creds_found)}")
    print(f"Final Score: {score}")
    print()

    print("Discovered Vulnerabilities: ")
    for host in scenario.get("hosts", []):
        host_id = host["id"]
        vulns = result.discovered_vulns.get(host_id, set())

        for vuln in host.get("vulnerabilities", []):
            if vuln["id"] in vulns:
                print(f"- {host_id}: {vuln['id']} ({vuln['severity']})")

    print()
    print("Action Sequence: ")
    for i, action in enumerate(result.actions_taken, 1):
        print(f"{i}. {action}")