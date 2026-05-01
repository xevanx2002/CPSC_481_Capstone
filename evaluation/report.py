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


def print_live_report(scenario: dict, runtime_state, log, score: int):
    print("VectorForge Live Run Report")
    print()

    print(f"Compromised Hosts: {sorted(runtime_state.compromised_hosts)}")
    footholds = sorted(getattr(runtime_state, "footholds", set()) - runtime_state.compromised_hosts)
    if footholds:
        print(f"Web-shell Footholds: {footholds}")
    print(f"Credentials Found: {len(runtime_state.creds_found)}")
    print(f"Final Score: {score}")
    print()

    print("Per-action results:")
    for i, entry in enumerate(log, 1):
        # not_implemented = executor doesn't support this action yet so not a real
        # failure on the target. show it as SKIP (for now until we put it in)
        if entry.success:
            tag = "OK"
        elif entry.error == "not_implemented":
            tag = "SKIP(not_implemented)"
        else:
            tag = f"FAIL({entry.error})"
        artifact_note = ""
        if entry.success and entry.artifacts:
            shell_url = entry.artifacts.get("shell_url")
            if shell_url:
                artifact_note = f"  -> {shell_url}"
        print(f"{i:>2}. [{tag}] {entry.action}{artifact_note}")

    print()
    print("Raw output (per failed action):")
    for entry in log:
        if entry.success or not entry.raw:
            continue
        print(f"--- {entry.action} ---")
        print(entry.raw)
        print()

    # outcome banner
    GREEN = "\033[1;32m"
    ORANGE = "\033[38;5;208m"  # 256-color orange
    RED = "\033[1;31m"
    RESET = "\033[0m"
    successes = sum(1 for e in log if e.success)
    skipped = sum(1 for e in log if not e.success and e.error == "not_implemented")
    failed = sum(1 for e in log if not e.success and e.error != "not_implemented")

    if runtime_state.compromised_hosts:
        tag = f"{GREEN}[+] objective met"
        detail = f"full compromise on {sorted(runtime_state.compromised_hosts)}"
    elif getattr(runtime_state, "footholds", set()):
        tag = f"{ORANGE}[~] partial objective"
        detail = f"web-shell foothold on {sorted(runtime_state.footholds)}"
    else:
        tag = f"{RED}[-] objective failed"
        detail = "no foothold or compromise — see failures above"
    counts = f"{successes} successful"
    if skipped:
        counts += f"  ·  {skipped} skipped"
    if failed:
        counts += f"  ·  {failed} failed"
    print(f"{tag}  ·  {detail}  ·  {counts}{RESET}")