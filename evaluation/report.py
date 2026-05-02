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

    _print_loot_summary(runtime_state, scenario)

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


# show what the agent actually stole, not just counts
def _print_loot_summary(runtime_state, scenario: dict):
    creds = runtime_state.creds_found
    shell_urls = getattr(runtime_state, "shell_urls", {})
    discovered_vulns = runtime_state.discovered_vulns
    access_levels = runtime_state.access_levels
    loot = getattr(runtime_state, "loot", {})

    has_anything = creds or shell_urls or discovered_vulns or access_levels or loot
    if not has_anything:
        return

    CYAN = "\033[36m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    print(f"{CYAN}─────────── Loot Summary ───────────{RESET}")

    if creds:
        print(f"Credentials ({len(creds)}):")
        for c in creds:
            print(
                f"  - {c.username} / {c.password}  "
                f"{DIM}(access={c.access}, source={c.source}, "
                f"confidence={c.confidence}){RESET}"
            )

    if shell_urls:
        print("Shell URLs:")
        for host, url in sorted(shell_urls.items()):
            print(f"  - {host}  ->  {url}")

    if discovered_vulns:
        # build a vuln_id -> severity lookup from scenario + KB
        from knowledge.vuln_kb import RULES
        sev_lookup = {r["id"]: r.get("severity", "?") for r in RULES}
        for host in scenario.get("hosts", []):
            for v in host.get("vulnerabilities", []):
                sev_lookup[v["id"]] = v.get("severity", "?")

        print("Vulnerabilities Identified:")
        for host_id, vuln_ids in sorted(discovered_vulns.items()):
            entries = ", ".join(
                f"{vid} ({sev_lookup.get(vid, '?')})" for vid in sorted(vuln_ids)
            )
            print(f"  - {host_id}: {entries}")

    if access_levels:
        print("Access Achieved:")
        for host_id, level in sorted(access_levels.items()):
            print(f"  - {host_id}: {level}")

    if loot:
        any_files = any(files for files in loot.values())
        if any_files:
            # trims long contents to first line / 64 chars. flag files are
            # usually one line MD5 hashes so this preserves them, longer
            # files get a preview.
            print("Captured Files:")
            for host_id, files in sorted(loot.items()):
                for path, content in sorted(files.items()):
                    preview = (content or "").strip().splitlines()
                    head = preview[0] if preview else "<empty>"
                    if len(head) > 64:
                        head = head[:61] + "..."
                    print(f"  - {host_id}:{path}  ->  {head}")

    print()