import json

from pathlib import Path
from agent.planner import plan
from evaluation.metrics import score_result

IP_PLACEHOLDER = "REPLACE_WITH_HTB_IP"


def _resolve_unknown_ips(scenario: dict, target_override: str | None = None) -> None:
    """
    Fill in any host IP left as a placeholder.

    HTB box IPs change per-session and per-teammate so the bootstrap
    scenario file ships without one. 
    
    If `target_override` is given, all placeholder hosts use it (scripted/demo runs). 
    If not we prompt the operator interactively
    """
    for host in scenario.get("hosts", []):
        if host.get("ip") == IP_PLACEHOLDER:
            label = host.get("hostname") or host.get("id") or "target"
            if target_override:
                host["ip"] = target_override
                continue
            ip = input(f"Enter target IP for {label}: ").strip()
            if not ip:
                raise SystemExit(f"No IP provided for {label}; aborting.")
            host["ip"] = ip


def run_evaluation(scenario_path: str, target_override: str | None = None):
    path = Path(scenario_path)
    scenario = json.loads(path.read_text())
    _resolve_unknown_ips(scenario, target_override)
    result = plan(scenario)
    score = score_result(result, scenario)

    return scenario, result, score


def run_live(scenario_path: str, target_override: str | None = None):
    # plan and execute against a real target
    # Uses RealExecutor only so unimplemented 
    # actions surface as honest failures instead of being
    # silently filled in with mock data
    from executors import RealExecutor, execute_with_replan

    path = Path(scenario_path)
    scenario = json.loads(path.read_text())
    _resolve_unknown_ips(scenario, target_override)

    runtime_state, log = execute_with_replan(scenario, RealExecutor())
    score = score_result(runtime_state, scenario)

    return scenario, runtime_state, log, score