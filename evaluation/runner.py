import json

from pathlib import Path
from agent.planner import plan
from evaluation.metrics import score_result

IP_PLACEHOLDER = "REPLACE_WITH_HTB_IP"


def _resolve_unknown_ips(scenario: dict) -> None:
    """Prompt the operator for any host IP left as a placeholder.

    HTB box IPs change per-session and per-teammate, so the bootstrap
    scenario file ships without one and resolves at runtime.
    """
    for host in scenario.get("hosts", []):
        if host.get("ip") == IP_PLACEHOLDER:
            label = host.get("hostname") or host.get("id") or "target"
            ip = input(f"Enter target IP for {label}: ").strip()
            if not ip:
                raise SystemExit(f"No IP provided for {label}; aborting.")
            host["ip"] = ip


def run_evaluation(scenario_path: str):
    path = Path(scenario_path)
    scenario = json.loads(path.read_text())
    _resolve_unknown_ips(scenario)
    result = plan(scenario)
    score = score_result(result, scenario)

    return scenario, result, score


def run_live(scenario_path: str):
    # plan-and-execute against a real target. uses RealExecutor only so
    # unimplemented actions surface as honest failures instead of being
    # silently filled in with mock data.
    from executors import RealExecutor, execute_with_replan

    path = Path(scenario_path)
    scenario = json.loads(path.read_text())
    _resolve_unknown_ips(scenario)

    runtime_state, log = execute_with_replan(scenario, RealExecutor())
    score = score_result(runtime_state, scenario)

    return scenario, runtime_state, log, score