from core.actions import Action
from core.state import Credential, State
from agent.action_generator import legal_actions
from agent.planner import is_goal, plan
from agent.transition import ACTION_COSTS
from executors.base import ExecutionResult, Executor

"""
This runs during a live run when an executor actually performs the scan
"""

def _initial_runtime_state(scenario: dict) -> State:
    state = State()
    for h in scenario.get("hosts", []):
        if h.get("exposure", "external") == "external":
            state.reachable_hosts.add(h["id"])
    return state


def _merge_observed(state: State, action: Action, result: ExecutionResult) -> None:
    obs = result.observed
    host = action.target_host

    if obs.get("host_alive"):
        state.discovered_hosts.add(host)
        state.reachable_hosts.add(host)

    if "open_ports" in obs:
        state.scanned_hosts.add(host)
        state.discovered_hosts.add(host)
        state.open_ports[host] = list(obs["open_ports"])
        state.discovered_services[host] = dict(obs.get("services", {}))

    if "paths" in obs:
        state.discovered_paths.setdefault(host, set()).update(obs["paths"])

    if "vulns" in obs:
        state.discovered_vulns.setdefault(host, set()).update(obs["vulns"])

    if "access_level" in obs:
        state.access_levels[host] = obs["access_level"]
        if obs["access_level"] == "web_shell":
            state.footholds.add(host)

    if obs.get("compromised"):
        state.compromised_hosts.add(host)

    for cred in obs.get("creds", []):
        state.creds_found.append(Credential(**cred))

    for reachable in obs.get("reachable", []):
        state.reachable_hosts.add(reachable)


def execute_plan(
    planned: State,
    scenario: dict,
    executor: Executor,
    stop_on_failure: bool = True,
) -> tuple[State, list[ExecutionResult]]:
    """
    Walk planned.actions_taken and dispatch each to the executor

    Builds a fresh runtime State from observed results - 
    Does NOT trust the planner's predicted state
    Returns (runtime_state, log).
    """
    runtime = _initial_runtime_state(scenario)
    log: list[ExecutionResult] = []

    for action in planned.actions_taken:
        result = executor.execute(action, runtime, scenario)
        log.append(result)
        if result.success:
            _merge_observed(runtime, action, result)
            runtime.actions_taken.append(action)
        elif stop_on_failure:
            break

    return runtime, log


def execute_with_replan(
    scenario: dict,
    executor: Executor,
    max_failures: int = 8,
) -> tuple[State, list[ExecutionResult]]:
    """
    Plan-execute-observe-replan loop

    Plans from current runtime state -> executes the next action -> merges
    observations -> replans
    Failed actions are excluded from future planning so A* finds an alternative route
    Stops when the goal is reached or no plan exists or max_failures is exhausted
    """
    runtime = _initial_runtime_state(scenario)
    log: list[ExecutionResult] = []
    excluded: set[Action] = set()
    failures = 0

    while not is_goal(runtime, scenario):
        plan_result = plan(scenario, start=runtime, excluded_actions=excluded)

        next_action = None
        if plan_result is not None:
            remaining = plan_result.actions_taken[len(runtime.actions_taken) :]
            if remaining:
                next_action = remaining[0]

        if next_action is None:
            # planner can't see a goal-reaching path. happens in discover mode
            # before recon populates state, or after enough failures cut off
            # all known routes. fall back to cheapest legal forward action so
            # execution still makes progress; next iteration's plan() may find
            # a real path once observations come in.
            legal = [
                a for a in legal_actions(runtime, scenario) if a not in excluded
            ]
            if not legal:
                break
            next_action = min(legal, key=lambda a: ACTION_COSTS.get(a.name, 99))
        result = executor.execute(next_action, runtime, scenario)
        log.append(result)

        if result.success:
            _merge_observed(runtime, next_action, result)
            runtime.actions_taken.append(next_action)
        else:
            excluded.add(next_action)
            failures += 1
            if failures > max_failures:
                break

    return runtime, log
