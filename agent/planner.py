import heapq
from dataclasses import dataclass, field
from typing import Optional

from core.state import State
from agent.action_generator import legal_actions
from agent.transition import apply_action
from agent.heuristic import heuristic


@dataclass(order=True)
class _Node:
    f: int
    counter: int
    state: State = field(compare=False)


def is_goal(state: State, scenario: dict) -> bool:
    target_hosts = {h["id"] for h in scenario.get("hosts", [])}
    return target_hosts.issubset(state.compromised_hosts)


def plan(
    scenario: dict,
    start: Optional[State] = None,
    excluded_actions: Optional[set] = None,
) -> Optional[State]:
    if start is None:
        start = State()
        for host in scenario.get("hosts", []):
            if host.get("exposure", "external") == "external":
                start.reachable_hosts.add(host["id"])

    if is_goal(start, scenario):
        return start

    excluded = excluded_actions or set()

    counter = 0
    frontier: list[_Node] = []
    heapq.heappush(
        frontier,
        _Node(f=heuristic(start, scenario), counter=counter, state=start),
    )

    best_g: dict = {start.signature(): start.total_cost}

    while frontier:
        node = heapq.heappop(frontier)
        state = node.state

        if is_goal(state, scenario):
            return state

        sig = state.signature()
        if state.total_cost > best_g.get(sig, state.total_cost):
            continue

        for action in legal_actions(state, scenario):
            if action in excluded:
                continue
            child = apply_action(state, action, scenario)
            if child is None:
                continue

            child_sig = child.signature()
            if child.total_cost >= best_g.get(child_sig, float("inf")):
                continue

            best_g[child_sig] = child.total_cost
            counter += 1
            f = child.total_cost + heuristic(child, scenario)
            heapq.heappush(frontier, _Node(f=f, counter=counter, state=child))

    return None
