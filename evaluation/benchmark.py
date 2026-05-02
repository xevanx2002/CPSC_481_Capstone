"""

Comparative benchmark harness for VectorForge.

Runs the same scenario through three different decision strategies
and reports actions, cost, success, and search effort. Used as
quantitative evidence in the technical report and capstone demo.

Strategies:

- a_star : the real planner (agent/planner.py)
- greedy : pick the cheapest legal action at each step
- random : pick any legal action at random (deterministic seed)

Execution uses MockExecutor for speed and repeatability. The benchmark
is about decision quality, not network behavior.

CLI:

    python -m evaluation.benchmark
    python -m evaluation.benchmark --runs 10

"""

import argparse
import json
import random
import time
from pathlib import Path

from agent.action_generator import legal_actions
from agent.planner import is_goal, plan
from agent.transition import ACTION_COSTS, apply_action
from core.actions import Action
from core.state import State
from executors import MockExecutor
from executors.runner import _initial_runtime_state, _merge_observed


_SCENARIOS = [
    "scenarios/simple_network.json",
    "scenarios/medium_network.json",
]


def _load_scenario(path: str) -> dict:
    return json.loads(Path(path).read_text())


# strategy plugs: take (runtime_state, scenario, excluded) and return
# the next Action to try, or None if no action is reachable
def _astar_strategy(runtime, scenario, excluded, stats):
    plan_result = plan(scenario, start=runtime, excluded_actions=excluded, stats=stats)
    if plan_result is None:
        return None
    remaining = plan_result.actions_taken[len(runtime.actions_taken):]
    if not remaining:
        return None
    return remaining[0]


def _greedy_strategy(runtime, scenario, excluded, _stats):
    legal = [a for a in legal_actions(runtime, scenario) if a not in excluded]
    if not legal:
        return None
    return min(legal, key=lambda a: ACTION_COSTS.get(a.name, 99))


def _random_strategy_factory(seed: int):
    rng = random.Random(seed)

    def _pick(runtime, scenario, excluded, _stats):
        legal = [a for a in legal_actions(runtime, scenario) if a not in excluded]
        if not legal:
            return None
        return rng.choice(legal)

    return _pick


def _run_strategy(strategy, scenario: dict, max_actions: int = 60) -> dict:
    """

    Run a single strategy against a scenario using MockExecutor.
    Returns stats dict with success, actions, cost, planning_time_s, nodes_expanded.

    """
    runtime = _initial_runtime_state(scenario)
    executor = MockExecutor()
    excluded = set()
    actions_taken = 0
    cost = 0
    nodes_expanded_total = 0
    plan_time_total = 0.0

    for _ in range(max_actions):
        if is_goal(runtime, scenario):
            break

        plan_stats: dict = {}
        t0 = time.perf_counter()
        action = strategy(runtime, scenario, excluded, plan_stats)
        plan_time_total += time.perf_counter() - t0

        nodes_expanded_total += plan_stats.get("nodes_expanded", 0)

        if action is None:
            break

        result = executor.execute(action, runtime, scenario)
        actions_taken += 1
        cost += ACTION_COSTS.get(action.name, 0)

        if result.success:
            _merge_observed(runtime, action, result)
            runtime.actions_taken.append(action)
        else:
            excluded.add(action)

    return {
        "success": is_goal(runtime, scenario),
        "actions": actions_taken,
        "cost": cost,
        "plan_time_s": round(plan_time_total, 4),
        "nodes_expanded": nodes_expanded_total,
        "compromised_count": len(runtime.compromised_hosts),
    }


def run_benchmark(scenarios=None, random_runs: int = 5, random_seed: int = 42):
    if scenarios is None:
        scenarios = _SCENARIOS

    rows = []
    for scenario_path in scenarios:
        scenario = _load_scenario(scenario_path)
        scenario_name = Path(scenario_path).stem

        # a_star and greedy are deterministic so one run each is enough
        astar = _run_strategy(_astar_strategy, scenario)
        greedy = _run_strategy(_greedy_strategy, scenario)

        # random gets averaged across multiple runs to smooth noise
        random_results = []
        for i in range(random_runs):
            seeded = _random_strategy_factory(random_seed + i)
            random_results.append(_run_strategy(seeded, scenario))

        random_avg = {
            "success_rate": sum(1 for r in random_results if r["success"]) / len(random_results),
            "actions": sum(r["actions"] for r in random_results) / len(random_results),
            "cost": sum(r["cost"] for r in random_results) / len(random_results),
            "plan_time_s": sum(r["plan_time_s"] for r in random_results) / len(random_results),
        }

        rows.append({
            "scenario": scenario_name,
            "astar": astar,
            "greedy": greedy,
            "random": random_avg,
            "random_runs": random_runs,
        })

    return rows


def format_markdown_table(rows: list[dict]) -> str:
    lines = []
    lines.append("# VectorForge Benchmark Results")
    lines.append("")
    lines.append("Same scenario, three decision strategies. MockExecutor for repeatability.")
    lines.append("")
    lines.append("| scenario | strategy | success | actions | cost | plan time (s) | nodes expanded |")
    lines.append("|---|---|---|---|---|---|---|")
    for row in rows:
        s = row["astar"]
        lines.append(
            f"| {row['scenario']} | a_star | "
            f"{'YES' if s['success'] else 'NO'} | "
            f"{s['actions']} | {s['cost']} | "
            f"{s['plan_time_s']} | {s['nodes_expanded']} |"
        )
        g = row["greedy"]
        lines.append(
            f"| {row['scenario']} | greedy | "
            f"{'YES' if g['success'] else 'NO'} | "
            f"{g['actions']} | {g['cost']} | "
            f"{g['plan_time_s']} | n/a |"
        )
        r = row["random"]
        lines.append(
            f"| {row['scenario']} | random (avg of {row['random_runs']}) | "
            f"{int(r['success_rate'] * 100)}% | "
            f"{r['actions']:.1f} | {r['cost']:.1f} | "
            f"{r['plan_time_s']:.4f} | n/a |"
        )
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        prog="vectorforge-benchmark",
        description="Compare A*, greedy, and random decision strategies on the scenario set.",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=5,
        help="number of random-strategy runs per scenario (averaged) (default: 5)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="random seed base (default: 42)",
    )
    parser.add_argument(
        "scenarios",
        nargs="*",
        help="scenario JSON paths (default: simple_network and medium_network)",
    )
    args = parser.parse_args()

    scenarios = args.scenarios if args.scenarios else None
    rows = run_benchmark(scenarios=scenarios, random_runs=args.runs, random_seed=args.seed)
    print(format_markdown_table(rows))


if __name__ == "__main__":
    main()
