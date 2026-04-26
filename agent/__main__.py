import argparse
import json
from pathlib import Path

from agent.planner import plan


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="vectorforge-agent",
        description="Run the VectorForge planning agent on a scenario.",
    )
    parser.add_argument(
        "scenario",
        nargs="?",
        default="scenarios/simple_network.json",
        help="Path to a scenario JSON file (default: scenarios/simple_network.json)",
    )
    args = parser.parse_args()

    scenario_path = Path(args.scenario)
    if not scenario_path.exists():
        print(f"scenario not found: {scenario_path}")
        return 1

    scenario = json.loads(scenario_path.read_text())
    result = plan(scenario)

    if result is None:
        print("no plan found")
        return 2

    print(f"scenario: {scenario_path}")
    print(f"hosts compromised: {sorted(result.compromised_hosts)}")
    print(f"total cost: {result.total_cost}")
    print(f"credentials obtained: {len(result.creds_found)}")
    print()
    print("plan:")
    for i, action in enumerate(result.actions_taken, 1):
        print(f"  {i:>2}. {action}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
