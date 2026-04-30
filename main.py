import sys

from evaluation.runner import run_evaluation, run_live
from evaluation.report import print_live_report, print_report

def main():
    args = [a for a in sys.argv[1:] if a]
    live = "--live" in args
    args = [a for a in args if a != "--live"]

    scenario_path = args[0] if args else "scenarios/simple_network.json"

    if live:
        scenario, runtime_state, log, score = run_live(scenario_path)
        print_live_report(scenario, runtime_state, log, score)
    else:
        scenario, result, score = run_evaluation(scenario_path)
        print_report(scenario, result, score)

if __name__ == "__main__":
    main()