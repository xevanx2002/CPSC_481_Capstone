import sys

from evaluation.runner import run_evaluation
from evaluation.report import print_report

def main():
    scenario_path = "scenarios/simple_network.json"

    if len(sys.argv) > 1:
        scenario_path = sys.argv[1]

    scenario, result, score = run_evaluation(scenario_path)
    print_report(scenario, result, score)

if __name__ == "__main__":
    main()