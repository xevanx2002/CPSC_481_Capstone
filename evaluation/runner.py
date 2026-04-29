import json

from pathlib import Path
from agent.planner import plan
from evaluation.metrics import score_result

def run_evaluation(scenario_path: str):
    path = Path(scenario_path)
    scenario = json.loads(path.read_text())
    result = plan(scenario)
    score = score_result(result, scenario)

    return scenario, result, score