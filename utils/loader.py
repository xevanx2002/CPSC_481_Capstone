import json


def load_scenario(path):
    with open(path, "r") as f:
        return json.load(f)