from agent.transition import apply_action
from core.state import State
from core.actions import Action

class Simulator:
    def __init__(self, scenario: dict):
        self.scenario = scenario
        self.state = State()

    def execute(self, action: Action) -> bool:
        next_state = apply_action(self.state, action, self.scenario)

        if next_state is None:
            return False
        
        self.state = next_state
        return True
    
    def get_state(self) -> State:
        return self.state