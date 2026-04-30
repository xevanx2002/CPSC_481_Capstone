from core.actions import Action
from core.state import State
from executors.base import ExecutionResult, Executor


class HybridExecutor:
    """Try `primary` first; on `not_implemented` errors fall back to `fallback`.

    Lets the agent run end-to-end against a real target even when only a few
    actions have real backends — e.g. real nmap for recon, mock for everything
    downstream during a dry-run.
    """

    def __init__(self, primary: Executor, fallback: Executor):
        self.primary = primary
        self.fallback = fallback

    def execute(self, action: Action, state: State, scenario: dict) -> ExecutionResult:
        result = self.primary.execute(action, state, scenario)
        if not result.success and result.error == "not_implemented":
            return self.fallback.execute(action, state, scenario)
        return result
