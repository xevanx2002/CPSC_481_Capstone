from dataclasses import dataclass, field
from typing import Any, Protocol

from core.actions import Action
from core.state import State


@dataclass
class ExecutionResult:
    action: Action
    success: bool
    observed: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    artifacts: dict[str, Any] = field(default_factory=dict)
    raw: str = ""

    def __str__(self) -> str:
        tag = "OK" if self.success else f"FAIL({self.error})"
        return f"[{tag}] {self.action}"


class Executor(Protocol):
    def execute(
        self, action: Action, state: State, scenario: dict
    ) -> ExecutionResult: ...
