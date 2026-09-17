"""Domain-specific errors."""

from enum import StrEnum


class InvalidStateTransitionError(ValueError):
    """Raised when a lifecycle transition is not permitted."""

    def __init__(self, lifecycle: str, current: StrEnum, target: StrEnum) -> None:
        super().__init__(f"invalid {lifecycle} transition: {current.value} -> {target.value}")
        self.lifecycle = lifecycle
        self.current = current
        self.target = target
