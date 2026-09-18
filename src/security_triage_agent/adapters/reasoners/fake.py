"""Deterministic scripted reasoner with no external capabilities."""

from collections.abc import Iterable
from typing import cast

from security_triage_agent.application.orchestration_contracts import ReasonerContext, ReasonerStep


class FakeReasoner:
    def __init__(self, script: Iterable[object]) -> None:
        self._script = iter(script)
        self.contexts: list[ReasonerContext] = []

    def next_step(self, context: ReasonerContext) -> ReasonerStep:
        self.contexts.append(context)
        step = next(self._script)
        if isinstance(step, BaseException):
            raise step
        return cast(ReasonerStep, step)
