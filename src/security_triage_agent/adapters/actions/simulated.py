"""Deterministic simulation that performs no external or host action."""

from security_triage_agent.application.ports.executors import ActionExecutionResult
from security_triage_agent.domain.actions import ActionProposal


class SimulatedActionExecutor:
    mode = "SIMULATED"

    def execute(self, action: ActionProposal) -> ActionExecutionResult:
        return ActionExecutionResult(
            mode=self.mode,
            outcome="SIMULATED_SUCCESS",
            details={
                "action_id": action.action_id,
                "catalog_action_id": action.catalog_action_id,
                "message": "Simulation completed; no real remediation was attempted.",
            },
        )
