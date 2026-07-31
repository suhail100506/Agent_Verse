from abc import ABC, abstractmethod
from src.fake_certificate_verification_agent.models.workflow_context import WorkflowContext, AgentResult


class BaseAgent(ABC):
    """Abstract base class for all AI verification agents."""

    agent_id: str = "base_agent"

    @abstractmethod
    def execute(self, context: WorkflowContext) -> AgentResult:
        """Executes agent logic taking WorkflowContext and returning AgentResult."""
        pass
