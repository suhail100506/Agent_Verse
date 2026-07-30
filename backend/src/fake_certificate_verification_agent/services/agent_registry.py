import logging
from typing import Dict, Optional, List
from src.fake_certificate_verification_agent.models.base_agent import BaseAgent

logger = logging.getLogger(__name__)


class AgentRegistry:
    """Registry for registering and looking up verification agents."""

    def __init__(self):
        self._agents: Dict[str, BaseAgent] = {}

    def register(self, agent: BaseAgent):
        self._agents[agent.agent_id] = agent
        logger.info(f"Registered agent '{agent.agent_id}' ({agent.__class__.__name__})")

    def get(self, agent_id: str) -> Optional[BaseAgent]:
        return self._agents.get(agent_id)

    def list_agent_ids(self) -> List[str]:
        return list(self._agents.keys())
