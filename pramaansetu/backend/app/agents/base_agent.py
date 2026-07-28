import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class BaseVerificationAgent(ABC):
    """
    Abstract Base Class for Autonomous Verification Agents in PramaanSetu.
    Every agent encapsulates a specialized forensic or analytical verification stage.
    """
    def __init__(self, agent_name: str, agent_id: str, description: str):
        self.agent_name = agent_name
        self.agent_id = agent_id
        self.description = description
        self.logger = logging.getLogger(f"agent.{agent_id}")

    @abstractmethod
    async def process(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes the agent's specific verification logic.
        :param context: Dictionary containing global verification context (file path, DB reference, previous stage outputs).
        :return: Agent output result dictionary.
        """
        pass

    def log_info(self, message: str):
        self.logger.info(f"[{self.agent_name}] {message}")

    def log_error(self, message: str, exc: Optional[Exception] = None):
        self.logger.error(f"[{self.agent_name}] {message}", exc_info=exc)
