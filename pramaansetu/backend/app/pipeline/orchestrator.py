import logging
from app.agents import MultiAgentOrchestrator

logger = logging.getLogger(__name__)

orchestrator_instance = MultiAgentOrchestrator()

async def run_verification_pipeline(verification_id: str, db=None) -> dict:
    """
    Executes multi-agent verification pipeline via app.agents 9-agent architecture.
    """
    logger.info(f"Delegating verification process for {verification_id} to MultiAgentOrchestrator")
    return await orchestrator_instance.run_pipeline(verification_id, db)
