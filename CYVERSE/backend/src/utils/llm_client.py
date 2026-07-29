import os
import json
import re
import logging
from typing import Optional, Dict, Any

from src.cyberverse_orchestrator.credentials_vault import resolve_secret

logger = logging.getLogger(__name__)

try:
    from litellm import completion
    HAS_LITELLM = True
except ImportError:
    HAS_LITELLM = False

DEFAULT_MODEL = "llama-3.3-70b-versatile"

_ENV_KEY_PRIORITY = ["GROQ_API_KEY", "OPENAI_API_KEY", "GROK_API_KEY", "XAI_API_KEY"]

_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*\})\s*```", re.DOTALL)


def _resolve_api_key(credential_id: Optional[str]) -> tuple[Optional[str], str]:
    """Returns (api_key, source_label)."""
    if credential_id:
        secret = resolve_secret(credential_id)
        if secret and secret.get("_type") in ("groq_api_key", "generic_api_key") and secret.get("api_key"):
            return secret["api_key"], f"credential:{credential_id}"
        logger.warning(f"Could not resolve usable API key from credential_id={credential_id}; falling back to env.")

    for env_var in _ENV_KEY_PRIORITY:
        value = os.getenv(env_var)
        if value:
            return value, "env-default"

    return None, "unavailable"


def _extract_json(content: str) -> Optional[dict]:
    content = content.strip()
    try:
        return json.loads(content)
    except (json.JSONDecodeError, ValueError):
        pass

    fence_match = _JSON_FENCE_RE.search(content)
    if fence_match:
        try:
            return json.loads(fence_match.group(1))
        except (json.JSONDecodeError, ValueError):
            pass

    brace_start = content.find("{")
    brace_end = content.rfind("}")
    if brace_start != -1 and brace_end > brace_start:
        try:
            return json.loads(content[brace_start:brace_end + 1])
        except (json.JSONDecodeError, ValueError):
            pass

    return None


def run_llm_agent(
    system_prompt: str,
    user_prompt: str,
    credential_id: Optional[str] = None,
    model: str = DEFAULT_MODEL,
    max_tokens: int = 700,
    expect_json: bool = True,
) -> Dict[str, Any]:
    """Runs one LLM completion for a cybersecurity agent's reasoning step.

    Never raises. Always returns an envelope: {"ok", "content", "source", "error"}.
    Callers should merge `content` over their own heuristic result only when `ok` is True,
    keeping the heuristic result untouched otherwise (fail-soft by design).
    """
    if not HAS_LITELLM:
        return {"ok": False, "content": None, "source": "unavailable", "error": "litellm not installed"}

    api_key, source = _resolve_api_key(credential_id)
    if not api_key:
        return {"ok": False, "content": None, "source": "unavailable", "error": "no API key available (no credential_id and no env key configured)"}

    resolved_model = model or DEFAULT_MODEL

    try:
        response = completion(
            model=f"groq/{resolved_model}",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            api_key=api_key,
            max_tokens=max_tokens,
        )
        raw_content = response.choices[0].message.content.strip()
    except Exception as e:
        logger.warning(f"LLM call failed (source={source}): {e}")
        return {"ok": False, "content": None, "source": source, "error": str(e)}

    if not expect_json:
        return {"ok": True, "content": raw_content, "source": source, "error": None}

    parsed = _extract_json(raw_content)
    if parsed is None:
        return {"ok": False, "content": raw_content, "source": source, "error": "json_parse_failed"}

    return {"ok": True, "content": parsed, "source": source, "error": None}
