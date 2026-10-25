# Local-only AI subsystem — no external API keys required.
# Primary backend: Ollama (http://localhost:11434).
# Fallback: deterministic rule-based analysis when Ollama is unavailable.
from ai.local_llm import LocalLLM, llm

__all__ = ["LocalLLM", "llm"]
