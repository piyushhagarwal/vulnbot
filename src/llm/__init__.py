from src.config import Config
from src.llm.base import LLMProvider


def get_llm_provider() -> LLMProvider:
    """
    Factory — returns the LLM provider configured in .env.
    Swap LLM_PROVIDER=anthropic|openai|ollama to change providers.
    """
    provider = Config.LLM_PROVIDER.lower()

    if provider == "openai":
        from src.llm.openai_provider import OpenAIProvider
        return OpenAIProvider()
    elif provider == "ollama":
        from src.llm.ollama_provider import OllamaProvider
        return OllamaProvider()

    raise ValueError(
        f"Unknown LLM_PROVIDER '{provider}'. "
        "Valid options: anthropic, openai, ollama"
    )