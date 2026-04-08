import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    # LLM Provider: "openai", or "ollama"
    LLM_PROVIDER: str = os.getenv("LLM_PROVIDER", "openai")

    # OpenAI
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-5.2")

    # Ollama — runs locally, no API key needed
    # Ollama exposes an OpenAI-compatible API at /v1, so we reuse the OpenAI SDK
    OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
    OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "llama3.1")

    # NVD
    NVD_API_KEY: str = os.getenv("NVD_API_KEY", "")
    NVD_BASE_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_RATE_LIMIT_DELAY: float = 6.0 if not os.getenv("NVD_API_KEY") else 0.6

    # MITRE
    MITRE_STIX_URL: str = (
        "https://raw.githubusercontent.com/mitre/cti/master/"
        "enterprise-attack/enterprise-attack.json"
    )
    MITRE_CACHE_FILE: str = ".mitre_cache.json"

    # Agent
    MAX_AGENT_ITERATIONS: int = int(os.getenv("MAX_AGENT_ITERATIONS", "10"))

    # Logging
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")