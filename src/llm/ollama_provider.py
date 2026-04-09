import json
import openai

from src.config import Config
from src.logger import get_logger
from src.llm.base import LLMProvider, LLMResponse, ToolCall

from src.llm.prompts import SYSTEM_PROMPT

logger = get_logger(__name__)

class OllamaProvider(LLMProvider):
    """
    LLM provider backed by a locally running Ollama instance.
    Ollama exposes an OpenAI-compatible /v1 API, so we reuse the OpenAI SDK
    pointed at localhost — no API key needed.

    Prerequisites:
        ollama serve          # start the server
        ollama pull llama3.1  # or any model that supports tool calling
    """

    def __init__(self):
        # OpenAI SDK accepts a custom base_url + dummy api_key for Ollama
        self._client = openai.OpenAI(
            base_url=Config.OLLAMA_BASE_URL,
            api_key="ollama",  # Ollama ignores this, but the SDK requires a non-empty value
        )
        self._model = Config.OLLAMA_MODEL

    def get_provider_name(self) -> str:
        return f"Ollama ({self._model})"

    def chat(self, messages: list[dict], tools: list[dict]) -> LLMResponse:
        logger.debug(f"Sending {len(messages)} messages to Ollama at {Config.OLLAMA_BASE_URL}")

        ollama_messages = [{"role": "system", "content": SYSTEM_PROMPT}] + messages
        ollama_tools = [self._to_openai_tool(t) for t in tools]

        response = self._client.chat.completions.create(
            model=self._model,
            messages=ollama_messages,
            tools=ollama_tools,
        )

        return self._parse_response(response)

    def _to_openai_tool(self, tool: dict) -> dict:
        return {
            "type": "function",
            "function": {
                "name": tool["name"],
                "description": tool["description"],
                "parameters": tool["input_schema"],
            },
        }

    def _parse_response(self, response) -> LLMResponse:
        message = response.choices[0].message
        tool_calls = []

        if message.tool_calls:
            for tc in message.tool_calls:
                try:
                    arguments = json.loads(tc.function.arguments)
                except json.JSONDecodeError:
                    # Some local models return malformed JSON — fail gracefully
                    logger.warning(f"Could not parse tool arguments: {tc.function.arguments}")
                    arguments = {}

                tool_calls.append(ToolCall(
                    id=tc.id,
                    name=tc.function.name,
                    arguments=arguments,
                ))

        raw_message = message.model_dump() if message.tool_calls else None  # ← add this

        return LLMResponse(
            content=message.content or "",
            tool_calls=tool_calls,
            raw_assistant_message=raw_message,  # ← and this
        )