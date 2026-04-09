import json
import openai

from src.config import Config
from src.logger import get_logger
from src.llm.base import LLMProvider, LLMResponse, ToolCall

from src.llm.prompts import SYSTEM_PROMPT

logger = get_logger(__name__)

class OpenAIProvider(LLMProvider):
    """LLM provider backed by OpenAI GPT models."""

    def __init__(self):
        if not Config.OPENAI_API_KEY:
            raise ValueError("OPENAI_API_KEY is not set in your .env file")
        self._client = openai.OpenAI(api_key=Config.OPENAI_API_KEY)
        self._model = Config.OPENAI_MODEL

    def get_provider_name(self) -> str:
        return f"OpenAI ({self._model})"

    def chat(self, messages: list[dict], tools: list[dict]) -> LLMResponse:
        logger.debug(f"Sending {len(messages)} messages to OpenAI")

        openai_messages = [{"role": "system", "content": SYSTEM_PROMPT}] + messages
        openai_tools = [self._to_openai_tool(t) for t in tools]

        response = self._client.chat.completions.create(
            model=self._model,
            messages=openai_messages,
            tools=openai_tools,
        )

        return self._parse_response(response)

    def _to_openai_tool(self, tool: dict) -> dict:
        """Convert our generic tool definition to OpenAI's format."""
        return {
            "type": "function",
            "function": {
                "name": tool["name"],
                "description": tool["description"],
                "parameters": tool["input_schema"],
            },
        }

    def _parse_response(self, response) -> LLMResponse:
        """Extract text and/or tool calls from OpenAI's response."""
        message = response.choices[0].message
        tool_calls = []

        if message.tool_calls:
            for tc in message.tool_calls:
                tool_calls.append(ToolCall(
                    id=tc.id,
                    name=tc.function.name,
                    arguments=json.loads(tc.function.arguments),
                ))
                
        raw_message = message.model_dump() if message.tool_calls else None  # ← this line

        return LLMResponse(
            content=message.content or "",
            tool_calls=tool_calls,
            raw_assistant_message=raw_message,
        )