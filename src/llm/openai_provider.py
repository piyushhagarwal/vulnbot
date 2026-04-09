import json
import openai

from config import Config
from logger import get_logger
from llm.base import LLMProvider, LLMResponse, ToolCall

logger = get_logger(__name__)

SYSTEM_PROMPT = (
    "You are a cybersecurity expert assistant specializing in vulnerability analysis. "
    "You have access to tools that query the National Vulnerability Database (NVD) "
    "and MITRE ATT&CK framework. "
    "Use them as many times as needed to give a thorough, accurate answer. "
    "When you have enough information, respond clearly and concisely to the user."
)


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

        return LLMResponse(
            content=message.content or "",
            tool_calls=tool_calls,
        )