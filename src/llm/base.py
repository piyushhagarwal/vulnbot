from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class ToolCall:
    """Represents a single tool invocation requested by the LLM."""
    id: str
    name: str
    arguments: dict


@dataclass
class LLMResponse:
    """
    Unified response object returned by every LLM provider.
    
    If tool_calls is non-empty, the agent should execute them and loop.
    If tool_calls is empty, content is the final answer for the user.
    """
    content: str
    tool_calls: list[ToolCall] = field(default_factory=list)

    @property
    def is_final_answer(self) -> bool:
        return len(self.tool_calls) == 0


class LLMProvider(ABC):
    """
    Abstract base that every LLM provider must implement.
    
    Concrete providers: OpenAIProvider, OllamaProvider.
    The agent loop only talks to this interface, it never knows which LLM is running.
    """

    @abstractmethod
    def chat(self, messages: list[dict], tools: list[dict]) -> LLMResponse:
        """
        Send a conversation to the LLM and return its response.

        Args:
            messages: Full conversation history in OpenAI-style format:
                      [{"role": "user"|"assistant"|"tool", "content": "..."}]
            tools:    Tool definitions in the provider's expected schema format.

        Returns:
            LLMResponse with either tool_calls (keep looping) or final content.
        """
        ...

    @abstractmethod
    def get_provider_name(self) -> str:
        """Human-readable name shown in the CLI header."""
        ...