"""
Chat Engine — the agentic loop.

Orchestrates the conversation between the user, the LLM, and the tools.
Runs in a loop until the LLM produces a final answer or the iteration
cap is hit (safety guard against infinite loops).

Message history format (neutral, provider-agnostic):
  {"role": "user",      "content": "..."}
  {"role": "assistant", "content": "...", "tool_calls": [...]}  ← when LLM calls tools
  {"role": "tool",      "content": "...", "tool_call_id": "..."} ← tool result
  {"role": "assistant", "content": "..."}                        ← final answer
"""

from src.config import Config
from src.dispatcher import Dispatcher
from src.llm.base import LLMProvider, LLMResponse
from src.logger import get_logger

logger = get_logger(__name__)


class ChatEngine:
    """
    Manages conversation state and runs the agentic tool-calling loop.

    One ChatEngine instance per session — history accumulates across turns.
    """

    def __init__(self, llm: LLMProvider, dispatcher: Dispatcher):
        self._llm        = llm
        self._dispatcher = dispatcher
        self._history: list[dict] = []  # full conversation history, grows each turn
        self._tools = dispatcher.get_tool_definitions()

    # ── public ────────────────────────────────────────────────────────────

    def chat(self, user_message: str) -> str:
        """
        Process a user message through the agentic loop.

        Appends the user message to history, then loops:
          1. Send history + tools to LLM
          2. If LLM wants tool calls → execute them, append results, loop again
          3. If LLM gives final answer → return it

        Args:
            user_message: Raw text from the user.

        Returns:
            The LLM's final answer as a plain string.
        """
        self._history.append({"role": "user", "content": user_message})
        logger.info(f"User: {user_message[:100]}...")

        for iteration in range(1, Config.MAX_AGENT_ITERATIONS + 1):
            logger.info(f"Agent iteration {iteration}/{Config.MAX_AGENT_ITERATIONS}")

            response = self._llm.chat(self._history, self._tools)

            if response.is_final_answer:
                # LLM is satisfied — no tool calls, just a text answer
                logger.info("Agent produced final answer")
                self._append_assistant_message(response)
                return response.content

            # LLM wants to call one or more tools
            logger.info(f"LLM requested {len(response.tool_calls)} tool call(s): "
                        f"{[tc.name for tc in response.tool_calls]}")

            self._append_assistant_message(response)

            # Execute every tool call the LLM requested in this iteration
            for tool_call in response.tool_calls:
                result = self._dispatcher.execute(tool_call)
                self._append_tool_result(tool_call.id, result)

        # Safety cap reached — ask LLM to wrap up with what it has
        logger.warning(f"Max iterations ({Config.MAX_AGENT_ITERATIONS}) reached — forcing final answer")
        return self._force_final_answer()

    def clear_history(self):
        """Reset conversation — called between sessions if needed."""
        self._history.clear()
        logger.info("Conversation history cleared")

    @property
    def history(self) -> list[dict]:
        return self._history

    # ── private ───────────────────────────────────────────────────────────

    def _append_assistant_message(self, response: LLMResponse):
        """
        Append the assistant turn to history.

        When there are tool calls we need to store them in history so the
        LLM remembers what it asked for when it sees the results.

        OpenAI/Ollama need the raw message object (with their native tool_calls
        structure).
        """
        if response.tool_calls and response.raw_assistant_message:
            # OpenAI/Ollama path — store the raw provider message verbatim
            self._history.append(response.raw_assistant_message)
        else:
            # Final answer — plain assistant message
            self._history.append({
                "role":    "assistant",
                "content": response.content,
            })

    def _append_tool_result(self, tool_call_id: str, result: str):
        """Append a tool result to history in the neutral format."""
        self._history.append({
            "role":         "tool",
            "tool_call_id": tool_call_id,
            "content":      result,
        })

    def _force_final_answer(self) -> str:
        """
        When the iteration cap is hit, send one final message asking the LLM
        to summarize what it has found so far instead of leaving the user hanging.
        """
        self._history.append({
            "role":    "user",
            "content": "Please summarize what you have found so far based on the tool results above.",
        })
        response = self._llm.chat(self._history, self._tools)
        self._history.append({"role": "assistant", "content": response.content})
        return response.content