"""
main.py — CLI entry point.

Wires everything together and runs the interactive chat loop.

Usage:
    uv run python main.py
"""

import sys

sys.path.insert(0, ".")

from src.chat_engine import ChatEngine
from src.config import Config
from src.dispatcher import Dispatcher
from src.formatter import (
    print_error,
    print_goodbye,
    print_info,
    print_response,
    print_thinking,
    print_tool_call,
    print_user_prompt,
    print_welcome,
)
from src.llm import get_llm_provider
from src.logger import setup_logging


def main():
    setup_logging(Config.LOG_LEVEL)

    # ── Initialise components ─────────────────────────────────────────────
    try:
        llm = get_llm_provider()
    except ValueError as e:
        print_error(str(e))
        sys.exit(1)

    dispatcher = Dispatcher()

    engine = ChatEngine(
        llm=llm,
        dispatcher=dispatcher,
        on_tool_call=print_tool_call,   # fires before each tool runs
    )

    print_welcome(llm.get_provider_name(), dispatcher.get_tool_definitions())

    # ── Main chat loop ────────────────────────────────────────────────────
    while True:
        try:
            user_input = print_user_prompt()
        except (EOFError, KeyboardInterrupt):
            # Ctrl+D or Ctrl+C — exit cleanly
            print_goodbye()
            break

        user_input = user_input.strip()

        if not user_input:
            continue

        if user_input.lower() in {"exit", "quit"}:
            print_goodbye()
            break

        if user_input.lower() == "clear":
            engine.clear_history()
            print_info("Conversation history cleared.")
            continue

        # Run the agentic loop — tool call notifications fire via callback
        try:
            with print_thinking():
                answer = engine.chat(user_input)
        except KeyboardInterrupt:
            # User hit Ctrl+C mid-response — cancel and re-prompt
            print_info("\nCancelled.")
            continue
        except Exception as e:
            print_error(f"Unexpected error: {e}")
            continue

        print_response(answer)


if __name__ == "__main__":
    main()