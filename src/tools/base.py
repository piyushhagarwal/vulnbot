"""
Abstract base for all tools.

Each tool:
  - Declares its name, description, and JSON schema (used by the LLM API)
  - Implements execute() which takes the LLM's parsed arguments and returns
    a plain string result that goes back into the conversation
"""

from abc import ABC, abstractmethod


class Tool(ABC):

    @property
    @abstractmethod
    def name(self) -> str:
        """Must match the function name the LLM will call."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """Shown to the LLM — be specific about when to use this tool."""
        ...

    @property
    @abstractmethod
    def input_schema(self) -> dict:
        """
        JSON Schema for the tool's arguments.
        This is passed directly to the LLM API as the tool definition.
        All required fields must be listed under 'required'.
        """
        ...

    @abstractmethod
    def execute(self, **kwargs) -> str:
        """
        Run the tool with the LLM-supplied arguments.

        Returns:
            A plain string result. Can be JSON, plain text, or an error
            message — the LLM will interpret it.
        """
        ...

    def to_api_dict(self) -> dict:
        """Serialize this tool into the generic dict the LLM providers expect."""
        return {
            "name":         self.name,
            "description":  self.description,
            "input_schema": self.input_schema,
        }