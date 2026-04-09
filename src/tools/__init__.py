"""
Tool registry — single source of truth for all available tools.

To add a new tool:
  1. Create it in nvd_tool.py or mitre_tool.py (or a new file)
  2. Import and add it to TOOLS list below
  3. Nothing else needs to change — dispatcher and prompts pick it up automatically
"""

from src.tools.nvd_tool import (
    GetCVEDetailsTool,
    SearchCVEsByKeywordTool,
    SearchCVEsBySeverityTool,
    SearchCVEsByDateRangeTool,
)
from src.tools.mitre_tool import (
    GetMITRETechniqueTool,
    SearchMITREByKeywordTool,
)

# Ordered list of all registered tools
TOOLS = [
    GetCVEDetailsTool(),
    SearchCVEsByKeywordTool(),
    SearchCVEsBySeverityTool(),
    SearchCVEsByDateRangeTool(),
    GetMITRETechniqueTool(),
    SearchMITREByKeywordTool(),
]