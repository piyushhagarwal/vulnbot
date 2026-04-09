"""
Formatter — rich terminal output for the CLI chatbot.

Handles all console rendering: welcome banner, user prompts,
agent thinking indicators, tool call notifications, and final answers.
Nothing here affects the agent logic — purely presentation.
"""

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.rule import Rule
from rich.spinner import Spinner
from rich.live import Live
from rich import box

console = Console()


def print_welcome(provider_name: str, tools: list[dict]):
    """Print the welcome banner shown once at startup."""
    tool_names = " · ".join(t["name"] for t in tools)

    console.print()
    console.print(Panel(
        f"[bold cyan]Vulnerability Intelligence Chatbot[/bold cyan]\n"
        f"[dim]Provider:[/dim] [green]{provider_name}[/green]\n"
        f"[dim]Tools:[/dim]    [yellow]{tool_names}[/yellow]\n\n"
        f"[dim]Ask about CVEs, MITRE ATT&CK techniques, or search for vulnerabilities.\n"
        f"Type [bold]exit[/bold] or [bold]quit[/bold] to leave. "
        f"Type [bold]clear[/bold] to reset conversation history.[/dim]",
        box=box.ROUNDED,
        border_style="cyan",
        padding=(1, 2),
    ))
    console.print()


def print_user_prompt() -> str:
    """Render the user input prompt and return what they typed."""
    return console.input("[bold green]You[/bold green] [dim]›[/dim] ")


def print_thinking():
    """Return a Live context showing a spinner while the agent is working."""
    return Live(
        Spinner("dots", text="[dim]Thinking...[/dim]", style="cyan"),
        console=console,
        transient=True,   # clears itself when the context exits
    )


def print_tool_call(tool_name: str, arguments: dict):
    """Show which tool the agent is calling and with what arguments."""
    # Format arguments as readable key=value pairs
    args_str = "  ".join(f"[yellow]{k}[/yellow]=[cyan]{v}[/cyan]" for k, v in arguments.items())
    console.print(f"  [dim]⚙ Calling[/dim] [bold]{tool_name}[/bold]  {args_str}")


def print_response(content: str):
    """Render the LLM's final answer as markdown."""
    console.print()
    console.print(Rule("[bold cyan]Assistant[/bold cyan]", style="cyan"))
    console.print(Markdown(content))
    console.print()


def print_error(message: str):
    """Print an error message in red."""
    console.print(f"\n[bold red]Error:[/bold red] {message}\n")


def print_info(message: str):
    """Print a dim informational message."""
    console.print(f"[dim]{message}[/dim]")


def print_goodbye():
    """Print exit message."""
    console.print("\n[dim]Goodbye.[/dim]\n")