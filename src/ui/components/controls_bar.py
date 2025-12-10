#!/usr/bin/env python3
"""
Controls bar component for Vulnhalla UI.
"""

from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Static, Label, Select, Button
from textual.app import ComposeResult


class ControlsBar(Container):
    """
    Bottom horizontal bar with controls, filters, and actions.
    """
    
    def compose(self) -> ComposeResult:
        """Compose the controls bar layout.

        Creates the bottom bar with language information, filters,
        action buttons and keyboard shortcut help text.
        """
        with Vertical():
            # Language label only
            with Horizontal():
                yield Static("Language: C (only language currently supported)", classes="control-label")
            # Filter and buttons
            with Horizontal():
                yield Label("Filter by llm decision:", classes="control-label")
                yield Select(
                    [("All", "all"), ("True Positive", "true"), ("False Positive", "false"), ("Needs more Info to decide", "more")],
                    value="all",
                    id="filter-select"
                )
                yield Button("Refresh", id="refresh-btn")
                yield Button("Run Analysis", id="run-analysis-btn")
            yield Static("")
            # Key Bindings help text
            with Horizontal():
                yield Label("Key Bindings:", classes="control-label")
                yield Static("↑/↓: Navigate | Tab: Switch focus | Enter: Show details | /: Search | [: Resize left | ]: Resize right | r: Reload | q: Quit", classes="help-text")

