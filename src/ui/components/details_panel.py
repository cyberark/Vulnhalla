#!/usr/bin/env python3
"""
Details panel component for Vulnhalla UI.
"""

from textual.containers import Container, Vertical, ScrollableContainer
from textual.widgets import Static, Label, Select
from textual.app import ComposeResult


class DetailsPanel(Container):
    """
    Right panel showing issue details with scrollable content and manual decision selector.
    """
    
    def compose(self) -> ComposeResult:
        """Compose the issue details panel layout.

        Builds the right-hand panel that shows LLM decisions, metadata,
        code snippets and the manual decision selector for the selected issue.
        """
        with Vertical():
            # Scrollable content area
            scrollable_content = ScrollableContainer(id="details-scrollable")
            with scrollable_content:
                yield Static("Select an issue to view details", id="details-content", markup=True)
            # Manual decision controls
            with Vertical(id="manual-decision-container"):
                yield Label("Enter your manual decision:", id="manual-decision-label")
                yield Select(
                    [
                        ("Not Set", None),
                        ("True Positive", "True Positive"),
                        ("False Positive", "False Positive"),
                        ("Uncertain", "Uncertain"),
                    ],
                    value=None,
                    id="manual-decision-select",
                    prompt="Not Set"
                )

