#!/usr/bin/env python3
"""
Issues list panel component for Vulnhalla UI.
"""

from textual.containers import Container, Vertical
from textual.widgets import Label, DataTable, Static, Input
from textual.app import ComposeResult


class IssuesListPanel(Container):
    """
    Left-hand panel showing list of issues in a DataTable.
    """
    
    def compose(self) -> ComposeResult:
        """Compose the issues list panel layout.

        Builds the left-hand panel that displays the table of issues,
        including columns such as ID, repository, file and decisions,
        along with the search input.
        """
        with Vertical():
            yield Label("Issues", classes="panel-title")
            table = DataTable(id="issues-table")
            table.cursor_type = "row"
            yield table
            yield Static("", id="issues-count")
            yield Input(placeholder="Search by issue name, file, repo, LLM decision, or manual decision...", id="issues-search")

