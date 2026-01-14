#!/usr/bin/env python3
"""
Vulnhalla UI - User Interface for browsing analysis results.

This module provides a three-panel UI for viewing and exploring
CodeQL analysis results processed by Vulnhalla.
"""

import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from rich.markup import escape as markup_escape

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import (
    DataTable, Static, Input, Select, Button, Label,
    Header, Footer
)
from textual.binding import Binding

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.ui.models import (
    Issue,
    format_status_display,
    format_manual_decision,
    get_default_sort_key,
    get_sort_key_for_column
)
from src.ui.results_loader import ResultsLoader
from src.ui.issue_parser import (
    extract_line_number_from_location,
    collect_all_code_snippets,
    extract_last_message
)
from src.ui.components.controls_bar import ControlsBar
from src.ui.components.splitter_divider import SplitterDivider
from src.ui.components.issues_list_panel import IssuesListPanel
from src.ui.components.details_panel import DetailsPanel


class VulnhallaUI(App):
    """
    Main UI application for Vulnhalla.
    """
    
    CSS = """
    .panel-title { text-style: bold; margin: 1; }
    .help-text { margin: 1; }
    .control-label { margin: 0 1; }
    #issues-table { height: 1fr; }
    #details-content { padding: 1; }
    #issues-search { margin: 1; width: 100%; }
    #controls-bar { height: 11; border-top: solid $primary; }
    #details-scrollable { height: 1fr; }
    #manual-decision-container { height: auto; border-top: solid $primary; }
    #manual-decision-label { margin: 1 1 0 1; }
    #manual-decision-select { margin: 0 1 1 1; width: auto; }
    #issues-list { width: 50%; }
    #details { width: 50%; }
    Select, Select:focus, SelectOverlay, SelectOverlay:focus { border: none; }
    Input, Input:focus { border: none; outline: none; }
    SplitterDivider { width: 1; background: transparent; color: $surface-lighten-2; }
    SplitterDivider:hover { background: $primary; color: $primary; }
    """
    
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "reload", "Reload"),
        Binding("tab", "focus_next", "Next Panel"),
        Binding("shift+tab", "focus_previous", "Previous Panel"),
        Binding("/", "search", "Search"),
        Binding("escape", "clear_search", "Clear Search"),
        Binding("enter", "select_issue", "Show Details"),
        Binding("[", "resize_left", "Resize Left"),
        Binding("]", "resize_right", "Resize Right"),
    ]
    
    def __init__(self):
        """
        Initialize the VulnhallaUI application.
        """
        super().__init__()
        self.loader = ResultsLoader()
        self.issues: List[Issue] = []
        self.filtered_issues: List[Issue] = []
        self.selected_issue: Optional[Issue] = None
        self.current_lang = "c"
        self.current_filter = "all"
        self.search_query = ""
        self.split_position = 0.5
        self.sort_column: Optional[str] = None
        self.sort_ascending: bool = True
        self._updating_manual_decision_select: bool = False
    
    def compose(self) -> ComposeResult:
        """Compose the main application layout.

        Builds the overall Textual UI, including the issues list panel,
        the details panel, and the bottom controls bar.
        """
        yield Header()
        with Vertical():
            with Horizontal():
                yield IssuesListPanel(id="issues-list")
                yield SplitterDivider(app_instance=self)
                yield DetailsPanel(id="details")
            yield ControlsBar(id="controls-bar")
        yield Footer()


    def on_mount(self) -> None:
        """
        Initialize the UI when app starts.
        """
        self.load_issues()
        self.update_issues_table()
        table = self.query_one("#issues-table", DataTable)
        table.cursor_type = "row"
        table.show_header = True
        table.focus()
        # Set initial split position
        self._update_split_position()
        # Hide manual decision select initially (no issue selected)
        try:
            manual_decision_container = self.query_one("#manual-decision-container", Vertical)
            manual_decision_container.styles.display = "none"
        except:
            pass


    def load_issues(self) -> None:
        """
        Load issues from disk and update the UI.
        
        Displays error notifications if any files fail to load.
        """
        self.current_lang = "c"  # Only C is currently supported
        
        # Save manual decisions before reloading
        manual_decisions_map: Dict[str, Optional[str]] = {}
        for issue in self.issues:
            if issue.manual_decision is not None:
                manual_decisions_map[issue.final_path] = issue.manual_decision
        
        # Load issues from disk - now returns (issues, errors)
        self.issues, errors = self.loader.load_all_issues(self.current_lang)
        
        # Display errors to user if any occurred
        if errors:
            error_count = len(errors)
            if error_count == 1:
                self.notify(f"Error loading file: {errors[0]}", severity="error")
            else:
                # Show summary for multiple errors
                self.notify(
                    f"Failed to load {error_count} file(s). Check logs for details.",
                    severity="warning"
                )
                # Log all errors for debugging
                from src.utils.logger import get_logger
                logger = get_logger(__name__)
                for error in errors:
                    logger.warning(error)
        
        # Restore manual decisions by matching final_path
        for issue in self.issues:
            if issue.final_path in manual_decisions_map:
                issue.manual_decision = manual_decisions_map[issue.final_path]
        
        self.apply_filters()


    def apply_filters(self) -> None:
        """
        Apply current filter and search to issues list.
        """
        filter_select = self.query_one("#filter-select", Select)
        self.current_filter = filter_select.value or "all"
        
        # Get search query from the persistent search input
        search_input = self.query_one("#issues-search", Input)
        self.search_query = (search_input.value or "").strip()
        
        # Filter by status
        if self.current_filter == "all":
            filtered = self.issues
        else:
            filtered = [i for i in self.issues if i.status == self.current_filter]
        
        # Apply search filter
        if self.search_query:
            query_lower = self.search_query.lower()
            filtered = [
                i for i in filtered
                if query_lower in i.name.lower()
                or query_lower in i.file.lower()
                or query_lower in i.repo.lower()
                or query_lower in i.status.lower() or query_lower in i.id.lower()
                or (i.manual_decision and query_lower in i.manual_decision.lower())
                or (not i.manual_decision and query_lower in "not set")
            ]
        
        # Apply user-defined column sorting if set, otherwise use default ID sorting
        if self.sort_column:
            self._sort_filtered_issues(filtered)
        else:
            # Default: Sort by numeric ID
            filtered.sort(key=get_default_sort_key)
        
        self.filtered_issues = filtered
        self.update_issues_table()


    def _sort_filtered_issues(self, issues: List[Issue]) -> None:
        """
        Sort filtered issues by the current sort column and direction.

        Args:
            issues (List[Issue]): List of issues to sort (modified in-place).
        """
        if not self.sort_column or not issues:
            return
        
        sort_key = get_sort_key_for_column(self.sort_column)
        if sort_key:
            issues.sort(key=sort_key, reverse=not self.sort_ascending)


    def update_issues_table(self, preserve_row_key: Optional[str] = None) -> None:
        """
        Update the issues table with current filtered issues.

        Args:
            preserve_row_key (Optional[str]): Optional row key (issue ID) to preserve 
                cursor position after update.
        """
        table = self.query_one("#issues-table", DataTable)
        # Clear both rows and columns to prevent duplicates
        table.clear(columns=True)
        table.add_columns("ID", "LLM decision", "Manual decision", "Repo", "Issue name", "File")
        
        for issue in self.filtered_issues:
            status_display = format_status_display(issue.status)
            manual_display = format_manual_decision(issue.manual_decision)
            
            # Normalize file name display format
            file_display = issue.file
            if file_display.endswith('"') and not file_display.startswith('"'):
                file_display = '"' + file_display
            # Truncate if needed
            if len(file_display) > 30:
                file_display = file_display[:30] + "..."
            
            table.add_row(
                issue.id,
                status_display,
                manual_display,
                issue.repo,
                issue.name[:40] + "..." if len(issue.name) > 40 else issue.name,
                file_display,
                key=issue.id
            )
        
        # Restore cursor position if requested (immediately after adding all rows)
        if preserve_row_key is not None:
            # Find target row index and restore cursor
            for idx, issue in enumerate(self.filtered_issues):
                if issue.id == preserve_row_key and idx > 0:
                    # Move cursor from row 0 (after clear) to target row
                    for _ in range(idx):
                        table.action_cursor_down()
                    break
        
        # Refresh the table to ensure visual update
        table.refresh()
        
        # Update count with sort indicator
        count_widget = self.query_one("#issues-count", Static)
        sort_indicator = ""
        if self.sort_column:
            direction = "↑" if self.sort_ascending else "↓"
            sort_indicator = f" | Sorted by: {self.sort_column} {direction}"
        count_widget.update(f"Showing {len(self.filtered_issues)} of {len(self.issues)} issues{sort_indicator}")


    def on_data_table_header_selected(self, event: DataTable.HeaderSelected) -> None:
        """
        Handle column header click for sorting.

        Args:
            event (DataTable.HeaderSelected): Event containing column index information.
        """
        # Get column index from the event
        column_index = getattr(event, 'column_index', None)
        
        # Map column index to column name
        column_names = ["ID", "LLM decision", "Manual decision", "Repo", "Issue name", "File"]
        
        if column_index is None or not (0 <= column_index < len(column_names)):
            return
        
        column_key = column_names[column_index]
        
        # Toggle sort direction if clicking the same column, otherwise set new column
        if self.sort_column == column_key:
            self.sort_ascending = not self.sort_ascending
        else:
            self.sort_column = column_key
            self.sort_ascending = True
        
        # Re apply filters (which will apply sorting) and update table
        self.apply_filters()


    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """
        Handle issue selection in the table.

        Args:
            event (DataTable.RowSelected): Event containing row selection information.
        """
        if event.cursor_row is None or event.cursor_row >= len(self.filtered_issues):
            return
        
        # Save current cursor position before updating
        table = self.query_one("#issues-table", DataTable)
        current_cursor_row = event.cursor_row
        
        self.selected_issue = self.filtered_issues[event.cursor_row]
        self.update_details_panel()
        
        # Restore cursor position after update
        if current_cursor_row is not None and current_cursor_row < len(self.filtered_issues):
            try:
                table.cursor_row = current_cursor_row
                table.refresh()
            except:
                pass


    def action_select_issue(self) -> None:
        """
        Action to select the currently highlighted issue and show details.
        """
        table = self.query_one("#issues-table", DataTable)
        # Get the current cursor row
        cursor_row = table.cursor_row
        if cursor_row is not None and 0 <= cursor_row < len(self.filtered_issues):
            self.selected_issue = self.filtered_issues[cursor_row]
            self.update_details_panel()
            # Trigger the row selection to highlight it
            table.action_select_cursor()


    def _escape_code_for_markup(self, code: str) -> str:
        """
        Escape Rich markup characters in code to prevent interpretation.

        Args:
            code (str): Code string to escape.

        Returns:
            str: Escaped code string with Rich markup characters escaped.
        """
        return code.replace('[', '\\[').replace(']', '\\]').replace('{', '\\{').replace('}', '\\}')


    def update_details_panel(self) -> None:
        """
        Update the details panel with selected issue information.
        """
        # Get widgets
        details_widget = self.query_one("#details-content", Static)
        manual_decision_select = self.query_one("#manual-decision-select", Select)
        manual_decision_label = self.query_one("#manual-decision-label", Label)
        manual_decision_container = self.query_one("#manual-decision-container", Vertical)
        
        if not self.selected_issue:
            details_widget.update("Select an issue to view details")
            # Hide manual decision select when no issue is selected
            manual_decision_container.styles.display = "none"
            return
        
        # Show manual decision select when issue is selected
        manual_decision_container.styles.display = "block"
        
        issue = self.selected_issue
        
        # Build details text parts
        details_parts = []
        
        # ===== LLM DECISION SECTION =====
        # Map status to display text
        status_display = format_status_display(issue.status)
        details_parts.append("[bold cyan]LLM decision[/bold cyan]")
        details_parts.append(markup_escape(status_display))
        details_parts.append("")
        
        # ===== METADATA SECTION =====
        # Use Rich markup for styled metadata
        details_parts.append("[bold cyan]Metadata[/bold cyan]")
        details_parts.append(f"[bold]Issue name:[/bold] {markup_escape(issue.name)}")
        details_parts.append(f"[bold]Repo:[/bold] {markup_escape(issue.repo)}")
        details_parts.append(f"[bold]File:[/bold] {markup_escape(issue.file)}:{issue.line}")
        details_parts.append(f"[bold]Type:[/bold] {markup_escape(issue.issue_type)}")
        
        # Add function name if available
        if issue.raw_data and "current_function" in issue.raw_data:
            func = issue.raw_data["current_function"]
            func_name = func.get("function_name", "").strip('"')
            if func_name:
                details_parts.append(f"[bold]Function:[/bold] {markup_escape(func_name)}")
        
        details_parts.append("")
        
        # ===== CODE SECTION =====
        initial_code, additional_code_list = collect_all_code_snippets(issue)
        
        details_parts.append("[bold cyan]Code[/bold cyan]")
        details_parts.append("")
        
        if not initial_code and not additional_code_list:
            details_parts.append("(No code available)")
        else:
            # Helper function to render code with highlighting
            def render_code_block(code: str, to_highlight: bool = True) -> tuple[list[str], Optional[int]]:
                """
                Render a code block with highlighting.

                Args:
                    code (str): Code block to render.
                    to_highlight (bool): Whether to highlight the line number of the location.
                    
                Returns:
                    tuple[list[str], Optional[int]]: Tuple of (rendered_lines, highlight_index).
                """
                if not code:
                    return ([], None)
                
                location_line = extract_line_number_from_location(issue)
                code_lines = code.split('\n')
                
                # Find highlight index within this block
                highlight_idx = None
                if location_line is not None:
                    for idx, line in enumerate(code_lines):
                        match = re.match(r'^\s*(\d+):', line)
                        if match and int(match.group(1)) == location_line:
                            highlight_idx = idx
                            break
                
                # Process and escape lines
                rendered_lines = []
                for idx, line in enumerate(code_lines):
                    escaped = self._escape_code_for_markup(line)
                    if highlight_idx is not None and idx == highlight_idx and to_highlight:
                        rendered_lines.append(f"[bold red]{escaped}[/bold red]")
                    else:
                        rendered_lines.append(escaped)
                
                return (rendered_lines, highlight_idx)
            
            if initial_code:
                details_parts.append("Initial Code Context:")
                details_parts.append("")
                initial_lines, _ = render_code_block(initial_code, to_highlight=True)
                details_parts.extend(initial_lines)
                details_parts.append("")
            
            if additional_code_list:
                details_parts.append("")
                details_parts.append("Additional Code (requested during analysis):")
                details_parts.append("")
                
                for additional_block in additional_code_list:
                    additional_lines, _ = render_code_block(additional_block, to_highlight=False)
                    details_parts.extend(additional_lines)
                    # Add separator between code blocks
                    if additional_block != additional_code_list[-1]:
                        details_parts.append("")
                        details_parts.append("────────────────────────────────────────────────────────────────────────────────")
                        details_parts.append("")
                
                details_parts.append("")
        
        # ===== SUMMARY SECTION =====
        # Extract the last LLM message (final answer/decision)
        summary_content = extract_last_message(issue.final_data)
        
        details_parts.append("")
        details_parts.append("[bold cyan]Summary (LLM final answer)[/bold cyan]")
        details_parts.append("")
        
        if summary_content:
            # Escape Rich markup and limit to 80 lines
            summary_lines = summary_content.split('\n')
            MAX_SUMMARY_LINES = 80
            
            if len(summary_lines) > MAX_SUMMARY_LINES:
                summary_lines = summary_lines[:MAX_SUMMARY_LINES]
                summary_lines.append("")
                summary_lines.append("... (truncated, showing first 80 lines)")
            
            # Add each line, escaping markup
            for line in summary_lines:
                escaped_line = markup_escape(line)
                details_parts.append(escaped_line)
        else:
            details_parts.append("(No summary available)")
        
        # Join all parts and update the widget
        details_text = "\n".join(details_parts)
        details_widget = self.query_one("#details-content", Static)
        details_widget.update(details_text)
        
        # Update manual decision select with current value
        manual_decision_select = self.query_one("#manual-decision-select", Select)
        current_value = issue.manual_decision if issue.manual_decision else None
        # Set flag to prevent event when updating programmatically
        self._updating_manual_decision_select = True
        # Update the select value
        manual_decision_select.value = current_value
        # Reset flag after a brief moment
        self.set_timer(0.1, lambda: setattr(self, '_updating_manual_decision_select', False))


    def on_select_changed(self, event: Select.Changed) -> None:
        """
        Handle filter selection change and manual decision selection.

        Args:
            event (Select.Changed): Event containing select widget and new value.
        """
        if event.select.id == "filter-select":
            self.apply_filters()
        elif event.select.id == "manual-decision-select":
            # Ignore if we're updating the select programmatically
            if self._updating_manual_decision_select:
                return
            # Update the selected issue's manual_decision
            if self.selected_issue:
                # Update the manual_decision
                self.selected_issue.manual_decision = event.value  # Could be None for "Not Set"
                
                # Update the table
                self.update_issues_table(preserve_row_key=self.selected_issue.id)


    def on_button_pressed(self, event: Button.Pressed) -> None:
        """
        Handle button clicks.

        Args:
            event (Button.Pressed): Event containing button information.
        """
        if event.button.id == "refresh-btn":
            self.load_issues()
        elif event.button.id == "run-analysis-btn":
            self.notify("Run analysis from command line: python examples/example.py", severity="info")


    def action_search(self) -> None:
        """
        Focus the search input.
        """
        search_input = self.query_one("#issues-search", Input)
        search_input.focus()


    def action_clear_search(self) -> None:
        """
        Clear search query and return focus to issues table.
        """
        search_input = self.query_one("#issues-search", Input)
        self.search_query = ""
        search_input.value = ""
        self.apply_filters()
        # Return focus to the issues table
        self.query_one("#issues-table", DataTable).focus()


    def action_reload(self) -> None:
        """
        Reload issues from disk.
        """
        self.load_issues()
        self.notify("Reloaded issues", severity="success")


    def _update_split_position(self) -> None:
        """
        Update CSS widths for both panels based on split_position.
        """
        issues_panel = self.query_one("#issues-list")
        details_panel = self.query_one("#details")
        
        issues_width = int(self.split_position * 100)
        details_width = int((1 - self.split_position) * 100)
        
        issues_panel.styles.width = f"{issues_width}%"
        details_panel.styles.width = f"{details_width}%"
    
    def action_resize_left(self) -> None:
        """
        Resize split to give more space to left panel (issues).
        """
        self.split_position = max(0.2, self.split_position - 0.05)  # Minimum 20% for right panel
        self._update_split_position()


    def action_resize_right(self) -> None:
        """
        Resize split to give more space to right panel (details).
        """
        self.split_position = min(0.8, self.split_position + 0.05)  # Maximum 80% for right panel
        self._update_split_position()


    def on_input_changed(self, event: Input.Changed) -> None:
        """
        Handle search input changes - update search in real-time.

        Args:
            event (Input.Changed): Event containing input widget and new value.
        """
        if event.input.id == "issues-search":
            self.search_query = event.value
            self.apply_filters()


    def get_actions(self):
        """
        Override to filter out minimize and maximize from command palette.

        Returns:
            List: Filtered list of actions excluding minimize and maximize.
        """
        # Get all actions from parent class
        actions = super().get_actions()
        # Filter out minimize and maximize actions by their action ID
        if actions:
            return [
                action for action in actions
                if hasattr(action, 'id') and action.id not in ("minimize", "maximize")
            ]
        return actions or []


    def action_minimize(self) -> None:
        """
        Override to prevent minimize from appearing in command palette.
        """
        pass


    def action_maximize(self) -> None:
        """
        Override to prevent maximize from appearing in command palette.
        """
        pass


def main():
    """
    Entry point for running the UI.
    """
    app = VulnhallaUI()
    app.run()


if __name__ == "__main__":
    main()
