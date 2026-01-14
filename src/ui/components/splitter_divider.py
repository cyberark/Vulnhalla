#!/usr/bin/env python3
"""
Splitter divider component for Vulnhalla UI.
"""

from textual.widget import Widget


class SplitterDivider(Widget):
    """
    Draggable divider widget between panels for resizing.
    """
    
    DEFAULT_CSS = """
    SplitterDivider {
        width: 1;
        background: transparent;
        color: $surface-lighten-2;
    }
    SplitterDivider:hover {
        background: $primary;
        color: $primary;
    }
    """
    
    def __init__(self, app_instance=None):
        """
        Initialize the SplitterDivider.

        Args:
            app_instance: Reference to the VulnhallaUI app instance for updating split position.
        """
        super().__init__()
        self.app_instance = app_instance
        self.dragging = False


    def render(self):
        """
        Render the divider as a thin vertical line.

        Returns:
            str: Single vertical line character "│".
        """
        return "│"


    def on_mouse_down(self, event) -> None:
        """
        Start dragging when mouse is pressed.

        Args:
            event: Mouse down event.
        """
        self.dragging = True
        self.capture_mouse()


    def on_mouse_move(self, event) -> None:
        """
        Update split position while dragging.

        Args:
            event: Mouse move event containing position information.
        """
        if self.dragging and self.app_instance:
            parent = self.parent
            if parent and parent.region:
                try:
                    # Get mouse position relative to parent container
                    mouse_x = event.screen_x - parent.region.x
                    parent_width = parent.size.width
                    if parent_width > 0:
                        new_position = max(0.2, min(0.8, mouse_x / parent_width))
                        self.app_instance.split_position = new_position
                        self.app_instance._update_split_position()
                except (AttributeError, TypeError):
                    # Fallback: use delta if available
                    if hasattr(event, 'delta_x') and event.delta_x != 0:
                        parent_width = parent.size.width
                        if parent_width > 0:
                            delta = event.delta_x / parent_width
                            new_position = max(0.2, min(0.8, self.app_instance.split_position + delta))
                            self.app_instance.split_position = new_position
                            self.app_instance._update_split_position()


    def on_mouse_up(self, event) -> None:
        """
        Stop dragging when mouse is released.

        Args:
            event: Mouse up event.
        """
        if self.dragging:
            self.dragging = False
            self.release_mouse()

