"""Mud ace match"""

from __future__ import annotations
from typing import Any


class MudMatch:
    """Mud match base class"""

    def load_from_json(self, json: dict[str, Any], extensions: list[str]):
        """Load MUD match from json"""
