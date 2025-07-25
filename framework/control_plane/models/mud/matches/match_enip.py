"""Mud ace match enip"""

from __future__ import annotations
from typing import Any, Union
from enum import Enum

from framework.control_plane.models.mud import InvalidMudProfileError
from framework.control_plane.models.mud.matches.match import MudMatch


class MudMatchEnip(MudMatch):
    """Mud match enip"""

    def __init__(self) -> None:
        super().__init__()

    def load_from_json(self, json: dict[str, Any], extensions: list[str]):
        try:
            pass
        except KeyError as error:
            raise InvalidMudProfileError(
                f"MUD Profile ACE ENIP match {error} entry is missing."
            ) from error
        except TypeError as error:
            raise InvalidMudProfileError(
                f"MUD Profile ACE ENIP match {error} entry is invalid."
            ) from error
