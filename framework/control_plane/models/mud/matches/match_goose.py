"""Mud ace match goose"""

from __future__ import annotations
from typing import Any, Union
from enum import Enum

from framework.control_plane.models.mud import InvalidMudProfileError
from framework.control_plane.models.mud.matches.match import MudMatch


class MudMatchGoose(MudMatch):
    """Mud match goose"""

    app_id: Union[int, None]

    def __init__(self) -> None:
        super().__init__()

        self.app_id = None

    def load_from_json(self, json: dict[str, Any], extensions: list[str]):
        try:
            if isinstance((app_id := json.get("app-id")), int):
                self.app_id = app_id
            elif app_id is not None:
                raise TypeError("allowed-app-ids")
            
        except KeyError as error:
            raise InvalidMudProfileError(
                f"MUD Profile ACE GOOSE match {error} entry is missing."
            ) from error
        except TypeError as error:
            raise InvalidMudProfileError(
                f"MUD Profile ACE GOOSE match {error} entry is invalid."
            ) from error
