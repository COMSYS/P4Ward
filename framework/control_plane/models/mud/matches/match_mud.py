"""Mud ace match Mud"""

from __future__ import annotations
from enum import Enum
from typing import Any, Union

from framework.control_plane.models.mud import InvalidMudProfileError
from framework.control_plane.models.mud.matches.match import MudMatch

class MudMatchMud(MudMatch):
    """Mud match Mud"""

    same_manufacturer: bool
    my_controller: bool
    local_networks: bool

    controller: Union[str, None]
    manufacturer: Union[str, None]
    model: Union[str, None]

    def __init__(self) -> None:
        super().__init__()

        self.same_manufacturer = False
        self.my_controller = False
        self.local_networks = False
        self.controller = None
        self.manufacturer = None
        self.model = None

    def get_controller_id(self) -> int:
        return self.controller.__hash__() & 0xFFFFFFFF

    def get_manufacturer_id(self) -> int:
        return self.manufacturer.__hash__() & 0xFFFF

    def get_model_id(self) -> int:
        return self.model.__hash__() & 0xFFFF

    def load_from_json(self, json: dict[str, Any], extensions: list[str]):
        try:
            if "same-manufacturer" in json:
                self.same_manufacturer = True

            if "local-networks" in json:
                self.local_networks = True

            if "my-controller" in json:
                self.my_controller = True

            if isinstance((controller := json.get("controller")), str):
                self.controller = controller
            elif controller is not None:
                raise TypeError("controller")

            if isinstance((manufacturer := json.get("manufacturer")), str):
                self.manufacturer = manufacturer
            elif manufacturer is not None:
                raise TypeError("manufacturer")

            if isinstance((model := json.get("model")), str):
                self.model = model
            elif manufacturer is not None:
                raise TypeError("model")

        except KeyError as error:
            raise InvalidMudProfileError(
                f"MUD Profile ACE MUD match {error} entry is missing."
            ) from error
        except TypeError as error:
            raise InvalidMudProfileError(
                f"MUD Profile ACE MUD match {error} entry is invalid."
            ) from error
