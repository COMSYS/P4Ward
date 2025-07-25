"""Mud ace match arp"""

from __future__ import annotations
from typing import Any, Union
from enum import Enum

from framework.control_plane.models.mud import InvalidMudProfileError
from framework.control_plane.models.mud.matches.match import MudMatch


class MudMatchArp(MudMatch):
    """Mud match arp"""

    disable_request: Union[bool, None]
    disable_reply: Union[bool, None]

    def __init__(self) -> None:
        super().__init__()

        self.disable_request = None
        self.disable_reply = None

    def load_from_json(self, json: dict[str, Any], extensions: list[str]):
        try:
            if isinstance((disable_request := json.get("disable-request")), bool):
                self.disable_request = disable_request
            elif disable_request is not None:
                raise TypeError("disable-request")
            
            if isinstance((disable_reply := json.get("disable-reply")), bool):
                self.disable_reply = disable_reply
            elif disable_reply is not None:
                raise TypeError("disable-reply")
            pass
        except KeyError as error:
            raise InvalidMudProfileError(
                f"MUD Profile ACE ARP match {error} entry is missing."
            ) from error
        except TypeError as error:
            raise InvalidMudProfileError(
                f"MUD Profile ACE ARP match {error} entry is invalid."
            ) from error
