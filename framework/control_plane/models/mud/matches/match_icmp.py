"""Mud ace match icmp"""

from __future__ import annotations
from typing import Any, Union
from enum import Enum

from framework.control_plane.models.mud import InvalidMudProfileError
from framework.control_plane.models.mud.matches.match import MudMatch


class MudMatchIcmp(MudMatch):
    """Mud match icmp"""

    disable_requests: Union[bool, None]
    disable_replies: Union[bool, None]

    disable_echo: Union[bool, None]
    disable_destination_unreachable: Union[bool, None]
    disable_redirect: Union[bool, None]
    disable_router_advertisement: Union[bool, None]
    disable_router_solicitation: Union[bool, None]
    disable_time_exceeded: Union[bool, None]
    disable_bad_header: Union[bool, None]
    disable_timestamp: Union[bool, None]

    def __init__(self) -> None:
        super().__init__()

        self.disable_requests = None
        self.disable_replies = None

        self.disable_echo = None
        self.disable_destination_unreachable = None
        self.disable_redirect = None
        self.disable_router_advertisement = None
        self.disable_router_solicitation = None
        self.disable_time_exceeded = None
        self.disable_bad_header = None
        self.disable_timestamp = None

    def load_from_json(self, json: dict[str, Any], extensions: list[str]):
        try:
            if isinstance((disable_requests := json.get("disable-requests")), bool):
                self.disable_requests = disable_requests
            elif disable_requests is not None:
                raise TypeError("disable-requests")
            
            if isinstance((disable_replies := json.get("disable-replies")), bool):
                self.disable_replies = disable_replies
            elif disable_replies is not None:
                raise TypeError("disable-replies")
            
            if isinstance((disable_echo := json.get("disable-echo")), bool):
                self.disable_echo = disable_echo
            elif disable_echo is not None:
                raise TypeError("disable-echo")
            
            if isinstance((disable_destination_unreachable := json.get("disable-destination-unreachable")), bool):
                self.disable_destination_unreachable = disable_destination_unreachable
            elif disable_destination_unreachable is not None:
                raise TypeError("disable-destination-unreachable")

            if isinstance((disable_redirect := json.get("disable-redirect")), bool):
                self.disable_redirect = disable_redirect
            elif disable_redirect is not None:
                raise TypeError("disable-redirect")
            
            if isinstance((disable_router_advertisement := json.get("disable-router-advertisement")), bool):
                self.disable_router_advertisement = disable_router_advertisement
            elif disable_router_advertisement is not None:
                raise TypeError("disable-router-advertisement")

            if isinstance((disable_router_solicitation := json.get("disable-router-solicitation")), bool):
                self.disable_router_solicitation = disable_router_solicitation
            elif disable_router_solicitation is not None:
                raise TypeError("disable-router-solicitation")
            
            if isinstance((disable_time_exceeded := json.get("disable-time-exceeded")), bool):
                self.disable_time_exceeded = disable_time_exceeded
            elif disable_time_exceeded is not None:
                raise TypeError("disable-time-exceeded")
            
            if isinstance((disable_bad_header := json.get("disable-bad-header")), bool):
                self.disable_bad_header = disable_bad_header
            elif disable_bad_header is not None:
                raise TypeError("disable-bad-header")
            
            if isinstance((disable_timestamp := json.get("disable-timestamp")), bool):
                self.disable_timestamp = disable_timestamp
            elif disable_timestamp is not None:
                raise TypeError("disable-timestamp")
            pass
        except KeyError as error:
            raise InvalidMudProfileError(
                f"MUD Profile ACE ARP match {error} entry is missing."
            ) from error
        except TypeError as error:
            raise InvalidMudProfileError(
                f"MUD Profile ACE ARP match {error} entry is invalid."
            ) from error
