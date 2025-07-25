"""Mud ace match IPv6"""

from __future__ import annotations
from typing import Any, Union

from framework.control_plane.models.mud import InvalidMudProfileError
from framework.control_plane.models.mud.matches.match import MudMatch


class MudMatchIPv6(MudMatch):
    """Mud match IPv6"""

    # DNS names
    source_dns_name: Union[str, None]
    destination_dns_name: Union[str, None]

    # IP protocol
    protocol: Union[int, None]

    def __init__(self) -> None:
        super().__init__()

        self.source_dns_name = None
        self.destination_dns_name = None

        self.protocol = None

    def load_from_json(self, json: dict[str, Any], extensions: list[str]):
        try:
            if isinstance((source_dns_name := json.get("ietf-acldns:src-dnsname")), str):
                if "ietf-acldns" not in extensions:
                    raise InvalidMudProfileError("ACL DNS is not a registered extension. Consider adding the 'ietf-acldns' extension.")
                
                self.source_dns_name = source_dns_name
            elif source_dns_name is not None:
                raise TypeError("src-dnsname")
            
            if isinstance((destination_dns_name := json.get("ietf-acldns:dst-dnsname")), str):
                if "ietf-acldns" not in extensions:
                    raise InvalidMudProfileError("ACL DNS is not a registered extension. Consider adding the 'ietf-acldns' extension.")
                
                self.destination_dns_name = destination_dns_name
            elif destination_dns_name is not None:
                raise TypeError("src-dnsname")
            
            if isinstance((protocol := json.get("protocol")), int):
                self.protocol = protocol
            elif protocol is not None:
                raise TypeError("protocol")

        except KeyError as error:
            raise InvalidMudProfileError(
                f"MUD Profile ACE IPv6 match {error} entry is missing."
            ) from error
        except TypeError as error:
            raise InvalidMudProfileError(
                f"MUD Profile ACE IPv6 match {error} entry is invalid."
            ) from error
