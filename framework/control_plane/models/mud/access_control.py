"""Access Control Policy"""

from __future__ import annotations
from typing import Any, Union
from enum import Enum

from framework.control_plane.models.mud import InvalidMudProfileError
from framework.control_plane.models.mud.matches.match_mud import MudMatchMud

from framework.control_plane.models.mud.matches.match_arp import MudMatchArp
from framework.control_plane.models.mud.matches.match_ipv4 import MudMatchIPv4
from framework.control_plane.models.mud.matches.match_ipv6 import MudMatchIPv6
from framework.control_plane.models.mud.matches.match_icmp import MudMatchIcmp

from framework.control_plane.models.mud.matches.match_tcp import MudMatchTcp
from framework.control_plane.models.mud.matches.match_udp import MudMatchUdp

from framework.control_plane.models.mud.matches.match_enip import MudMatchEnip
from framework.control_plane.models.mud.matches.match_modbus import MudMatchModBus
from framework.control_plane.models.mud.matches.match_opcua import MudMatchOpcUA
from framework.control_plane.models.mud.matches.match_goose import MudMatchGoose


class MudEndpointType(Enum):
    CLIENT = 0
    SERVER = 1


class MudAccessControlList:
    """Access control list"""

    name: str
    type: Union[str, None]

    self_type: Union[MudEndpointType, None]

    entries: list[MudAccessControlEntry]

    def __init__(self) -> None:
        self.name = ""
        self.type = None
        self.self_type = None
        self.entries = []

    def load_from_json(self, json: dict[str, Any], extensions: list[str]):
        """Load MUD access control list from JSON

        Args:
            json (dict[str, Any]): JSON
            extensions (list[str]): Enabled Extensions

        Raises:
            InvalidMudProfileError: MUD access control list is not valid
        """
        try:
            if isinstance((name := json["name"]), str):
                self.name = name
            else:
                raise TypeError("name")

            if isinstance((typev := json.get("type")), str):
                self.type = typev
            elif typev is not None:
                raise TypeError("type")

            if isinstance((self_type := json.get("self-type")), str):
                if "endpoint-type" not in extensions:
                    raise InvalidMudProfileError(
                        "Endpoint Type extension is not registered. Consider adding the 'endpoint-type' extension."
                    )

                if self_type == "client":
                    self.self_type = MudEndpointType.CLIENT
                elif self_type == "server":
                    self.self_type = MudEndpointType.SERVER
                else:
                    raise TypeError("self-type")
            elif self_type is not None:
                raise TypeError("self-type")

            for json_entry in json.get("aces", {}).get("ace", []):
                access_control_entry = MudAccessControlEntry()

                access_control_entry.name = str(json_entry["name"])

                for match_name, json_match in json_entry.get("matches", {}).items():
                    if match_name == "ietf-mud:mud":
                        access_control_entry.mud_match = MudMatchMud()
                        access_control_entry.mud_match.load_from_json(
                            json_match, extensions
                        )
                    elif match_name == "arp":
                        if "arp" not in extensions:
                            raise InvalidMudProfileError(
                                "ARP extension is not registered. Consider adding the 'arp' extension."
                            )
                        
                        access_control_entry.arp_match = MudMatchArp()
                        access_control_entry.arp_match.load_from_json(
                            json_match, extensions
                        )
                    elif match_name == "ipv4":
                        access_control_entry.ipv4_match = MudMatchIPv4()
                        access_control_entry.ipv4_match.load_from_json(
                            json_match, extensions
                        )
                    elif match_name == "ipv6":
                        access_control_entry.ipv6_match = MudMatchIPv6()
                        access_control_entry.ipv6_match.load_from_json(
                            json_match, extensions
                        )
                    elif match_name == "icmp":
                        if "icmp" not in extensions:
                            raise InvalidMudProfileError(
                                "ICMP extension is not registered. Consider adding the 'icmp' extension."
                            )
                        
                        access_control_entry.icmp_match = MudMatchIcmp()
                        access_control_entry.icmp_match.load_from_json(
                            json_match, extensions
                        )
                    elif match_name == "tcp":
                        access_control_entry.tcp_match = MudMatchTcp()
                        access_control_entry.tcp_match.load_from_json(
                            json_match, extensions
                        )
                    elif match_name == "udp":
                        access_control_entry.udp_match = MudMatchUdp()
                        access_control_entry.udp_match.load_from_json(
                            json_match, extensions
                        )
                    elif match_name == "enip":
                        if "enip" not in extensions:
                            raise InvalidMudProfileError(
                                "ENIP extension is not registered. Consider adding the 'enip' extension."
                            )

                        access_control_entry.enip_match = MudMatchEnip()
                        access_control_entry.enip_match.load_from_json(
                            json_match, extensions
                        )
                    elif match_name == "modbus":
                        if "modbus" not in extensions:
                            raise InvalidMudProfileError(
                                "ModBus extension is not registered. Consider adding the 'modbus' extension."
                            )

                        access_control_entry.modbus_match = MudMatchModBus()
                        access_control_entry.modbus_match.load_from_json(
                            json_match, extensions
                        )
                    elif match_name == "opcua":
                        if "opcua" not in extensions:
                            raise InvalidMudProfileError(
                                "OPCUA extension is not registered. Consider adding the 'opcua' extension."
                            )

                        access_control_entry.opcua_match = MudMatchOpcUA()
                        access_control_entry.opcua_match.load_from_json(
                            json_match, extensions
                        )
                    elif match_name == "goose":
                        if "goose" not in extensions:
                            raise InvalidMudProfileError(
                                "GOOSE extension is not registered. Consider adding the 'goose' extension."
                            )

                        access_control_entry.goose_match = MudMatchGoose()
                        access_control_entry.goose_match.load_from_json(
                            json_match, extensions
                        )
                    else:
                        raise TypeError(f"{match_name}")

                self.entries.append(access_control_entry)
        except KeyError as error:
            raise InvalidMudProfileError(
                f"MUD Profile ACL {error} entry is missing."
            ) from error
        except TypeError as error:
            raise InvalidMudProfileError(
                f"MUD Profile ACL {error} entry is invalid."
            ) from error


class MudAccessControlEntry:
    """MUD access control entry definition"""

    name: str
    mud_match: Union[MudMatchMud, None]

    arp_match: Union[MudMatchArp, None]
    ipv4_match: Union[MudMatchIPv4, None]
    ipv6_match: Union[MudMatchIPv6, None]
    icmp_match: Union[MudMatchIcmp, None]

    tcp_match: Union[MudMatchTcp, None]
    udp_match: Union[MudMatchUdp, None]

    enip_match: Union[MudMatchEnip, None]
    modbus_match: Union[MudMatchModBus, None]
    opcua_match: Union[MudMatchOpcUA, None]
    goose_match: Union[MudMatchGoose, None]

    def __init__(self) -> None:
        self.name = ""
        self.mud_match = None

        self.arp_match = None
        self.ipv4_match = None
        self.ipv6_match = None
        self.icmp_match = None

        self.tcp_match = None
        self.udp_match = None

        self.enip_match = None
        self.modbus_match = None
        self.opcua_match = None
        self.goose_match = None
