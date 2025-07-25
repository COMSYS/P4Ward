"""L3 cli handler"""

from __future__ import annotations
from typing import Any, Union
import argparse
from ipaddress import IPv4Address, IPv6Address
from macaddress import EUI48
import typing

if typing.TYPE_CHECKING:
    from framework.control_plane.switch import Switch


class L3CliHandler:
    """L3 cli handler"""

    _switch: "Switch"
    _parser: argparse.ArgumentParser

    def __init__(
        self, switch: "Switch", parser: argparse.ArgumentParser, parsers
    ) -> None:
        # super().__init__(switch)
        self._switch = switch
        self._parser = parser

        subparser: "argparse.ArgumentParser" = parsers.add_parser(
            "l3", help="L3 tools"
        )
        subparsers = subparser.add_subparsers(
            title="L3 tools", dest="l3", help="L3 tools"
        )

        parser_add = subparsers.add_parser("add", help="Add L3 routing entry")
        parser_add.add_argument(
            "--ipv4-address", type=IPv4Address, help="IPv4 address"
        )
        parser_add.add_argument(
            "--ipv6-address", type=IPv6Address, help="IPv6 address"
        )
        parser_add.add_argument(
            "--mac-address", type=EUI48, help="MAC address"
        )
        parser_add.add_argument(
            "--port", type=int, help="Hardware Port"
        )
        parser_add.set_defaults(func=self._exec_add)

        parser_list = subparsers.add_parser("list", help="List L3 routing entries")
        parser_list.set_defaults(func=self._exec_list)

        parser_remove = subparsers.add_parser("remove", help="Remove L3 routing entry")
        parser_remove.add_argument(
            "--ipv4-address", type=IPv4Address, help="IPv4 address"
        )
        parser_remove.add_argument(
            "--ipv6-address", type=IPv6Address, help="IPv6 address"
        )
        parser_remove.set_defaults(func=self._exec_remove)

    def _exec_add(self, args: Any):
        ip_address: Union[IPv4Address, IPv6Address]
        if args.ipv4_address is not None:
            ip_address = args.ipv4_address
        if args.ipv6_address is not None:
            ip_address = args.ipv6_address
        else:
            self._parser.error("missing ip address")

        mac_address: EUI48
        if args.mac_address is not None:
            mac_address = args.mac_address
        else:
            self._parser.error("missing mac address")

        port: int
        if args.port is not None:
            port = args.port
        else:
            self._parser.error("missing port")

        self._switch.l3.add_route(ip_address, mac_address, port)

    def _exec_list(self, _args: Any):
        print("IP Address      -> MAC Address")
        for ip_address, mac_address in self._switch.l3._routes.items():
            print(f"{str(ip_address).rjust(15)} -> {str(mac_address)}")

    def _exec_remove(self, args: Any):
        ip_address: Union[IPv4Address, IPv6Address]
        if args.ipv4_address is not None:
            ip_address = args.ipv4_address
        if args.ipv6_address is not None:
            ip_address = args.ipv6_address
        else:
            self._parser.error("missing ip address")

        self._switch.l3.remove_route(ip_address)
