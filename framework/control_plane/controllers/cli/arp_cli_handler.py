"""L2 cli handler"""

from __future__ import annotations
from ipaddress import IPv4Address, IPv6Address
from typing import Any, Union
import argparse
from macaddress import EUI48
import typing

if typing.TYPE_CHECKING:
    from framework.control_plane.switch import Switch


class ArpCliHandler:
    """ARP cli handler"""

    _switch: "Switch"
    _parser: argparse.ArgumentParser

    def __init__(
        self, switch: "Switch", parser: argparse.ArgumentParser, parsers
    ) -> None:
        # super().__init__(switch)
        self._switch = switch
        self._parser = parser

        subparser: "argparse.ArgumentParser" = parsers.add_parser(
            "arp", help="ARP tools"
        )
        subparsers = subparser.add_subparsers(
            title="ARP tools", dest="arp", help="ARP tools"
        )

        parser_add = subparsers.add_parser("add", help="Add ARP reply entry")
        parser_add.add_argument(
            "--port", type=int, help="Port"
        )
        parser_add.add_argument(
            "--ipv4-address", type=IPv4Address, help="IPv4 address"
        )
        parser_add.add_argument(
            "--mac-address", type=EUI48, help="MAC address"
        )
        parser_add.set_defaults(func=self._exec_add)

        parser_list = subparsers.add_parser("list", help="List ARP reply entries")
        parser_list.set_defaults(func=self._exec_list)

        parser_remove = subparsers.add_parser("remove", help="Remove ARP reply entry")
        parser_remove.add_argument(
            "--port", type=int, help="Port"
        )
        parser_remove.add_argument(
            "--ipv4-address", type=IPv4Address, help="IPv4 address"
        )
        parser_remove.set_defaults(func=self._exec_remove)

    def _exec_add(self, args: Any):
        port: int
        if args.port is not None:
            port = args.port
        else:
            self._parser.error("missing port")

        ip_address: IPv4Address
        if args.ipv4_address is not None:
            ip_address = args.ipv4_address
        else:
            self._parser.error("missing ip address")

        mac_address: EUI48
        if args.mac_address is not None:
            mac_address = args.mac_address
        else:
            self._parser.error("missing mac address")

        if self._switch.arp.add_reply(port, ip_address, mac_address):
            print("ok")
        else:
            print("not ok")

    def _exec_list(self, _args: Any):
        print("Port , IP Address      -> Multicast Group")
        for (port, ip_address), reply in self._switch.arp._replies.items():
            print(f"{str(port).ljust(5)}, {str(ip_address).ljust(15)} -> {str(reply.mac_address)}")

    def _exec_remove(self, args: Any):
        port: int
        if args.port is not None:
            port = args.port
        else:
            self._parser.error("missing port")

        ip_address: IPv4Address
        if args.ipv4_address is not None:
            ip_address = args.ipv4_address
        else:
            self._parser.error("missing ip address")

        if self._switch.arp.remove_reply(port, ip_address):
            print("ok")
        else:
            print("not ok")
