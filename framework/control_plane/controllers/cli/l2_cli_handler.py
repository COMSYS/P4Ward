"""L2 cli handler"""

from __future__ import annotations
from typing import Any, Union
import argparse
from macaddress import EUI48
import typing

if typing.TYPE_CHECKING:
    from framework.control_plane.switch import Switch


class L2CliHandler:
    """L2 cli handler"""

    _switch: "Switch"
    _parser: argparse.ArgumentParser

    def __init__(
        self, switch: "Switch", parser: argparse.ArgumentParser, parsers
    ) -> None:
        # super().__init__(switch)
        self._switch = switch
        self._parser = parser

        subparser: "argparse.ArgumentParser" = parsers.add_parser(
            "l2", help="L2 tools"
        )
        subparsers = subparser.add_subparsers(
            title="L2 tools", dest="l2", help="L2 tools"
        )

        parser_enable = subparsers.add_parser("add", help="Add L2 routing entry")
        parser_enable.add_argument(
            "--address", type=EUI48, help="MAC device address"
        )
        parser_enable.add_argument(
            "--port", type=int, help="Forward Port"
        )
        parser_enable.set_defaults(func=self._exec_add)

        parser_list = subparsers.add_parser("list", help="List L2 routing entries")
        parser_list.set_defaults(func=self._exec_list)

        parser_remove = subparsers.add_parser("remove", help="Remove L2 routing entry")
        parser_remove.add_argument(
            "--address", type=EUI48, help="MAC device address"
        )
        parser_remove.set_defaults(func=self._exec_remove)

    def _exec_add(self, args: Any):
        address: EUI48
        if args.address is not None:
            address = args.address
        else:
            self._parser.error("missing device address")

        port: int
        if args.port is not None:
            port = args.port
        else:
            self._parser.error("missing port")

        self._switch.l2.add_route(address, port)

    def _exec_list(self, _args: Any):
        print("MAC Address       -> Port")
        for address, port in self._switch.l2._entries.items():
            print(f"{str(address).rjust(17)} -> {port}")

    def _exec_remove(self, args: Any):
        address: EUI48
        if args.address is not None:
            address = args.address
        else:
            self._parser.error("missing device address")

        self._switch.l2.remove_route(address)
