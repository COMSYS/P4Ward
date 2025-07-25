"""Access Control cli handler"""

from __future__ import annotations
from typing import Any, Union
import argparse
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
import typing

from framework.control_plane.controllers.ac.ac_entry import (
    AcAction,
    AcDirection,
    AcEntry,
    AcProtocolId,
    AcProtocolMask,
)

if typing.TYPE_CHECKING:
    from framework.control_plane.switch import Switch


class AcCliHandler:
    """Access Control cli handler"""

    _switch: "Switch"
    _parser: argparse.ArgumentParser

    def __init__(
        self, switch: "Switch", parser: argparse.ArgumentParser, parsers
    ) -> None:
        # super().__init__(switch)
        self._switch = switch
        self._parser = parser

        subparser: "argparse.ArgumentParser" = parsers.add_parser("ac", help="AC tools")
        subparsers = subparser.add_subparsers(
            title="AC tools", dest="ac", help="AC tools"
        )

        parser_list = subparsers.add_parser("list", help="List AC routing entries")
        parser_list.set_defaults(func=self._exec_list)

    def _exec_list(self, _args: Any):
        for entry in self._switch.acl._entries.values():
            print(f"{str(entry)}")