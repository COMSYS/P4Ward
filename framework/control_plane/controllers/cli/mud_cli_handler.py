"""MUD cli handler"""

from __future__ import annotations
from typing import Any, Union
import argparse
from ipaddress import IPv4Address, IPv6Address
import typing
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.shortcuts import PromptSession

from framework.control_plane.controllers.controller import Controller
from framework.control_plane.controllers.mud.local.mud_controller import LocalMudController

if typing.TYPE_CHECKING:
    from framework.control_plane.switch import Switch


class MudCliHandler:
    """MUD cli handler"""

    _switch: "Switch"
    _parser: argparse.ArgumentParser

    def __init__(
        self, switch: "Switch", parser: argparse.ArgumentParser, parsers
    ) -> None:
        # super().__init__(switch)
        self._switch = switch
        self._parser = parser

        subparser: "argparse.ArgumentParser" = parsers.add_parser(
            "mud-profile", help="MUD profile tools"
        )
        subparsers = subparser.add_subparsers(
            title="MUD profile tools", dest="mud-profile", help="MUD profile tools"
        )

        parser_enable = subparsers.add_parser("enable", help="Enable MUD profile")
        parser_enable.add_argument(
            "--port", type=int, help="Hardware Port"
        )
        parser_enable.add_argument(
            "--ipv4-address", type=IPv4Address, help="IPv4 address"
        )
        parser_enable.add_argument(
            "--ipv6-address", type=IPv6Address, help="IPv6 address"
        )
        parser_enable.add_argument("--url", type=str, help="MUD profile url")
        parser_enable.set_defaults(func=self._exec_enable_mud_profile)

        parser_list = subparsers.add_parser("list", help="List MUD profiles")
        parser_list.set_defaults(func=self._exec_list_mud_profile)

        parser_disable = subparsers.add_parser("disable", help="Disable MUD profile")
        parser_disable.add_argument(
            "--ipv4-address", type=IPv4Address, help="IPv4 address"
        )
        parser_disable.add_argument(
            "--ipv6-address", type=IPv6Address, help="IPv6 address"
        )
        parser_disable.set_defaults(func=self._exec_disable_mud_profile)

    async def _exec_enable_mud_profile(self, args: Any):
        port: int
        if args.port is not None:
            port = args.port
        else:
            self._parser.error("missing port")

        ip_address: Union[IPv4Address, IPv6Address]
        if args.ipv4_address is not None:
            ip_address = args.ipv4_address
        if args.ipv6_address is not None:
            ip_address = args.ipv6_address
        else:
            self._parser.error("missing ip address")

        url: str
        if args.url is not None:
            url = args.url
        else:
            self._parser.error("missing mud url")

        if (profile := await self._switch.mud.get_profile(url)) is not None:
            self._switch.mud.enable_profile(port, None, ip_address, profile)
        else:
            self._parser.error("failed to find mud profile")

    def _exec_list_mud_profile(self, args: Any):
        if isinstance(self._switch.mud, LocalMudController):
            for profile in self._switch.mud._mud_profiles.values():
                if profile is not None:
                    print(f"{profile.url}")

    def _exec_disable_mud_profile(self, args: Any):
        ip_address: Union[IPv4Address, IPv6Address]
        if args.ipv4_address is not None:
            ip_address = args.ipv4_address
        if args.ipv6_address is not None:
            ip_address = args.ipv6_address
        else:
            self._parser.error("missing ip address")

        self._switch.mud.disable_profile(ip_address)
