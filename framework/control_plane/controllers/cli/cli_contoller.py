"""CLI controller"""

from __future__ import annotations
from typing import Any, Union
import logging
import argparse
from ipaddress import IPv4Address, IPv6Address
import typing
import os
import inspect
from prompt_toolkit.shortcuts import PromptSession
from framework.control_plane.controllers.cli.ac_cli_handler import AcCliHandler

from framework.control_plane.controllers.controller import Controller

from framework.control_plane.controllers.cli.device_cli_handler import DeviceCliHandler
from framework.control_plane.controllers.cli.mud_cli_handler import MudCliHandler
from framework.control_plane.controllers.cli.l2_cli_handler import L2CliHandler
from framework.control_plane.controllers.cli.l3_cli_handler import L3CliHandler
from framework.control_plane.controllers.cli.arp_cli_handler import ArpCliHandler

if typing.TYPE_CHECKING:
    from framework.control_plane.switch import Switch


class CliController(Controller):
    """MUD management controller"""

    _parser: argparse.ArgumentParser
    _device_handler: DeviceCliHandler
    _mud_handler: MudCliHandler
    _l2_handler: L2CliHandler
    _l3_handler: L3CliHandler
    _arp_handler: ArpCliHandler

    def __init__(self, switch: "Switch") -> None:
        super().__init__(switch)

        self._parser = argparse.ArgumentParser(
            prog="cli", usage="<tool name> ...", add_help=True
        )
        subparsers = self._parser.add_subparsers(
            title="CLI Tool", dest="CLI", help="Basic CLI"
        )

        parser_help = subparsers.add_parser("help", help="Print help")
        parser_help.set_defaults(func=lambda _: self._parser.print_help())

        parser_clear = subparsers.add_parser("clear", help="Clear terminal")
        parser_clear.set_defaults(func=lambda _: os.system("clear"))

        parser_clear = subparsers.add_parser("exit", help="Exit control plane")
        parser_clear.set_defaults(func=lambda _: os._exit(0))

        self._device_handler = DeviceCliHandler(switch, self._parser, subparsers)
        self._mud_handler = MudCliHandler(switch, self._parser, subparsers)
        self._l2_handler = L2CliHandler(switch, self._parser, subparsers)
        self._l3_handler = L3CliHandler(switch, self._parser, subparsers)
        self._arp_handler = ArpCliHandler(switch, self._parser, subparsers)
        self._ac_handler = AcCliHandler(switch, self._parser, subparsers)

    async def run(self):
        """Run cli controller"""

        session = PromptSession(">> ")

        while True:
            command: str = await session.prompt_async()
            args: list[str] = list(
                filter(lambda item: len(str(item)) > 0, command.split(" "))
            )
            if len(args) > 0:
                try:
                    logging.debug("User is executing: %s", command)
                    result = self._parser.parse_args(args)
                    if hasattr(result, "func"):
                        if inspect.iscoroutinefunction(result.func):
                            await result.func(result)
                        else:
                            result.func(result)
                except:
                    pass
            else:
                self._parser.print_help()
