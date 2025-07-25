"""Device cli handler"""

from __future__ import annotations
from typing import Any, Union
import argparse
from ipaddress import IPv4Address, IPv6Address
from macaddress import EUI48
import typing

from framework.control_plane.controllers.device.device import Device, Ignore

if typing.TYPE_CHECKING:
    from framework.control_plane.switch import Switch


class DeviceCliHandler:
    """Device cli handler"""

    _switch: "Switch"
    _parser: argparse.ArgumentParser

    def __init__(
        self, switch: "Switch", parser: argparse.ArgumentParser, parsers
    ) -> None:
        self._switch = switch
        self._parser = parser

        subparser: "argparse.ArgumentParser" = parsers.add_parser(
            "dev", help="Device tools"
        )
        subparsers = subparser.add_subparsers(
            title="Device tools", dest="dev", help="Device tools"
        )

        parser_add = subparsers.add_parser("add", help="Add device")
        parser_add.add_argument("--port", type=int, help="Port")
        parser_add.add_argument("--mac-address", type=EUI48, help="MAC address")
        parser_add.add_argument("--ipv4-address", type=IPv4Address, help="IPv4 address")
        parser_add.add_argument("--ipv6-address", type=IPv6Address, help="IPv6 address")
        parser_add.add_argument("--profile", type=str, help="Profile URL")
        parser_add.set_defaults(func=self._exec_add)

        parser_list = subparsers.add_parser("list", help="List devices")
        parser_list.set_defaults(func=self._exec_list)

        parser_remove = subparsers.add_parser("remove", help="Remove device")
        parser_remove.add_argument("--mac-address", type=EUI48, help="MAC address")
        parser_remove.set_defaults(func=self._exec_remove)

        parser_add_src_ignore = subparsers.add_parser(
            "add-src-ignore", help="Add source ignore"
        )
        parser_add_src_ignore.add_argument("--port", type=int, help="Port")
        parser_add_src_ignore.add_argument(
            "--mac-address", type=EUI48, help="MAC address"
        )
        parser_add_src_ignore.add_argument(
            "--ipv4-address", type=IPv4Address, help="IPv4 address"
        )
        parser_add_src_ignore.add_argument(
            "--ipv6-address", type=IPv6Address, help="IPv6 address"
        )
        parser_add_src_ignore.add_argument(
            "--controller-name", type=str, help="Controller name (optional)"
        )
        parser_add_src_ignore.add_argument(
            "--manufacturer-name", type=str, help="Manufacturer Name (optional)"
        )
        parser_add_src_ignore.add_argument(
            "--model-name", type=str, help="Model Name (optional)"
        )
        parser_add_src_ignore.set_defaults(func=self._exec_add_src_ignore)

        parser_list_src_ignore = subparsers.add_parser("list-src-ignore", help="List source ignore")
        parser_list_src_ignore.set_defaults(func=self._exec_list_src_ignore)

        parser_remove_src_ignore = subparsers.add_parser(
            "remove-src-ignore", help="Remove source ignore"
        )
        parser_remove_src_ignore.add_argument(
            "--mac-address", type=EUI48, help="MAC address"
        )
        parser_remove_src_ignore.set_defaults(func=self._exec_remove_src_ignore)

        parser_add_dst_ignore = subparsers.add_parser(
            "add-dst-ignore", help="Add destination ignore"
        )
        parser_add_dst_ignore.add_argument(
            "--mac-address", type=EUI48, help="MAC address"
        )
        parser_add_dst_ignore.add_argument(
            "--ipv4-address", type=IPv4Address, help="IPv4 address"
        )
        parser_add_dst_ignore.add_argument(
            "--ipv6-address", type=IPv6Address, help="IPv6 address"
        )
        parser_add_dst_ignore.add_argument(
            "--controller-name", type=str, help="Controller name (optional)"
        )
        parser_add_dst_ignore.add_argument(
            "--manufacturer-name", type=str, help="Manufacturer Name (optional)"
        )
        parser_add_dst_ignore.add_argument(
            "--model-name", type=str, help="Model Name (optional)"
        )
        parser_add_dst_ignore.set_defaults(func=self._exec_add_dst_ignore)

        parser_list_dst_ignore = subparsers.add_parser("list-dst-ignore", help="List destination ignore")
        parser_list_dst_ignore.set_defaults(func=self._exec_list_dst_ignore)

        parser_remove_dst_ignore = subparsers.add_parser(
            "remove-dst-ignore", help="Remove destination ignore"
        )
        parser_remove_dst_ignore.add_argument(
            "--mac-address", type=EUI48, help="MAC address"
        )
        parser_remove_dst_ignore.set_defaults(func=self._exec_remove_dst_ignore)

    async def _exec_add(self, args: Any):
        port: int
        if args.port is not None:
            port = args.port
        else:
            self._parser.error("missing port")

        mac_address: EUI48
        if args.mac_address is not None:
            mac_address = args.mac_address
        else:
            self._parser.error("missing mac address")

        ip_address: Union[IPv4Address, IPv6Address]
        if args.ipv4_address is not None:
            ip_address = args.ipv4_address
        elif args.ipv6_address is not None:
            ip_address = args.ipv6_address
        else:
            self._parser.error("missing ip address")

        profile_url: str
        if args.profile is not None:
            profile_url = args.profile
        else:
            self._parser.error("missing profile")

        if (profile := await self._switch.mud.get_profile(profile_url)) is not None:
            self._switch.device.add_device(
                Device(
                    port=port,
                    mac_address=mac_address,
                    ip_addresses=[ip_address],
                    profile=profile,
                    group="CLI",
                )
            )

    def _exec_list(self, _args: Any):
        print("MAC Address       -> Device")
        for mac_address, device in self._switch.device._devices.items():
            print(f"{str(mac_address).rjust(17)} -> {device}")

    def _exec_remove(self, args: Any):
        mac_address: EUI48
        if args.mac_address is not None:
            mac_address = args.mac_address
        else:
            self._parser.error("missing mac address")

        self._switch.device.remove_device(mac_address)

    async def _exec_add_src_ignore(self, args: Any):
        port: int
        if args.port is not None:
            port = args.port
        else:
            self._parser.error("missing port")

        mac_address: EUI48
        if args.mac_address is not None:
            mac_address = args.mac_address
        else:
            self._parser.error("missing mac address")

        ip_address: Union[IPv4Address, IPv6Address]
        if args.ipv4_address is not None:
            ip_address = args.ipv4_address
        elif args.ipv6_address is not None:
            ip_address = args.ipv6_address
        else:
            self._parser.error("missing ip address")

        controller_name: Union[str, None] = None
        if args.controller_name is not None:
            controller_name = args.controller_name

        manufacturer_name: Union[str, None] = None
        if args.manufacturer_name is not None:
            manufacturer_name = args.manufacturer_name

        model_name: Union[str, None] = None
        if args.model_name is not None:
            model_name = args.model_name

        self._switch.device.add_src_ignore(
            Ignore(
                port=port,
                mac_address=mac_address,
                ip_address=ip_address,
                controller_name=controller_name,
                manufacturer_name=manufacturer_name,
                model_name=model_name,
                group="CLI",
            )
        )

    def _exec_list_src_ignore(self, _args: Any):
        print("MAC Address       -> Source Ignore")
        for mac_address, ignore in self._switch.device._src_ignores.items():
            print(f"{str(mac_address).rjust(17)} -> {ignore}")

    def _exec_remove_src_ignore(self, args: Any):
        mac_address: EUI48
        if args.mac_address is not None:
            mac_address = args.mac_address
        else:
            self._parser.error("missing mac address")

        self._switch.device.remove_src_ignore(mac_address)

    async def _exec_add_dst_ignore(self, args: Any):
        mac_address: EUI48
        if args.mac_address is not None:
            mac_address = args.mac_address
        else:
            self._parser.error("missing mac address")

        ip_address: Union[IPv4Address, IPv6Address]
        if args.ipv4_address is not None:
            ip_address = args.ipv4_address
        elif args.ipv6_address is not None:
            ip_address = args.ipv6_address
        else:
            self._parser.error("missing ip address")

        controller_name: Union[str, None] = None
        if args.controller_name is not None:
            controller_name = args.controller_name

        manufacturer_name: Union[str, None] = None
        if args.manufacturer_name is not None:
            manufacturer_name = args.manufacturer_name

        model_name: Union[str, None] = None
        if args.model_name is not None:
            model_name = args.model_name

        self._switch.device.add_dst_ignore(
            Ignore(
                port=0,
                mac_address=mac_address,
                ip_address=ip_address,
                controller_name=controller_name,
                manufacturer_name=manufacturer_name,
                model_name=model_name,
                group="CLI",
            )
        )

    def _exec_list_dst_ignore(self, _args: Any):
        print("MAC Address       -> Destination Ignore")
        for mac_address, ignore in self._switch.device._dst_ignores.items():
            print(f"{str(mac_address).rjust(17)} -> {ignore}")

    def _exec_remove_dst_ignore(self, args: Any):
        mac_address: EUI48
        if args.mac_address is not None:
            mac_address = args.mac_address
        else:
            self._parser.error("missing mac address")

        self._switch.device.remove_dst_ignore(mac_address)
