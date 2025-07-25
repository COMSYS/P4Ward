"""ACL device"""

from __future__ import annotations
from typing import Any, Union
from ipaddress import (
    IPv4Address,
    IPv6Address,
)
from urllib.parse import urlparse
from macaddress import EUI48

from framework.control_plane.helper import CRC16, CRC32
from framework.control_plane.models.mud.mud_profile import MudProfile


class Device:
    """Device Manager Device

    A device entry sets the source and destination tables and enables the from and to tables of the ACL module.

    Remarks:
        A device binds mac and ip addresses to different ids used to filter, route and authenticate devices
    """

    group: Union[str, None]
    sub_group: Union[str, None]

    # Device specific
    local_id: int
    port: int
    mac_address: EUI48
    ip_addresses: list[Union[IPv4Address, IPv6Address]]
    controller_name: str

    # Device hardware specific
    manufacturer_name: str
    model_name: str

    independent: bool
    profile: MudProfile

    def __init__(
        self,
        port: int,
        mac_address: EUI48,
        ip_addresses: list[Union[IPv4Address, IPv6Address]],
        profile: MudProfile,
        independent: bool = False,
        group: Union[str, None] = None,
        sub_group: Union[str, None] = None,
    ) -> None:
        self.local_id = -1

        self.port = port
        self.mac_address = mac_address
        self.ip_addresses = ip_addresses
        self.independent = independent
        self.profile = profile

        self.controller_name = (
            "default:controller"
            if profile.controller_name is None
            else profile.controller_name
        )
        self.manufacturer_name = (
            urlparse(profile.url).netloc
            if profile.manufacturer_name is None
            else profile.manufacturer_name
        )
        self.model_name = (
            profile.url if profile.model_name is None else profile.model_name
        )

        self.group = group
        self.sub_group = sub_group

    def get_id(self, ip_address: Union[IPv4Address, IPv6Address]) -> int:
        return CRC32(bytes(self.mac_address) + ip_address.packed)

    def get_id_bytes(self, ip_address: Union[IPv4Address, IPv6Address]) -> bytes:
        return self.get_id(ip_address).to_bytes(4, "big")

    def get_sub_id(self) -> int:
        return CRC32(self.controller_name.encode())

    def get_sub_id_bytes(self) -> bytes:
        return self.get_sub_id().to_bytes(4, "big")

    def get_manufacturer_id(self) -> int:
        return CRC16(self.manufacturer_name.encode())

    def get_manufacturer_id_bytes(self) -> bytes:
        return self.get_manufacturer_id().to_bytes(2, "big")

    def get_model_id(self) -> int:
        return CRC16(self.model_name.encode())

    def get_model_id_bytes(self) -> bytes:
        return self.get_model_id().to_bytes(2, "big")

    def __str__(self) -> str:
        result: str = ""

        result += f"{self.mac_address}"
        result += (
            f" [{', '.join(map(lambda a: f'{a}#{self.get_id(a)}', self.ip_addresses))}]"
        )

        result += " ("
        result += f"{self.controller_name}#{self.get_sub_id()}"
        result += f", {self.manufacturer_name}#{self.get_manufacturer_id()}"
        result += f", {self.model_name}#{self.get_model_id()})"
        result += ")"

        return result


class Ignore:
    """Device Manager Ignore
    
    An ignore entry can be set in the source and destination tables and marks the source or destination as ignored.
    Using the ignore entry the from and to tables of the ACL module are disabled. 
    """

    group: Union[str, None]
    sub_group: Union[str, None]

    port: int
    mac_address: EUI48
    ip_address: Union[IPv4Address, IPv6Address, None]
    controller_name: Union[str, None]
    manufacturer_name: Union[str, None]
    model_name: Union[str, None]

    def __init__(
        self,
        port: int,
        mac_address: EUI48,
        ip_address: Union[IPv4Address, IPv6Address, None] = None,
        controller_name: Union[str, None] = None,
        manufacturer_name: Union[str, None] = None,
        model_name: Union[str, None] = None,
        group: Union[str, None] = None,
        sub_group: Union[str, None] = None,
    ) -> None:
        self.local_id = -1

        self.port = port
        self.mac_address = mac_address
        self.ip_address = ip_address
        self.controller_name = controller_name
        self.manufacturer_name = manufacturer_name
        self.model_name = model_name

        self.group = group
        self.sub_group = sub_group

    def get_id(self, ip_address: Union[IPv4Address, IPv6Address, None]) -> int:
        return CRC32(bytes(self.mac_address) + (ip_address.packed if ip_address is not None else bytes()))

    def get_id_bytes(self, ip_address: Union[IPv4Address, IPv6Address, None]) -> bytes:
        return self.get_id(ip_address).to_bytes(4, "big")

    def get_sub_id(self) -> int:
        return CRC32(self.controller_name.encode()) if self.controller_name is not None else 0

    def get_sub_id_bytes(self) -> bytes:
        return self.get_sub_id().to_bytes(4, "big")

    def get_manufacturer_id(self) -> int:
        return CRC16(self.manufacturer_name.encode()) if self.manufacturer_name is not None else 0

    def get_manufacturer_id_bytes(self) -> bytes:
        return self.get_manufacturer_id().to_bytes(2, "big")

    def get_model_id(self) -> int:
        return CRC16(self.model_name.encode()) if self.model_name is not None else 0

    def get_model_id_bytes(self) -> bytes:
        return self.get_model_id().to_bytes(2, "big")

    def __str__(self) -> str:
        result: str = ""

        result += f"(ignore) {self.mac_address}"
        result += (
            f" [{f'{self.ip_address}#{self.get_id(self.ip_address)}'}]"
        )

        result += " ("
        result += f"{self.controller_name}#{self.get_sub_id()}"
        result += f", {self.manufacturer_name}#{self.get_manufacturer_id()}"
        result += f", {self.model_name}#{self.get_model_id()})"
        result += ")"

        return result
