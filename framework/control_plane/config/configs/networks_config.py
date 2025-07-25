"""Network configuration"""

from __future__ import annotations
from ipaddress import IPv4Interface, IPv6Interface
from typing import Any, Union, List
from pydantic import BaseModel, ConfigDict, Field, field_serializer
from pydantic_extra_types.mac_address import MacAddress


class NetworkEntry(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    name: Union[str, None] = Field(
        alias="name",
        default=None,
    )
    mac_address: Union[MacAddress, None] = Field(
        alias="mac-address",
        default=None,
    )
    ipv4_interface: Union[IPv4Interface, None] = Field(
        alias="ipv4-interface",
        default=None,
    )
    ipv6_interface: Union[IPv6Interface, None] = Field(
        alias="ipv6-interface",
        default=None,
    )
    ports: List[int] = Field(
        alias="ports",
        default=[],
    )
    test_ports: List[int] = Field(
        alias="test-ports",
        default=[],
    )

    @field_serializer("ipv4_interface")
    @classmethod
    def convert_ipv4_interface(cls, ip_interface):
        return str(ip_interface)

    @field_serializer("ipv6_interface")
    @classmethod
    def convert_ipv6_interface(cls, ip_interface):
        return str(ip_interface)


class NetworksConfig(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    networks: List[NetworkEntry] = Field(
        alias="networks",
        default=[],
    )
