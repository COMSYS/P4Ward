"""Preload config"""

from __future__ import annotations
from typing import Any, Union, List
from ipaddress import IPv4Address, IPv6Address
from pydantic import BaseModel, ConfigDict, Field, field_serializer
from pydantic_extra_types.mac_address import MacAddress


class DeviceEntry(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    port: int = Field(
        alias="port",
    )
    mac_address: MacAddress = Field(
        alias="mac-address",
    )
    ip_addresses: List[Union[IPv4Address, IPv6Address]] = Field(
        alias="ip-addresses",
    )
    independent: bool = Field(
        alias="independent",
        default=False,
    )
    profile: str = Field(
        alias="profile",
    )

    @field_serializer("ip_addresses")
    @classmethod
    def convert_ip_addresses(cls, ip_addresses):
        return [ str(a) for a in ip_addresses ]


class DevicePreload(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    devices: List[DeviceEntry] = Field(
        alias="devices",
        default=[],
    )
