"""L3 Preload config"""

from __future__ import annotations
from typing import Any, Union, List
from pydantic import BaseModel, ConfigDict, Field, field_serializer
from ipaddress import IPv4Address, IPv6Address
from pydantic_extra_types.mac_address import MacAddress


class RouteEntry(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    ip_address: Union[IPv4Address, IPv6Address] = Field(
        alias="ip-address",
    )
    mac_address: MacAddress = Field(
        alias="mac-address",
    )
    port: int = Field(
        alias="port",
    )

    @field_serializer("ip_address")
    @classmethod
    def convert_ip_address(cls, ip_address):
        return str(ip_address)


class L3Preload(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    routes: List[RouteEntry] = Field(
        alias="routes",
        default=[],
    )
