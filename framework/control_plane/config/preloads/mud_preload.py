"""Mud Preload config"""

from __future__ import annotations
from typing import Any, Union, List
from ipaddress import IPv4Address, IPv6Address
from pydantic import BaseModel, ConfigDict, Field, field_serializer
from pydantic_extra_types.mac_address import MacAddress


class ProfileEntry(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    url: str = Field(
        alias="url",
    )
    port: int = Field(
        alias="port",
    )
    ip_address: Union[IPv4Address, IPv6Address] = Field(
        alias="ip-address",
    )

    @field_serializer("ip_address")
    @classmethod
    def convert_ip_address(cls, ip_address):
        return str(ip_address)


class MudPreload(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    profiles: List[ProfileEntry] = Field(
        alias="profiles",
        default=[],
    )
    independent_profiles: List[str] = Field(
        alias="independent-profiles",
        default=[],
    )
