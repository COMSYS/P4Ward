"""ARP Preload config"""

from __future__ import annotations
from typing import Any, Union, List
from pydantic import BaseModel, ConfigDict, Field, field_serializer
from ipaddress import IPv4Address, IPv6Address
from pydantic_extra_types.mac_address import MacAddress


class ReplyEntry(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    port: int = Field(
        alias="port",
    )
    ipv4_address: IPv4Address = Field(
        alias="ipv4-address",
    )
    mac_address: MacAddress = Field(
        alias="mac-address",
    )

    @field_serializer("ipv4_address")
    @classmethod
    def convert_ip_address(cls, ip_address):
        return str(ip_address)
    
class BroadcastEntry(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    port: int = Field(
        alias="port",
    )

    multicast: int = Field(
        alias="multicast",
    )


class ArpPreload(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    replies: List[ReplyEntry] = Field(
        alias="replies",
        default=[],
    )
    broadcasts: List[BroadcastEntry] = Field(
        alias="broadcasts",
        default=[],
    )
