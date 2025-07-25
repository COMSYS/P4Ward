"""MUD configuration"""

from __future__ import annotations
from typing import Any, Union, Dict
from ipaddress import IPv4Address, IPv6Address

from pydantic import BaseModel, ConfigDict, Field


class DnsConfig(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    ipv4_constants: Dict[str, IPv4Address] = Field(
        alias="ipv4-constants",
        default={},
    )
    ipv6_constants: Dict[str, IPv6Address] = Field(
        alias="ipv6-constants",
        default={},
    )
