"""Bind configuration"""

from __future__ import annotations
from typing import Any, Union, List
from ipaddress import IPv4Address, IPv6Address

from pydantic import BaseModel, ConfigDict, Field, field_serializer


class BindConfig(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    address: Union[IPv4Address, IPv6Address] = Field(
        alias="address",
        default=IPv4Address("0.0.0.0"),
    )
    port: int = Field(
        alias="port",
        default="51001",
    )

    @field_serializer("address")
    @classmethod
    def convert_address(cls, address):
        return str(address)
