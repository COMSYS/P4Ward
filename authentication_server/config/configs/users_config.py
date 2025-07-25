"""Users configuration"""

from __future__ import annotations
from ipaddress import IPv4Address, IPv6Address
from typing import Any, Union, List, Dict
from pydantic import BaseModel, ConfigDict, Field, field_serializer
from pydantic_extra_types.mac_address import MacAddress


class UserEntry(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    name: str = Field(
        alias="name",
    )
    alias: Union[str, None] = Field(
        alias="name",
        default=None,
    )
    password: str = Field(
        alias="password",
    )
    authentication_method: str = Field(
        alias="auth-method",
    )
    ip_address: Union[IPv4Address, IPv6Address] = Field(
        alias="ip-address",
    )
    profile: str = Field(
        alias="profile",
    )
    attributes: Dict[str, str] = Field(
        alias="attributes",
        default=[],
    )

    @field_serializer("ip_address")
    @classmethod
    def convert_ip_addresses(cls, ip_address):
        return str(ip_address)


class UsersConfig(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    users: List[UserEntry] = Field(
        alias="users",
        default=[],
    )
