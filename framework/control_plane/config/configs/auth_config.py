"""Authentication configuration"""

from __future__ import annotations
from typing import Any, Union, List, Dict
from ipaddress import IPv4Address, IPv6Address
from pydantic import BaseModel, ConfigDict, Field, field_serializer


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


class OTPConfig(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    per_auth: int = Field(
        alias="per-auth",
        default=50,
    )
    storing_factor: int = Field(
        alias="storing-factor",
        default=40,
    )


class AuthConfig(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    use_remote: bool = Field(
        alias="use-remote",
        default=True,
    )
    host: str = Field(
        alias="host",
        default="127.0.0.1:51001",
    )
    method: str = Field(
        alias="method",
        default="password",
    )

    timeout: int = Field(
        alias="timeout",
        default=4,
    )

    reauth: int = Field(
        alias="reauth",
        default=40,
    )

    otp: OTPConfig = Field(
        alias="otp",
        default=OTPConfig(),
    )

    users: List[UserEntry] = Field(
        alias="users",
        default=[],
    )
