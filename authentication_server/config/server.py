"""Server config"""

from __future__ import annotations
from typing import Any, Union

from pydantic import BaseModel, ConfigDict, Field

from authentication_server.config.configs.bind_config import BindConfig
from authentication_server.config.configs.users_config import UsersConfig


class ServerConfig(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    bind: BindConfig = Field(
        alias="bind",
        default=BindConfig(),
    )

    users: UsersConfig = Field(
        alias="users",
        default=UsersConfig(),
    )
