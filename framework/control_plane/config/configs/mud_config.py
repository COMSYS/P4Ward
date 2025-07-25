"""MUD configuration"""

from __future__ import annotations
from typing import Any, Union

from pydantic import BaseModel, ConfigDict, Field


class MudConfig(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    use_remote: bool = Field(
        alias="use-remote",
        default=True,
    )
    origin: str = Field(
        alias="origin",
        default="127.0.0.1:80",
    )
    enable_cache: bool = Field(
        alias="enable-cache",
        default=True,
    )
