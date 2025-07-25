"""Data Plane configuration"""

from __future__ import annotations
from typing import Any, Union

from pydantic import BaseModel, ConfigDict, Field


class DataPlaneConfig(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    push: str= Field(
        alias="push",
        default="0.0.0.0:50052",
    )
    pull: str= Field(
        alias="pull",
        default="ens1",
    )
    mock: Union[bool, None] = Field(
        alias="mock",
        default=None,
    )
