"""Bandwidth configuration"""

from __future__ import annotations
from typing import Any, Union

from pydantic import BaseModel, ConfigDict, Field


class BandwidthConfig(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    pps: Union[int, None] = Field(
        alias="pps",
        default=None,
    )
    pbs: Union[int, None] = Field(
        alias="pbs",
        default=None,
    )

    enforce_max_bandwidth: bool = Field(
        alias="enforce-max-bandwidth",
        default=False,
    )
